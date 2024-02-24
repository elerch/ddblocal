const std = @import("std");
const universal_lambda = @import("universal_lambda_handler");
const universal_lambda_interface = @import("universal_lambda_interface");
const universal_lambda_options = @import("universal_lambda_build_options");
const signing = @import("aws-signing");
const AuthenticatedRequest = @import("AuthenticatedRequest.zig");

const log = std.log.scoped(.dynamodb);

pub const std_options = struct {
    pub const log_scope_levels = &[_]std.log.ScopeLevel{.{ .scope = .aws_signing, .level = .info }};
};

pub fn main() !u8 {
    return try universal_lambda.run(null, handler);
}

pub fn handler(allocator: std.mem.Allocator, event_data: []const u8, context: universal_lambda_interface.Context) ![]const u8 {
    const access_key = try allocator.dupe(u8, "ACCESS");
    const secret_key = try allocator.dupe(u8, "SECRET");
    test_credential = signing.Credentials.init(allocator, access_key, secret_key, null);
    defer test_credential.deinit();
    var fis = std.io.fixedBufferStream(event_data);

    try authenticateUser(allocator, context, context.request.target, context.request.headers, fis.reader());
    try setContentType(&context.headers, "application/x-amz-json-1.0", false);
    // https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html#API_CreateTable_Examples
    // Operation is in X-Amz-Target
    // event_data is json
    // X-Amz-Target: DynamoDB_20120810.CreateTable
    const target_value_or_null = context.request.headers.getFirstValue("X-Amz-Target");
    const target_value = if (target_value_or_null) |t| t else {
        context.status = .bad_request;
        context.reason = "Missing X-Amz-Target header";
        return error.XAmzTargetHeaderMissing;
    };
    const operation_or_null = std.mem.lastIndexOf(u8, target_value, ".");
    const operation = if (operation_or_null) |o| target_value[o + 1 ..] else {
        context.status = .bad_request;
        context.reason = "Missing operation in X-Amz-Target";
        return error.XAmzTargetHeaderMalformed;
    };
    var authenticated_request = AuthenticatedRequest{
        .allocator = allocator,
        .event_data = event_data,
        .account_id = try accountId(allocator, context.request.headers),
        .status = context.status,
        .reason = context.reason,
        .headers = context.request.headers,
        .output_format = switch (universal_lambda_options.build_type) {
            // This may seem to be dumb, but we want to be cognizant of
            // any new platforms and explicitly consider them
            .awslambda, .standalone_server, .cloudflare, .flexilib => .json,
            .exe_run => .text,
        },
    };

    const writer = context.writer();
    if (std.ascii.eqlIgnoreCase("CreateTable", operation))
        return executeOperation(&authenticated_request, context, writer, @import("createtable.zig").handler);
    if (std.ascii.eqlIgnoreCase("BatchWriteItem", operation))
        return executeOperation(&authenticated_request, context, writer, @import("batchwriteitem.zig").handler);
    if (std.ascii.eqlIgnoreCase("BatchGetItem", operation))
        return executeOperation(&authenticated_request, context, writer, @import("batchgetitem.zig").handler);

    try writer.print("Operation '{s}' unsupported\n", .{operation});
    context.status = .bad_request;
    return error.OperationUnsupported;
}
fn setContentType(headers: *std.http.Headers, content_type: []const u8, overwrite: bool) !void {
    if (headers.contains("content-type")) {
        if (!overwrite) return;
        _ = headers.delete("content-type");
    }
    try headers.append("Content-Type", content_type);
}
fn executeOperation(
    request: *AuthenticatedRequest,
    context: universal_lambda_interface.Context,
    writer: anytype,
    operation: fn (*AuthenticatedRequest, anytype) anyerror![]const u8,
) ![]const u8 {
    return operation(request, writer) catch |err| {
        context.status = request.status;
        context.reason = request.reason;
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
        return err;
    };
}
fn authenticateUser(allocator: std.mem.Allocator, context: universal_lambda_interface.Context, target: []const u8, headers: std.http.Headers, body_reader: anytype) !void {
    var request = signing.UnverifiedRequest{
        .method = std.http.Method.POST,
        .target = target,
        .headers = headers,
    };
    const auth_bypass =
        @import("builtin").mode == .Debug and try std.process.hasEnvVar(allocator, "DEBUG_AUTHN_BYPASS");
    const is_authenticated = auth_bypass or
        signing.verify(allocator, request, body_reader, getCreds) catch |err| {
        if (std.mem.eql(u8, "AuthorizationHeaderMissing", @errorName(err))) {
            context.status = .unauthorized;
            return error.Unauthenticated;
        }
        log.err("Caught error on signature verifcation: {any}", .{err});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }

        context.status = .unauthorized;
        return error.Unauthenticated;
    };
    // Universal lambda should check these and convert them to http
    if (!is_authenticated) {
        context.status = .unauthorized;
        return error.Unauthenticated;
    }
}

// TODO: Get hook these functions up to IAM for great good
var test_credential: signing.Credentials = undefined;
fn getCreds(access: []const u8) ?signing.Credentials {
    if (std.mem.eql(u8, access, "ACCESS")) return test_credential;
    return null;
}

fn accountForAccessKey(allocator: std.mem.Allocator, access_key: []const u8) ![]const u8 {
    _ = allocator;
    log.debug("Finding account for access key: '{s}'", .{access_key});
    return "1234";
}
/// Function assumes an authenticated request, so signing.verify must be called
/// and returned true before calling this function. If authentication header
/// is not found, environment variable will be used
fn accountId(allocator: std.mem.Allocator, headers: std.http.Headers) ![]const u8 {
    const auth_header = headers.getFirstValue("Authorization");
    if (auth_header) |h| {
        // AWS4-HMAC-SHA256 Credential=ACCESS/20230908/us-west-2/s3/aws4_request, SignedHeaders=accept;content-length;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, Signature=fcc43ce73a34c9bd1ddf17e8a435f46a859812822f944f9eeb2aabcd64b03523
        const start = std.mem.indexOf(u8, h, "Credential=").? + "Credential=".len;
        var split = std.mem.split(u8, h[start..], "/");
        return try accountForAccessKey(allocator, split.first());
    }
    return try iamAccountId(allocator);
}

pub fn returnException(
    request: *AuthenticatedRequest,
    status: std.http.Status,
    err: anyerror,
    writer: anytype,
    message: []const u8,
) !void {
    switch (request.output_format) {
        .json => try writer.print(
            \\{{"__type":"{s}","message":"{s}"}}
        ,
            .{ @errorName(err), message },
        ),

        .text => try writer.print(
            "{s}: {s}\n",
            .{ @errorName(err), message },
        ),
    }
    request.status = status;
    return err;
}

// These never need to be freed because we will need them throughout the program
var iam_account_id: ?[]const u8 = null;
var iam_access_key: ?[]const u8 = null;
var iam_secret_key: ?[]const u8 = null;
var iam_credential: ?signing.Credentials = null;
fn iamCredentials(allocator: std.mem.Allocator) ![]const u8 {
    if (iam_credential) |cred| return cred;
    iam_credential = signing.Credentials.init(allocator, try iamAccessKey(allocator), try iamSecretKey(allocator), null);
    return iam_credential.?;
}
fn iamAccountId(allocator: std.mem.Allocator) ![]const u8 {
    return try getVariable(allocator, &iam_account_id, "IAM_ACCOUNT_ID");
}
fn iamAccessKey(allocator: std.mem.Allocator) ![]const u8 {
    return try getVariable(allocator, &iam_access_key, "IAM_ACCESS_KEY");
}
fn iamSecretKey(allocator: std.mem.Allocator) ![]const u8 {
    return try getVariable(allocator, &iam_secret_key, "IAM_SECRET_KEY");
}
fn getVariable(allocator: std.mem.Allocator, global: *?[]const u8, env_var_name: []const u8) ![]const u8 {
    if (global.*) |gl| return gl;
    global.* = try std.process.getEnvVarOwned(allocator, env_var_name);
    return global.*.?;
}

test {
    std.testing.refAllDecls(@import("createtable.zig"));
    std.testing.refAllDecls(@import("batchwriteitem.zig"));
    std.testing.refAllDecls(@import("batchgetitem.zig"));
}
