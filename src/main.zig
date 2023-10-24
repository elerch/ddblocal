const std = @import("std");
const universal_lambda = @import("universal_lambda_handler");
const helper = @import("universal_lambda_helpers");
const signing = @import("aws-signing");

pub const std_options = struct {
    pub const log_scope_levels = &[_]std.log.ScopeLevel{.{ .scope = .aws_signing, .level = .info }};
};

pub fn main() !u8 {
    return try universal_lambda.run(null, handler);
}

var test_credential: signing.Credentials = undefined;
pub fn handler(allocator: std.mem.Allocator, event_data: []const u8, context: universal_lambda.Context) ![]const u8 {
    const access_key = try allocator.dupe(u8, "ACCESS");
    const secret_key = try allocator.dupe(u8, "SECRET");
    test_credential = signing.Credentials.init(allocator, access_key, secret_key, null);
    defer test_credential.deinit();

    var headers = try helper.allHeaders(allocator, context);
    defer headers.deinit();
    var fis = std.io.fixedBufferStream(event_data);
    var request = signing.UnverifiedRequest{
        .method = std.http.Method.PUT,
        .target = try helper.findTarget(allocator, context),
        .headers = headers.http_headers.*,
    };

    const auth_bypass =
        @import("builtin").mode == .Debug and try std.process.hasEnvVar(allocator, "DEBUG_AUTHN_BYPASS");
    const is_authenticated = auth_bypass or
        try signing.verify(allocator, request, fis.reader(), getCreds);
    // Universal lambda should check these and convert them to http
    if (!is_authenticated) return error.Unauthenticated;
    // https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html#API_CreateTable_Examples
    // Operation is in X-Amz-Target
    // event_data is json
    // X-Amz-Target: DynamoDB_20120810.CreateTable
    const target_value = headers.http_headers.getFirstValue("X-Amz-Target").?;
    const operation = target_value[std.mem.lastIndexOf(u8, target_value, ".").? + 1 ..];
    const account_id = try accountId(allocator, headers.http_headers.*);
    if (std.ascii.eqlIgnoreCase("CreateTable", operation))
        return @import("createtable.zig").handler(allocator, account_id, event_data);
    try std.io.getStdErr().writer().print("Operation '{s}' unsupported\n", .{operation});
    return error.OperationUnsupported;
}

// TODO: Get hook these functions up to IAM for great good
fn getCreds(access: []const u8) ?signing.Credentials {
    if (std.mem.eql(u8, access, "ACCESS")) return test_credential;
    return null;
}

fn accountForAccessKey(allocator: std.mem.Allocator, access_key: []const u8) ![]const u8 {
    _ = allocator;
    _ = access_key;
    return "1234, Get your woman, on the floor";
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
}
