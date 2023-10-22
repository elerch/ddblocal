const std = @import("std");
const universal_lambda = @import("universal_lambda_handler");
const helper = @import("universal_lambda_helpers");
const signing = @import("aws-signing");

pub const std_options = struct {
    pub const log_scope_levels = &[_]std.log.ScopeLevel{.{ .scope = .aws_signing, .level = .info }};
};

pub fn main() !void {
    try universal_lambda.run(null, handler);
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
    if (std.ascii.eqlIgnoreCase("CreateTable", operation))
        return @import("createtable.zig").handler(allocator, event_data);
    try std.io.getStdErr().writer().print("Operation '{s}' unsupported\n", .{operation});
    return error.OperationUnsupported;
}

fn getCreds(access: []const u8) ?signing.Credentials {
    if (std.mem.eql(u8, access, "ACCESS")) return test_credential;
    return null;
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
    if (global) |gl| return gl;
    global = try std.process.getEnvVarOwned(allocator, env_var_name);
    return global.?;
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
