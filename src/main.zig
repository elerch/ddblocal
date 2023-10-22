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

    // https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html#API_CreateTable_Examples
    // Operation is in X-Amz-Target
    // event_data is json
    var al = std.ArrayList(u8).init(allocator);
    var writer = al.writer();
    try writer.print("Mode: {}\nAuthenticated: {}\nValue for header 'Foo' is: {s}\n", .{
        @import("builtin").mode,
        is_authenticated,
        headers.http_headers.getFirstValue("foo") orelse "undefined",
    });
    return al.items;
}

fn getCreds(access: []const u8) ?signing.Credentials {
    if (std.mem.eql(u8, access, "ACCESS")) return test_credential;
    return null;
}
test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
