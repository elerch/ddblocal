const std = @import("std");
const sqlite = @import("sqlite");
const AuthenticatedRequest = @import("AuthenticatedRequest.zig");
const Account = @import("Account.zig");
const encryption = @import("encryption.zig");
const returnException = @import("main.zig").returnException;

pub fn handler(request: *AuthenticatedRequest, writer: anytype) ![]const u8 {
    _ = writer;
    const allocator = request.allocator;
    const account_id = request.account_id;
    _ = account_id;

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, request.event_data, .{});
    defer parsed.deinit();
    // const request_params = try parseRequest(request, parsed, writer);
    return "hi";
}
