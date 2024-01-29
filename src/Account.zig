const std = @import("std");
const encryption = @import("encryption.zig");

const test_account_key = "09aGW6z6QofVsPlWP9FGqVnshxHWAWrKZwLkwkgWs7w=";

const Self = @This();

allocator: std.mem.Allocator,
root_account_key: *[encryption.key_length]u8,

pub fn accountForId(allocator: std.mem.Allocator, account_id: []const u8) !Self {
    // TODO: Allow environment variables to house encoded keys. If not in the
    //       environment, check with LocalDB table to get it. We're
    //       building LocalDB, though, so we need that working first...
    if (!std.mem.eql(u8, account_id, "1234")) return error.NotImplemented;
    var key = try allocator.alloc(u8, encryption.key_length);
    errdefer allocator.free(key);
    try encryption.decodeKey(key[0..encryption.key_length], test_account_key.*);
    return Self{
        .allocator = allocator,
        .root_account_key = key[0..encryption.key_length],
    };
}

pub fn deinit(self: Self) void {
    self.allocator.free(self.root_account_key);
}
