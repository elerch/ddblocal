const std = @import("std");

pub fn handler(allocator: std.mem.Allocator, event_data: []const u8) ![]const u8 {
    _ = event_data;
    var al = std.ArrayList(u8).init(allocator);
    var writer = al.writer();
    try writer.print("hello\n", .{});
    return al.items;
}
