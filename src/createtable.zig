const std = @import("std");
const sqlite = @import("sqlite");

pub fn handler(allocator: std.mem.Allocator, event_data: []const u8) ![]const u8 {
    _ = event_data;
    var db = try sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .File = "donotuse.db" },
        .open_flags = .{
            .write = true,
            .create = true,
        },
        .threading_mode = .MultiThread,
    });
    try db.exec("CREATE TABLE user(id integer primary key, age integer, name text)", .{}, .{});
    var al = std.ArrayList(u8).init(allocator);
    var writer = al.writer();
    try writer.print("table created\n", .{});
    return al.items;
}
