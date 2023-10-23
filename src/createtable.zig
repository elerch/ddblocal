const std = @import("std");
const sqlite = @import("sqlite");

pub fn handler(allocator: std.mem.Allocator, account_id: []const u8, event_data: []const u8) ![]const u8 {
    _ = event_data;
    var db = try sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .File = "donotuse.db" },
        .open_flags = .{
            .write = true,
            .create = true,
        },
        .threading_mode = .MultiThread,
    });
    // DDB minimum table name length is 3. DDB local creates this table with metadata
    // This of course is only if the database is first run
    // try db.exec(
    //     \\CREATE TABLE dm (
    //     \\    TableName TEXT,
    //     \\    CreationDateTime INTEGER,
    //     \\    LastDecreaseDate INTEGER,
    //     \\    LastIncreaseDate INTEGER,
    //     \\    NumberOfDecreasesToday INTEGER,
    //     \\    ReadCapacityUnits INTEGER,
    //     \\    WriteCapacityUnits INTEGER,
    //     \\    TableInfo BLOB,
    //     \\    BillingMode INTEGER DEFAULT 0,
    //     \\    PayPerRequestDateTime INTEGER DEFAULT 0,
    //     \\    PRIMARY KEY(TableName)
    // );
    try db.exec("CREATE TABLE user(id integer primary key, age integer, name text)", .{}, .{});
    var al = std.ArrayList(u8).init(allocator);
    var writer = al.writer();
    try writer.print("table created for account {s}\n", .{account_id});
    return al.items;

    // This is what the music collection sample creates
    // CREATE TABLE IF NOT EXISTS "MusicCollection" (hashKey TEXT DEFAULT NULL, rangeKey TEXT DEFAULT NULL, hashValue BLOB NOT NULL, rangeValue BLOB NOT NULL, itemSize INTEGER DEFAULT 0, ObjectJSON BLOB NOT NULL, PRIMARY KEY(hashKey, rangeKey));
    // CREATE INDEX "MusicCollection*HVI" ON "MusicCollection" (hashValue);
}
