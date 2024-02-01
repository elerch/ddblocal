const std = @import("std");
const encryption = @import("encryption.zig");
const sqlite = @import("sqlite"); // TODO: If we use this across all services, Account should not have this, and we should have a localdbaccount struct

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
    std.crypto.utils.secureZero(u8, self.root_account_key);
    self.allocator.free(self.root_account_key);
}

pub var data_dir: []const u8 = "";

/// Gets the database for this account. If under test, a memory database is used
/// instead. Will initialize the database with appropriate metadata tables
pub fn dbForAccount(allocator: std.mem.Allocator, account_id: []const u8) !sqlite.Db {
    // TODO: Need to move this function somewhere central
    // TODO: Need configuration for what directory to use
    // TODO: Should this be a pool, and if so, how would we know when to close?
    const file_without_path = try std.fmt.allocPrint(allocator, "ddb-{s}.sqlite3", .{account_id});
    defer allocator.free(file_without_path);
    const db_file_name = try std.fs.path.joinZ(allocator, &[_][]const u8{ data_dir, file_without_path });
    defer allocator.free(db_file_name);
    const mode = if (@import("builtin").is_test) sqlite.Db.Mode.Memory else sqlite.Db.Mode{ .File = db_file_name };
    const new = mode == .Memory or (std.fs.cwd().statFile(file_without_path) catch null == null);
    var db = try sqlite.Db.init(.{
        .mode = mode,
        .open_flags = .{
            .write = true,
            .create = new,
        },
        .threading_mode = .MultiThread,
    });

    // DDB minimum table name length is 3. DDB local creates this table with metadata
    // This of course is only if the database is first run
    if (new)
        try db.exec(
            \\CREATE TABLE dm (
            \\    TableName TEXT,
            \\    CreationDateTime INTEGER,
            \\    LastDecreaseDate INTEGER,
            \\    LastIncreaseDate INTEGER,
            \\    NumberOfDecreasesToday INTEGER,
            \\    ReadCapacityUnits INTEGER,
            \\    WriteCapacityUnits INTEGER,
            \\    TableInfo BLOB,
            \\    BillingMode INTEGER DEFAULT 0,
            \\    PayPerRequestDateTime INTEGER DEFAULT 0,
            \\    PRIMARY KEY(TableName))
        , .{}, .{});
    return db;
}
