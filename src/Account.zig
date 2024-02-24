const std = @import("std");
const encryption = @import("encryption.zig");
const sqlite = @import("sqlite"); // TODO: If we use this across all services, Account should not have this, and we should have a localdbaccount struct

const test_account_key = "09aGW6z6QofVsPlWP9FGqVnshxHWAWrKZwLkwkgWs7w=";

const log = std.log.scoped(.Account);
const Self = @This();

allocator: std.mem.Allocator,
root_account_key: *[encryption.key_length]u8,

pub var root_key_mapping: ?std.StringHashMap([]const u8) = null;

pub fn accountForId(allocator: std.mem.Allocator, account_id: []const u8) !Self {
    if (std.mem.eql(u8, account_id, "1234")) {
        var key = try allocator.alloc(u8, encryption.key_length);
        errdefer allocator.free(key);
        try encryption.decodeKey(key[0..encryption.key_length], test_account_key.*);
        return Self{
            .allocator = allocator,
            .root_account_key = key[0..encryption.key_length],
        };
    }

    // Check our root mappings (populated elsewhere)
    if (root_key_mapping) |m| {
        if (m.get(account_id)) |k| {
            var key = try allocator.alloc(u8, encryption.key_length);
            errdefer allocator.free(key);
            try encryption.decodeKey(key[0..encryption.key_length], @constCast(k[0..encryption.encoded_key_length]).*);
            return Self{
                .allocator = allocator,
                .root_account_key = key[0..encryption.key_length],
            };
        }
    }

    // TODO: Check STS
    log.err("Got account id '{s}', but could not find this ('1234' is test account). STS GetAccessKeyInfo not implemented", .{account_id});
    return error.NotImplemented;
}

pub fn deinit(self: Self) void {
    std.crypto.utils.secureZero(u8, self.root_account_key);
    self.allocator.free(self.root_account_key);
}

pub var data_dir: []const u8 = "";
pub var test_retain_db: bool = false;
var test_db: ?*sqlite.Db = null;

pub fn testDbDeinit() void {
    test_retain_db = false;
    if (test_db) |db| {
        db.deinit();
        test_db = null;
    }
}
/// Gets the database for this account. If under test, a memory database is used
/// instead. Will initialize the database with appropriate metadata tables
pub fn dbForAccount(allocator: std.mem.Allocator, account_id: []const u8) !*sqlite.Db {
    const builtin = @import("builtin");
    if (builtin.is_test and test_retain_db)
        if (test_db) |db| return db;
    // TODO: Need to move this function somewhere central
    // TODO: Need configuration for what directory to use
    // TODO: Should this be a pool, and if so, how would we know when to close?
    const file_without_path = try std.fmt.allocPrint(allocator, "ddb-{s}.sqlite3", .{account_id});
    defer allocator.free(file_without_path);
    const db_file_name = try std.fs.path.joinZ(allocator, &[_][]const u8{ data_dir, file_without_path });
    defer allocator.free(db_file_name);
    const mode = if (builtin.is_test) sqlite.Db.Mode.Memory else sqlite.Db.Mode{ .File = db_file_name };
    const new = mode == .Memory or (std.fs.cwd().statFile(file_without_path) catch null == null);
    var db = try allocator.create(sqlite.Db);
    db.* = try sqlite.Db.init(.{
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
    if (builtin.is_test and test_retain_db) test_db = db;
    return db;
}
