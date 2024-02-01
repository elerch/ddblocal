const std = @import("std");
const sqlite = @import("sqlite");
const AuthenticatedRequest = @import("AuthenticatedRequest.zig");
const Account = @import("Account.zig");
const encryption = @import("encryption.zig");
const builtin = @import("builtin");

/// Serialized into metadata table. This is an explicit enum with a twin
/// AttributeTypeName enum to make coding with these types easier. Use
/// Descriptor for storage or communication with the outside world, and
/// Name for internal use
pub const AttributeTypeDescriptor = enum(u4) {
    S = 0,
    N = 1,
    B = 2,
    BOOL = 3,
    NULL = 4,
    M = 5,
    L = 6,
    SS = 7,
    NS = 8,
    BS = 9,
};

pub const AttributeTypeName = enum(u4) {
    string = 0,
    number = 1,
    binary = 2,
    boolean = 3,
    null = 4,
    map = 5,
    list = 6,
    string_set = 7,
    number_set = 8,
    binary_set = 9,
};

/// Serialized into metadata table
pub const AttributeDefinition = struct {
    name: []const u8,
    type: AttributeTypeDescriptor,
};

/// TableInfo is serialized directly into the underlying metadata table, along
/// with AttributeDefinition structure and types
pub const TableInfo = struct {
    attribute_definitions: []*const AttributeDefinition,
    // gsi_list: []const u8, // Not sure how this is used
    // gsi_description_list: []const u8, // Not sure how this is used
    // sqlite_index: []const u8, // Not sure how this is used
    table_key: [encryption.encoded_key_length]u8,
};

pub const TableArray = struct {
    items: []Table,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, length: usize) !TableArray {
        return .{
            .allocator = allocator,
            .items = try allocator.alloc(Table, length),
        };
    }

    pub fn deinit(self: *TableArray) void {
        for (self.items) |*item|
            item.deinit();
        self.allocator.free(self.items);
    }
};
pub const Table = struct {
    table_name: []const u8,
    table_key: [encryption.key_length]u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Table) void {
        std.crypto.utils.secureZero(u8, &self.table_key);
        self.allocator.free(self.table_name);
    }
};

// Gets all table names/keys for the account. Caller owns returned array
pub fn tablesForAccount(allocator: std.mem.Allocator, account_id: []const u8) !TableArray {
    var db = try Account.dbForAccount(allocator, account_id);
    defer if (!builtin.is_test) db.deinit();
    const account = try Account.accountForId(allocator, account_id); // This will get us the encryption key needed
    defer account.deinit();

    const query =
        \\SELECT TableName as table_name, TableInfo as table_info FROM dm
    ;

    var stmt = try db.prepare(query);
    defer stmt.deinit();

    const rows = try stmt.all(struct {
        table_name: []const u8,
        table_info: []const u8,
    }, allocator, .{}, .{});
    defer allocator.free(rows);
    var rc = try TableArray.init(allocator, rows.len);
    errdefer rc.deinit();

    // std.debug.print(" \n===\nRow count: {d}\n===\n", .{rows.len});
    for (rows, 0..) |row, inx| {
        defer allocator.free(row.table_name);
        defer allocator.free(row.table_info);
        const table_name = try encryption.decodeAndDecrypt(
            allocator,
            account.root_account_key.*,
            row.table_name,
        );
        errdefer allocator.free(table_name);
        const table_info_str = try encryption.decodeAndDecrypt(
            allocator,
            account.root_account_key.*,
            row.table_info,
        );
        defer allocator.free(table_info_str);
        // std.debug.print(" \n===TableInfo: {s}\n===\n", .{table_info_str});
        const table_info = try std.json.parseFromSlice(TableInfo, allocator, table_info_str, .{});
        defer table_info.deinit();
        // errdefer allocator.free(table_info.table_key);
        // defer {
        //     // we don't even really need to defer this...
        //     for (table_info.value.attribute_definitions) |*def| {
        //         allocator.free(def.*.name);
        //         allocator.destroy(def);
        //     }
        //     allocator.free(table_info.table_key);
        // }

        rc.items[inx] = .{
            .allocator = allocator,
            .table_name = table_name,
            .table_key = undefined,
        };
        try encryption.decodeKey(&rc.items[inx].table_key, table_info.value.table_key);
    }
    return rc;
}

/// creates a table in the underlying storage
pub fn createDdbTable(
    allocator: std.mem.Allocator,
    db: *sqlite.Db,
    account: Account,
    table_name: []const u8,
    table_info: TableInfo,
    read_capacity_units: i64,
    write_capacity_units: i64,
    billing_mode_pay_per_request: bool,
) !void {
    const encrypted_table_name = try insertIntoDatabaseMetadata(
        allocator,
        db,
        account,
        table_name,
        table_info,
        read_capacity_units,
        write_capacity_units,
        billing_mode_pay_per_request,
    );
    defer allocator.free(encrypted_table_name);

    var diags = sqlite.Diagnostics{};

    // It doesn't seem that I can bind a variable here. But it actually doesn't matter as we're
    // encoding the name...
    // IF NOT EXISTS doesn't apply - we want this to bounce if the table exists
    const create_stmt = try std.fmt.allocPrint(allocator,
        \\CREATE TABLE '{s}' (
        \\    hashKey TEXT DEFAULT NULL,
        \\    rangeKey TEXT DEFAULT NULL,
        \\    hashValue BLOB NOT NULL,
        \\    rangeValue BLOB NOT NULL,
        \\    itemSize INTEGER DEFAULT 0,
        \\    ObjectJSON BLOB NOT NULL,
        \\    PRIMARY KEY(hashKey, rangeKey)
        \\)
    , .{encrypted_table_name});
    defer allocator.free(create_stmt);
    // db.exec requires a comptime statement. execDynamic does not
    db.execDynamic(
        create_stmt,
        .{ .diags = &diags },
        .{},
    ) catch |e| {
        std.log.debug("SqlLite Diags: {}", .{diags});
        return e;
    };
    const create_index_stmt = try std.fmt.allocPrint(
        allocator,
        "CREATE INDEX \"{s}*HVI\" ON \"{s}\" (hashValue)",
        .{ encrypted_table_name, encrypted_table_name },
    );
    defer allocator.free(create_index_stmt);
    try db.execDynamic(create_index_stmt, .{}, .{});
}

/// Inserts a new table into the database metadata (dm) table. Handles encryption
/// Returns encrypted table name
fn insertIntoDatabaseMetadata(
    allocator: std.mem.Allocator,
    db: *sqlite.Db,
    account: Account,
    table_name: []const u8,
    table_info: TableInfo,
    read_capacity_units: i64,
    write_capacity_units: i64,
    billing_mode_pay_per_request: bool,
) ![]const u8 {
    // TODO: better to do all encryption when request params are parsed?
    const encrypted_table_name = try encryption.encryptAndEncode(allocator, account.root_account_key.*, table_name);
    errdefer allocator.free(encrypted_table_name);
    // We'll json serialize our table_info structure, encrypt, encode, and plow in
    const table_info_string = try std.json.stringifyAlloc(allocator, table_info, .{ .whitespace = .indent_2 });
    defer allocator.free(table_info_string);
    const encrypted_table_info = try encryption.encryptAndEncode(allocator, account.root_account_key.*, table_info_string);
    defer allocator.free(encrypted_table_info);
    try insertIntoDm(db, encrypted_table_name, encrypted_table_info, read_capacity_units, write_capacity_units, billing_mode_pay_per_request);
    return encrypted_table_name;
}

fn insertIntoDm(
    db: *sqlite.Db,
    table_name: []const u8,
    table_info: []const u8,
    read_capacity_units: i64,
    write_capacity_units: i64,
    billing_mode_pay_per_request: bool,
) !void {
    // const current_time = std.time.nanotimestamp();
    const current_time = std.time.microTimestamp(); // SQLlite integers are only 64bit max
    try db.exec(
        \\INSERT INTO dm(
        \\  TableName,
        \\  CreationDateTime,
        \\  LastDecreaseDate,
        \\  LastIncreaseDate,
        \\  NumberOfDecreasesToday,
        \\  ReadCapacityUnits,
        \\  WriteCapacityUnits,
        \\  TableInfo,
        \\  BillingMode,
        \\  PayPerRequestDateTime
        \\  ) VALUES (
        \\  $tablename{[]const u8},
        \\  $createdate{i64},
        \\  $lastdecreasedate{usize},
        \\  $lastincreasedate{usize},
        \\  $numberofdecreasestoday{usize},
        \\  $readcapacityunits{i64},
        \\  $writecapacityunits{i64},
        \\  $tableinfo{[]const u8},
        \\  $billingmode{usize},
        \\  $payperrequestdatetime{usize}
        \\  )
    , .{}, .{
        table_name,
        current_time,
        @as(usize, 0),
        @as(usize, 0),
        @as(usize, 0),
        read_capacity_units,
        write_capacity_units,
        table_info,
        if (billing_mode_pay_per_request) @as(usize, 1) else @as(usize, 0),
        @as(usize, 0),
    });
}

fn testCreateTable(allocator: std.mem.Allocator, account_id: []const u8) !sqlite.Db {
    var db = try Account.dbForAccount(allocator, account_id);
    const account = try Account.accountForId(allocator, account_id); // This will get us the encryption key needed
    defer account.deinit();
    var hash = AttributeDefinition{ .name = "Artist", .type = .S };
    var range = AttributeDefinition{ .name = "SongTitle", .type = .S };
    var definitions = @constCast(&[_]*AttributeDefinition{
        &hash,
        &range,
    });
    var table_info: TableInfo = .{
        .table_key = undefined,
        .attribute_definitions = definitions[0..],
    };
    encryption.randomEncodedKey(&table_info.table_key);
    try createDdbTable(
        allocator,
        &db,
        account,
        "MusicCollection",
        table_info,
        5,
        5,
        false,
    );
    return db;
}
test "can create a table" {
    const allocator = std.testing.allocator;
    const account_id = "1234";
    var db = try testCreateTable(allocator, account_id);
    defer db.deinit();
}
test "can list tables in an account" {
    Account.test_retain_db = true;
    defer Account.test_retain_db = false;
    const allocator = std.testing.allocator;
    const account_id = "1234";
    var db = try testCreateTable(allocator, account_id);
    defer db.deinit();
    var table_list = try tablesForAccount(allocator, account_id);
    defer table_list.deinit();
    try std.testing.expectEqual(@as(usize, 1), table_list.items.len);
    try std.testing.expectEqualStrings("MusicCollection", table_list.items[0].table_name);
    // std.debug.print(" \n===\nKey: {s}\n===\n", .{std.fmt.fmtSliceHexLower(&table_list.items[0].table_key)});
}
