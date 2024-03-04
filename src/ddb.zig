const std = @import("std");
const sqlite = @import("sqlite");
const AuthenticatedRequest = @import("AuthenticatedRequest.zig");
const Account = @import("Account.zig");
const encryption = @import("encryption.zig");
const builtin = @import("builtin");
const returnException = @import("main.zig").returnException;

// We need our enryption to be able to store/retrieve and otherwise work like
// a database. So the use of a nonce here defeats these use cases
const nonce = &[_]u8{
    0x55, 0x4a, 0x38, 0x16, 0x55, 0x55, 0x2d, 0x05,
    0x32, 0x70, 0x3f, 0xa0, 0xde, 0x3d, 0x2c, 0xb8,
    0x89, 0x40, 0x07, 0xc5, 0x57, 0x7d, 0xa0, 0xb8,
};

fn encryptAndEncode(allocator: std.mem.Allocator, key: [encryption.key_length]u8, plaintext: []const u8) ![]const u8 {
    return try encryption.encryptAndEncodeWithNonce(allocator, key, nonce.*, plaintext);
}
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

    pub fn toAttributeTypeName(self: AttributeTypeDescriptor) AttributeTypeName {
        return @as(AttributeTypeName, @enumFromInt(@intFromEnum(self)));
    }
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

pub const ReturnConsumedCapacity = enum {
    indexes,
    total,
    none,
};

pub const Attribute = struct {
    name: []const u8,
    value: AttributeValue,

    pub fn parseAttributes(
        arena: std.mem.Allocator,
        value: std.json.ObjectMap,
        request: *AuthenticatedRequest,
        writer: anytype,
    ) ![]Attribute {
        // TODO: remove this function
        //  {
        //    "string" : {...attribute value...}
        //  }
        var attribute_count = value.count();
        if (attribute_count == 0)
            try returnException(
                request,
                .bad_request,
                error.ValidationException,
                writer,
                "Request in RequestItems found without any attributes in object",
            );
        var rc = try arena.alloc(Attribute, attribute_count);
        var iterator = value.iterator();
        var inx: usize = 0;
        while (iterator.next()) |att| : (inx += 1) {
            const key = att.key_ptr.*;
            const val = att.value_ptr.*;
            // std.debug.print(" \n====\nkey = \"{s}\"\nval = {any}\n====\n", .{ key, val.object.count() });
            if (val != .object or val.object.count() != 1)
                try returnException(
                    request,
                    .bad_request,
                    error.ValidationException,
                    writer,
                    "Request in RequestItems found invalid attributes in object",
                );
            rc[inx].name = key; //try arena.dupe(u8, key);
            rc[inx].value = try std.json.parseFromValueLeaky(AttributeValue, arena, val, .{});
        }
        return rc;
    }
};

pub const AttributeValue = union(AttributeTypeName) {
    string: []const u8,
    number: []const u8, // Floating point stored as string
    binary: []const u8, // Base64-encoded binary data object
    boolean: bool,
    null: bool,
    map: std.json.ObjectMap, // We're just holding the json...in the DB we probably just stringify this?
    // "M": {"Name": {"S": "Joe"}, "Age": {"N": "35"}}
    list: std.json.Array, // Again, just hoding json here:
    // "L": [ {"S": "Cookies"} , {"S": "Coffee"}, {"N": "3.14159"}]
    string_set: [][]const u8,
    number_set: [][]const u8,
    binary_set: [][]const u8,

    const Self = @This();
    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: *std.json.Scanner,
        options: std.json.ParseOptions,
    ) !Self {
        if (.object_begin != try source.next()) return error.UnexpectedToken;
        const token = try source.nextAlloc(allocator, options.allocate.?);
        if (token != .string) return error.UnexpectedToken;
        var rc: ?Self = null;
        if (std.mem.eql(u8, token.string, "string") or std.mem.eql(u8, token.string, "S"))
            rc = Self{ .string = try std.json.innerParse([]const u8, allocator, source, options) };
        if (std.mem.eql(u8, token.string, "number") or std.mem.eql(u8, token.string, "N"))
            rc = Self{ .number = try std.json.innerParse([]const u8, allocator, source, options) };
        if (std.mem.eql(u8, token.string, "binary") or std.mem.eql(u8, token.string, "B"))
            rc = Self{ .binary = try std.json.innerParse([]const u8, allocator, source, options) };
        if (std.mem.eql(u8, token.string, "boolean") or std.mem.eql(u8, token.string, "BOOL"))
            rc = Self{ .boolean = try std.json.innerParse(bool, allocator, source, options) };
        if (std.mem.eql(u8, token.string, "null") or std.mem.eql(u8, token.string, "NULL"))
            rc = Self{ .null = try std.json.innerParse(bool, allocator, source, options) };
        if (std.mem.eql(u8, token.string, "string_set") or std.mem.eql(u8, token.string, "SS"))
            rc = Self{ .string_set = try std.json.innerParse([][]const u8, allocator, source, options) };
        if (std.mem.eql(u8, token.string, "number_set") or std.mem.eql(u8, token.string, "NS"))
            rc = Self{ .number_set = try std.json.innerParse([][]const u8, allocator, source, options) };
        if (std.mem.eql(u8, token.string, "binary_set") or std.mem.eql(u8, token.string, "BS"))
            rc = Self{ .binary_set = try std.json.innerParse([][]const u8, allocator, source, options) };
        if (std.mem.eql(u8, token.string, "list") or std.mem.eql(u8, token.string, "L")) {
            var json = try std.json.Value.jsonParse(allocator, source, options);
            rc = Self{ .list = json.array };
        }
        if (std.mem.eql(u8, token.string, "map") or std.mem.eql(u8, token.string, "M")) {
            var json = try std.json.Value.jsonParse(allocator, source, options);
            rc = Self{ .map = json.object };
        }
        if (rc == null) return error.InvalidEnumTag;
        if (.object_end != try source.next()) return error.UnexpectedToken;
        rc.?.validate() catch return error.InvalidCharacter;
        return rc.?;
    }

    pub fn jsonParseFromValue(allocator: std.mem.Allocator, source: std.json.Value, options: std.json.ParseOptions) !Self {
        if (source != .object) return error.UnexpectedToken;
        var rc: ?Self = null;
        if (source.object.get("string") orelse source.object.get("S")) |attr|
            rc = Self{ .string = try std.json.innerParseFromValue([]const u8, allocator, attr, options) };
        if (source.object.get("number") orelse source.object.get("N")) |attr|
            rc = Self{ .number = try std.json.innerParseFromValue([]const u8, allocator, attr, options) };
        if (source.object.get("binary") orelse source.object.get("B")) |attr|
            rc = Self{ .binary = try std.json.innerParseFromValue([]const u8, allocator, attr, options) };
        if (source.object.get("boolean") orelse source.object.get("BOOL")) |attr|
            rc = Self{ .boolean = try std.json.innerParseFromValue(bool, allocator, attr, options) };
        if (source.object.get("null") orelse source.object.get("NULL")) |attr|
            rc = Self{ .null = try std.json.innerParseFromValue(bool, allocator, attr, options) };
        if (source.object.get("string_set") orelse source.object.get("SS")) |attr|
            rc = Self{ .string_set = try std.json.innerParseFromValue([][]const u8, allocator, attr, options) };
        if (source.object.get("number_set") orelse source.object.get("NS")) |attr|
            rc = Self{ .number_set = try std.json.innerParseFromValue([][]const u8, allocator, attr, options) };
        if (source.object.get("binary_set") orelse source.object.get("BS")) |attr|
            rc = Self{ .binary_set = try std.json.innerParseFromValue([][]const u8, allocator, attr, options) };
        if (source.object.get("list") orelse source.object.get("L")) |attr| {
            var json = try std.json.Value.jsonParseFromValue(allocator, attr, options);
            rc = Self{ .list = json.array };
        }
        if (source.object.get("map") orelse source.object.get("M")) |attr| {
            var json = try std.json.Value.jsonParseFromValue(allocator, attr, options);
            rc = Self{ .map = json.object };
        }
        if (rc == null) return error.InvalidEnumTag;

        return rc.?;
    }

    pub fn jsonStringify(self: Self, jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField(switch (self) {
            .string => "S",
            .number => "N",
            .binary => "B",
            .boolean => "BOOL",
            .null => "NULL",
            .string_set => "SS",
            .number_set => "NS",
            .binary_set => "BS",
            .list => "L",
            .map => "M",
        });
        switch (self) {
            .string, .number, .binary => |s| try jws.write(s),
            .boolean, .null => |b| try jws.write(b),
            .string_set, .number_set, .binary_set => |s| try jws.write(s),
            .list => |l| try jws.write(l.items),
            .map => |inner| {
                try jws.beginObject();
                var it = inner.iterator();
                while (it.next()) |entry| {
                    try jws.objectField(entry.key_ptr.*);
                    try jws.write(entry.value_ptr.*);
                }
                try jws.endObject();
            },
        }
        return try jws.endObject();
    }
    pub fn validate(self: Self) !void {
        switch (self) {
            .string, .string_set, .boolean, .null, .map, .list => {},
            .number => |s| _ = try std.fmt.parseFloat(f64, s),
            .binary => |s| try base64Validate(std.base64.standard.Decoder, s),
            .number_set => |ns| for (ns) |s| {
                _ = try std.fmt.parseFloat(f64, s);
            },
            .binary_set => |bs| for (bs) |s| try base64Validate(std.base64.standard.Decoder, s),
        }
    }

    fn base64Validate(decoder: std.base64.Base64Decoder, source: []const u8) std.base64.Error!void {
        const invalid_char = 0xff;
        // This is taken from the stdlib decode function and modified to simply
        // not write anything
        if (decoder.pad_char != null and source.len % 4 != 0) return error.InvalidPadding;
        var acc: u12 = 0;
        var acc_len: u4 = 0;
        var leftover_idx: ?usize = null;
        for (source, 0..) |c, src_idx| {
            const d = decoder.char_to_index[c];
            if (d == invalid_char) {
                if (decoder.pad_char == null or c != decoder.pad_char.?) return error.InvalidCharacter;
                leftover_idx = src_idx;
                break;
            }
            acc = (acc << 6) + d;
            acc_len += 6;
            if (acc_len >= 8) {
                acc_len -= 8;
            }
        }
        if (acc_len > 4 or (acc & (@as(u12, 1) << acc_len) - 1) != 0) {
            return error.InvalidPadding;
        }
        if (leftover_idx == null) return;
        var leftover = source[leftover_idx.?..];
        if (decoder.pad_char) |pad_char| {
            const padding_len = acc_len / 2;
            var padding_chars: usize = 0;
            for (leftover) |c| {
                if (c != pad_char) {
                    return if (c == invalid_char) error.InvalidCharacter else error.InvalidPadding;
                }
                padding_chars += 1;
            }
            if (padding_chars != padding_len) return error.InvalidPadding;
        }
    }
};

/// TableInfo is serialized directly into the underlying metadata table, along
/// with AttributeDefinition structure and types
pub const TableInfo = struct {
    attribute_definitions: []*const AttributeDefinition,
    // gsi_list: []const u8, // Not sure how this is used
    // gsi_description_list: []const u8, // Not sure how this is used
    // sqlite_index: []const u8, // Not sure how this is used
    table_key: [encryption.encoded_key_length]u8,

    // DDB Local is using sqlite_index here, which seems very much overkill
    // as everything can be determined by just the name...
    hash_key_attribute_name: []const u8,
    range_key_attribute_name: ?[]const u8,
};

pub const AccountTables = struct {
    items: []Table,
    db: *sqlite.Db,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, length: usize, db: *sqlite.Db) !AccountTables {
        return .{
            .allocator = allocator,
            .items = try allocator.alloc(Table, length),
            .db = db,
        };
    }

    pub fn deinit(self: *AccountTables) void {
        for (self.items) |*item|
            item.deinit();
        self.allocator.free(self.items);
    }
};
pub const Table = struct {
    name: []const u8,
    key: [encryption.key_length]u8,
    info: std.json.Parsed(TableInfo),
    /// underlying data for json parsed version
    info_str: []const u8,
    db: *sqlite.Db,
    allocator: std.mem.Allocator,
    encrypted_name: []const u8,

    pub fn deleteItem(self: *Table, hash_value: []const u8, range_value: ?[]const u8) !void {
        const encrypted_hash = try encryptAndEncode(self.allocator, self.key, hash_value);
        defer self.allocator.free(encrypted_hash);
        const encrypted_range = if (range_value) |r|
            try encryptAndEncode(self.allocator, self.key, r)
        else
            null;
        defer if (encrypted_range != null) self.allocator.free(encrypted_range.?);

        // TODO: hashKey and rangeKey are text, while hashvalue/rangevalue are blobx
        // this is to accomodate non-string hash/range value by running a hash
        // function over the data, probably base64 encoded. Do we want to do
        // something like this?
        const delete = try std.fmt.allocPrint(self.allocator,
            \\DELETE FROM '{s}' WHERE
            \\    hashKey = ?
            \\  AND
            \\    rangeKey = ?
        , .{self.encrypted_name});
        defer self.allocator.free(delete);
        try self.db.execDynamic(delete, .{}, .{
            encrypted_hash,
            encrypted_range,
        });
    }
    pub fn getItem(
        self: *Table,
        hash_value: []const u8,
        range_value: ?[]const u8,
    ) ![][]const u8 {
        const encrypted_hash = try encryptAndEncode(self.allocator, self.key, hash_value);
        defer self.allocator.free(encrypted_hash);
        const range_clause = blk: {
            if (range_value == null) break :blk "";
            const encrypted_range = try encryptAndEncode(self.allocator, self.key, range_value.?);
            defer self.allocator.free(encrypted_range);
            // This is base64 encoded, so no chance of sql injection with this
            break :blk try std.fmt.allocPrint(self.allocator, "\n  AND rangeKey = '{s}'", .{encrypted_range});
        };
        defer if (range_value != null) self.allocator.free(range_clause);
        // const encrypted_data = try encryptAndEncode(self.allocator, self.key, data);
        // defer self.allocator.free(encrypted_data);

        // TODO: hashKey and rangeKey are text, while hashvalue/rangevalue are blobx
        // this is to accomodate non-string hash/range value by running a hash
        // function over the data, probably base64 encoded. Do we want to do
        // something like this?
        const select = try std.fmt.allocPrint(self.allocator,
            \\SELECT ObjectJSON FROM '{s}'
            \\  WHERE hashKey = ? {s}
        , .{ self.encrypted_name, range_clause });
        defer self.allocator.free(select);
        var stmt = try self.db.prepareDynamic(select);
        defer stmt.deinit();

        var iter = try stmt.iterator([]const u8, .{
            .hash = encrypted_hash,
        });
        var results = std.ArrayList([]const u8).init(self.allocator);
        defer results.deinit();
        while (try iter.nextAlloc(self.allocator, .{})) |encoded_data| {
            defer self.allocator.free(encoded_data);
            const data = try encryption.decodeAndDecrypt(self.allocator, self.key, encoded_data);
            try results.append(data);
        }

        return results.toOwnedSlice();
    }
    pub fn putItem(
        self: *Table,
        hash_value: []const u8,
        range_value: ?[]const u8,
        data: []const u8,
    ) !void {
        var sp = try self.db.savepoint("putItem");

        errdefer sp.rollback();
        // TODO: savepoint this
        try self.deleteItem(hash_value, range_value);
        const encrypted_hash = try encryptAndEncode(self.allocator, self.key, hash_value);
        defer self.allocator.free(encrypted_hash);
        const encrypted_range = if (range_value) |r|
            try encryptAndEncode(self.allocator, self.key, r)
        else
            null;
        defer if (encrypted_range != null) self.allocator.free(encrypted_range.?);
        const encrypted_data = try encryptAndEncode(self.allocator, self.key, data);
        defer self.allocator.free(encrypted_data);

        // TODO: hashKey and rangeKey are text, while hashvalue/rangevalue are blobx
        // this is to accomodate non-string hash/range value by running a hash
        // function over the data, probably base64 encoded. Do we want to do
        // something like this?
        const insert = try std.fmt.allocPrint(self.allocator,
            \\INSERT INTO '{s}' (
            \\    hashKey,
            \\    rangeKey,
            \\    hashValue,
            \\    rangeValue,
            \\    itemSize,
            \\    ObjectJSON
            \\  ) VALUES ( ?, ?, ?, ?, ?, ? )
            // This syntax doesn't seem to work here? Used ?'s above
            // \\  $encrypted_hash{{[]const u8}},
            // \\  $encrypted_range{{[]const u8}},
            // \\  $encrypted_hash{{[]const u8}},
            // \\  $encrypted_range{{[]const u8}},
            // \\  $len{{usize}},
            // \\  $encrypted_data{{[]const u8}}
            // \\  )
        , .{self.encrypted_name});
        defer self.allocator.free(insert);
        var diags = sqlite.Diagnostics{};
        // std.debug.print(
        //     \\====================
        //     \\Insert to table: {s}
        //     \\  hashKey: {s}
        //     \\  rangeKey: {?s}
        //     \\  hashValue: {s}
        //     \\  rangeValue: {?s}
        //     \\  itemSize: {d}
        //     \\  ObjectJSON: {s}
        //     \\====================
        // , .{
        //     self.encrypted_name,
        //     encrypted_hash,
        //     encrypted_range,
        //     encrypted_hash,
        //     encrypted_range,
        //     encrypted_data.len,
        //     encrypted_data,
        // });
        self.db.execDynamic(insert, .{ .diags = &diags }, .{
            encrypted_hash,
            encrypted_range,
            encrypted_hash,
            encrypted_range,
            encrypted_data.len,
            encrypted_data,
        }) catch |e| {
            std.debug.print("Insert stmt: {s}\n", .{insert});
            std.debug.print("SqlLite diags: {s}\n", .{diags});
            return e;
        };
        sp.commit();
    }

    pub fn deinit(self: *Table) void {
        std.crypto.utils.secureZero(u8, &self.key);
        self.allocator.free(self.encrypted_name);
        self.allocator.free(self.info_str);
        self.info.deinit();
        self.allocator.free(self.name);
    }
};

/// Gets all table names/keys for the account. Caller owns returned array
/// The return value will also provide the opened database. As encryption keys
/// are stored in here, realistically, this will be the first function called
/// every time anything interacts with the database, so this function opens
/// the database for you
pub fn tablesForAccount(allocator: std.mem.Allocator, account_id: u40) !AccountTables {

    // TODO: This function should take a list of table names, which can then be used
    // to filter the query below rather than just grabbing everything
    var db = try Account.dbForAccount(allocator, account_id);
    errdefer if (!builtin.is_test) db.deinit();
    const account = try Account.accountForId(allocator, account_id); // This will get us the encryption key needed
    defer account.deinit();

    const query =
        \\SELECT TableName as name, TableInfo as info FROM dm
    ;

    var stmt = try db.prepare(query);
    defer stmt.deinit();

    const rows = try stmt.all(struct {
        name: []const u8,
        info: []const u8,
    }, allocator, .{}, .{});
    defer allocator.free(rows);
    var rc = try AccountTables.init(allocator, rows.len, db);
    errdefer rc.deinit();

    // std.debug.print(" \n===\nRow count: {d}\n===\n", .{rows.len});
    for (rows, 0..) |row, inx| {
        defer allocator.free(row.name);
        defer allocator.free(row.info);
        const table_name = try encryption.decodeAndDecrypt(
            allocator,
            account.root_account_key.*,
            row.name,
        );
        errdefer allocator.free(table_name);
        const table_info_str = try encryption.decodeAndDecrypt(
            allocator,
            account.root_account_key.*,
            row.info,
        );

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
            .name = table_name,
            .encrypted_name = try allocator.dupe(u8, row.name),
            .key = undefined,
            .info = try std.json.parseFromSlice(TableInfo, allocator, table_info_str, .{}),
            .info_str = table_info_str,
            .db = db,
        };
        try encryption.decodeKey(&rc.items[inx].key, rc.items[inx].info.value.table_key);
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
    const encrypted_table_name = try encryptAndEncode(allocator, account.root_account_key.*, table_name);
    errdefer allocator.free(encrypted_table_name);
    // We'll json serialize our table_info structure, encrypt, encode, and plow in
    const table_info_string = try std.json.stringifyAlloc(allocator, table_info, .{ .whitespace = .indent_2 });
    defer allocator.free(table_info_string);
    const encrypted_table_info = try encryptAndEncode(allocator, account.root_account_key.*, table_info_string);
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

fn testCreateTable(allocator: std.mem.Allocator, account_id: u40) !*sqlite.Db {
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
        .hash_key_attribute_name = "Artist",
        .range_key_attribute_name = null,
    };
    encryption.randomEncodedKey(&table_info.table_key);
    try createDdbTable(
        allocator,
        db,
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
    const account_id = 1234;
    var db = try testCreateTable(allocator, account_id);
    defer allocator.destroy(db);
    defer db.deinit();
}
test "can list tables in an account" {
    Account.test_retain_db = true;
    const allocator = std.testing.allocator;
    const account_id = 1234;
    var db = try testCreateTable(allocator, account_id);
    defer allocator.destroy(db);
    defer Account.testDbDeinit();
    var table_list = try tablesForAccount(allocator, account_id);
    defer table_list.deinit();
    try std.testing.expectEqual(@as(usize, 1), table_list.items.len);
    try std.testing.expectEqualStrings("MusicCollection", table_list.items[0].name);
    // std.debug.print(" \n===\nKey: {s}\n===\n", .{std.fmt.fmtSliceHexLower(&table_list.items[0].table_key)});
}

test "can put an item in a table in an account" {
    Account.test_retain_db = true;
    const allocator = std.testing.allocator;
    const account_id = 1234;
    var db = try testCreateTable(allocator, account_id);
    defer allocator.destroy(db);
    defer Account.testDbDeinit();
    var table_list = try tablesForAccount(allocator, account_id);
    defer table_list.deinit();
    try std.testing.expectEqualStrings("MusicCollection", table_list.items[0].name);
    var table = table_list.items[0];
    try table.putItem("Foo Fighters", "Everlong", "whatevs");
    // This should succeed, because putItem is an upsert mechanism
    try table.putItem("Foo Fighters", "Everlong", "whatevs");

    // TODO: this test should do getItem to verify data
    // std.debug.print(" \n===\nKey: {s}\n===\n", .{std.fmt.fmtSliceHexLower(&table_list.items[0].table_key)});
}

test "can parse attribute values using slices" {
    const allocator = std.testing.allocator;
    const source =
        \\                    {
        \\                        "String": {
        \\                            "S": "Amazon DynamoDB"
        \\                        },
        \\                        "Number": {
        \\                            "N": "1.3"
        \\                        },
        \\                        "Binary": {
        \\                            "B": "dGhpcyB0ZXh0IGlzIGJhc2U2NC1lbmNvZGVk"
        \\                        },
        \\                        "Boolean": {
        \\                            "BOOL": true
        \\                        },
        \\                        "Null": {
        \\                            "NULL": true
        \\                        },
        \\                        "List": {
        \\                            "L": [ {"S": "Cookies"} , {"S": "Coffee"}, {"N": "3.14159"}]
        \\                        },
        \\                        "Map": {
        \\                            "M": {"Name": {"S": "Joe"}, "Age": {"N": "35"}}
        \\                        },
        \\                        "Number Set": {
        \\                            "NS": ["42.2", "-19", "7.5", "3.14"]
        \\                        },
        \\                        "Binary Set": {
        \\                            "BS": ["U3Vubnk=", "UmFpbnk=", "U25vd3k="]
        \\                        },
        \\                        "String Set": {
        \\                            "SS": ["Giraffe", "Hippo" ,"Zebra"]
        \\                        }
        \\                    }
    ;
    const source_value = try std.json.parseFromSlice(std.json.Value, allocator, source, .{});
    defer source_value.deinit();
    var val = source_value.value.object.get("String").?;
    {
        const attribute_value_string = try std.json.stringifyAlloc(allocator, val, .{});
        defer allocator.free(attribute_value_string);

        const attribute_value = try std.json.parseFromSlice(AttributeValue, allocator, attribute_value_string, .{});
        // const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqualStrings("Amazon DynamoDB", attribute_value.value.string);
    }
    val = source_value.value.object.get("Number").?;
    {
        const attribute_value_string = try std.json.stringifyAlloc(allocator, val, .{});
        defer allocator.free(attribute_value_string);

        const attribute_value = try std.json.parseFromSlice(AttributeValue, allocator, attribute_value_string, .{});
        // const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqualStrings("1.3", attribute_value.value.number);
    }
    val = source_value.value.object.get("Binary").?;
    {
        const attribute_value_string = try std.json.stringifyAlloc(allocator, val, .{});
        defer allocator.free(attribute_value_string);

        const attribute_value = try std.json.parseFromSlice(AttributeValue, allocator, attribute_value_string, .{});
        // const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqualStrings("dGhpcyB0ZXh0IGlzIGJhc2U2NC1lbmNvZGVk", attribute_value.value.binary);
    }
    val = source_value.value.object.get("Boolean").?;
    {
        const attribute_value_string = try std.json.stringifyAlloc(allocator, val, .{});
        defer allocator.free(attribute_value_string);

        const attribute_value = try std.json.parseFromSlice(AttributeValue, allocator, attribute_value_string, .{});
        // const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqual(true, attribute_value.value.boolean);
    }
    val = source_value.value.object.get("Null").?;
    {
        const attribute_value_string = try std.json.stringifyAlloc(allocator, val, .{});
        defer allocator.free(attribute_value_string);

        const attribute_value = try std.json.parseFromSlice(AttributeValue, allocator, attribute_value_string, .{});
        // const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqual(true, attribute_value.value.null);
    }
    val = source_value.value.object.get("List").?;
    {
        const attribute_value_string = try std.json.stringifyAlloc(allocator, val, .{});
        defer allocator.free(attribute_value_string);

        const attribute_value = try std.json.parseFromSlice(AttributeValue, allocator, attribute_value_string, .{});
        // const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqual(@as(usize, 3), attribute_value.value.list.items.len);
    }
    val = source_value.value.object.get("Map").?;
    {
        const attribute_value_string = try std.json.stringifyAlloc(allocator, val, .{});
        defer allocator.free(attribute_value_string);

        const attribute_value = try std.json.parseFromSlice(AttributeValue, allocator, attribute_value_string, .{});
        // const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqual(@as(usize, 2), attribute_value.value.map.keys().len);
    }
    val = source_value.value.object.get("Number Set").?;
    {
        const attribute_value_string = try std.json.stringifyAlloc(allocator, val, .{});
        defer allocator.free(attribute_value_string);

        const attribute_value = try std.json.parseFromSlice(AttributeValue, allocator, attribute_value_string, .{});
        // const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqual(@as(usize, 4), attribute_value.value.number_set.len);
        try std.testing.expectEqualStrings("7.5", attribute_value.value.number_set[2]);
    }
    val = source_value.value.object.get("Binary Set").?;
    {
        const attribute_value_string = try std.json.stringifyAlloc(allocator, val, .{});
        defer allocator.free(attribute_value_string);

        const attribute_value = try std.json.parseFromSlice(AttributeValue, allocator, attribute_value_string, .{});
        // const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqual(@as(usize, 3), attribute_value.value.binary_set.len);
        try std.testing.expectEqualStrings("U25vd3k=", attribute_value.value.binary_set[2]);
    }
    val = source_value.value.object.get("String Set").?;
    {
        const attribute_value_string = try std.json.stringifyAlloc(allocator, val, .{});
        defer allocator.free(attribute_value_string);

        const attribute_value = try std.json.parseFromSlice(AttributeValue, allocator, attribute_value_string, .{});
        // const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqual(@as(usize, 3), attribute_value.value.string_set.len);
        try std.testing.expectEqualStrings("Zebra", attribute_value.value.string_set[2]);
    }
}

test "can parse attribute values using jsonvalue" {
    const allocator = std.testing.allocator;
    const source =
        \\                    {
        \\                        "String": {
        \\                            "S": "Amazon DynamoDB"
        \\                        },
        \\                        "Number": {
        \\                            "N": "1.3"
        \\                        },
        \\                        "Binary": {
        \\                            "B": "dGhpcyB0ZXh0IGlzIGJhc2U2NC1lbmNvZGVk"
        \\                        },
        \\                        "Boolean": {
        \\                            "BOOL": true
        \\                        },
        \\                        "Null": {
        \\                            "NULL": true
        \\                        },
        \\                        "List": {
        \\                            "L": [ {"S": "Cookies"} , {"S": "Coffee"}, {"N": "3.14159"}]
        \\                        },
        \\                        "Map": {
        \\                            "M": {"Name": {"S": "Joe"}, "Age": {"N": "35"}}
        \\                        },
        \\                        "Number Set": {
        \\                            "NS": ["42.2", "-19", "7.5", "3.14"]
        \\                        },
        \\                        "Binary Set": {
        \\                            "BS": ["U3Vubnk=", "UmFpbnk=", "U25vd3k="]
        \\                        },
        \\                        "String Set": {
        \\                            "SS": ["Giraffe", "Hippo" ,"Zebra"]
        \\                        }
        \\                    }
    ;
    const source_value = try std.json.parseFromSlice(std.json.Value, allocator, source, .{});
    defer source_value.deinit();
    var val = source_value.value.object.get("String").?;
    {
        const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqualStrings("Amazon DynamoDB", attribute_value.value.string);
    }
    val = source_value.value.object.get("Number").?;
    {
        const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqualStrings("1.3", attribute_value.value.number);
    }
    val = source_value.value.object.get("Binary").?;
    {
        const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqualStrings("dGhpcyB0ZXh0IGlzIGJhc2U2NC1lbmNvZGVk", attribute_value.value.binary);
    }
    val = source_value.value.object.get("Boolean").?;
    {
        const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqual(true, attribute_value.value.boolean);
    }
    val = source_value.value.object.get("Null").?;
    {
        const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqual(true, attribute_value.value.null);
    }
    val = source_value.value.object.get("List").?;
    {
        const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqual(@as(usize, 3), attribute_value.value.list.items.len);
    }
    val = source_value.value.object.get("Map").?;
    {
        const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqual(@as(usize, 2), attribute_value.value.map.keys().len);
    }
    val = source_value.value.object.get("Number Set").?;
    {
        const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqual(@as(usize, 4), attribute_value.value.number_set.len);
        try std.testing.expectEqualStrings("7.5", attribute_value.value.number_set[2]);
    }
    val = source_value.value.object.get("Binary Set").?;
    {
        const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqual(@as(usize, 3), attribute_value.value.binary_set.len);
        try std.testing.expectEqualStrings("U25vd3k=", attribute_value.value.binary_set[2]);
    }
    val = source_value.value.object.get("String Set").?;
    {
        const attribute_value = try std.json.parseFromValue(AttributeValue, allocator, val, .{});
        defer attribute_value.deinit();
        try std.testing.expectEqual(@as(usize, 3), attribute_value.value.string_set.len);
        try std.testing.expectEqualStrings("Zebra", attribute_value.value.string_set[2]);
    }
}

test "round trip attributes" {
    const allocator = std.testing.allocator;
    var json_stuff = try std.json.parseFromSlice(std.json.Value, allocator,
        \\ {
        \\ "M": {"Name": {"S": "Joe"}, "Age": {"N": "35"}},
        \\ "L": [ {"S": "Cookies"} , {"S": "Coffee"}, {"N": "3.14159"}]
        \\ }
    , .{});
    defer json_stuff.deinit();
    const map = json_stuff.value.object.get("M").?.object;
    const list = json_stuff.value.object.get("L").?.array;
    const attributes = &[_]Attribute{
        .{
            .name = "foo",
            .value = .{ .string = "bar" },
        },
        .{
            .name = "foo",
            .value = .{ .number = "42" },
        },
        .{
            .name = "foo",
            .value = .{ .binary = "YmFy" }, // "bar"
        },
        .{
            .name = "foo",
            .value = .{ .boolean = true },
        },
        .{
            .name = "foo",
            .value = .{ .null = false },
        },
        .{
            .name = "foo",
            .value = .{ .string_set = @constCast(&[_][]const u8{ "foo", "bar" }) },
        },
        .{
            .name = "foo",
            .value = .{ .number_set = @constCast(&[_][]const u8{ "41", "42" }) },
        },
        .{
            .name = "foo",
            .value = .{ .binary_set = @constCast(&[_][]const u8{ "Zm9v", "YmFy" }) }, // foo, bar
        },
        .{
            .name = "foo",
            .value = .{ .map = map },
        },
        .{
            .name = "foo",
            .value = .{ .list = list },
        },
    };
    const attributes_as_string = try std.json.stringifyAlloc(
        allocator,
        attributes,
        .{ .whitespace = .indent_2 },
    );
    defer allocator.free(attributes_as_string);
    try std.testing.expectEqualStrings(
        \\[
        \\  {
        \\    "name": "foo",
        \\    "value": {
        \\      "S": "bar"
        \\    }
        \\  },
        \\  {
        \\    "name": "foo",
        \\    "value": {
        \\      "N": "42"
        \\    }
        \\  },
        \\  {
        \\    "name": "foo",
        \\    "value": {
        \\      "B": "YmFy"
        \\    }
        \\  },
        \\  {
        \\    "name": "foo",
        \\    "value": {
        \\      "BOOL": true
        \\    }
        \\  },
        \\  {
        \\    "name": "foo",
        \\    "value": {
        \\      "NULL": false
        \\    }
        \\  },
        \\  {
        \\    "name": "foo",
        \\    "value": {
        \\      "SS": [
        \\        "foo",
        \\        "bar"
        \\      ]
        \\    }
        \\  },
        \\  {
        \\    "name": "foo",
        \\    "value": {
        \\      "NS": [
        \\        "41",
        \\        "42"
        \\      ]
        \\    }
        \\  },
        \\  {
        \\    "name": "foo",
        \\    "value": {
        \\      "BS": [
        \\        "Zm9v",
        \\        "YmFy"
        \\      ]
        \\    }
        \\  },
        \\  {
        \\    "name": "foo",
        \\    "value": {
        \\      "M": {
        \\        "Name": {
        \\          "S": "Joe"
        \\        },
        \\        "Age": {
        \\          "N": "35"
        \\        }
        \\      }
        \\    }
        \\  },
        \\  {
        \\    "name": "foo",
        \\    "value": {
        \\      "L": [
        \\        {
        \\          "S": "Cookies"
        \\        },
        \\        {
        \\          "S": "Coffee"
        \\        },
        \\        {
        \\          "N": "3.14159"
        \\        }
        \\      ]
        \\    }
        \\  }
        \\]
    , attributes_as_string);

    var round_tripped = try std.json.parseFromSlice([]Attribute, allocator, attributes_as_string, .{});
    defer round_tripped.deinit();
}
