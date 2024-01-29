const std = @import("std");
const sqlite = @import("sqlite");
const AuthenticatedRequest = @import("AuthenticatedRequest.zig");
const Account = @import("Account.zig");
const encryption = @import("encryption.zig");
pub var data_dir: []const u8 = "";

// These are in the original casing so as to make the error messages nice
const RequiredFields = enum(u3) {
    // zig fmt: off
    TableName            = 1 << 0,
    AttributeDefinitions = 1 << 1,
    KeySchema            = 1 << 2,
    // zig fmt: on
};

const AttributeTypeDescriptor = enum(u4) {
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

const AttributeTypeName = enum(4) {
    String = 0,
    Number = 1,
    Binary = 2,
    Boolean = 3,
    Null = 4,
    Map = 5,
    List = 6,
    StringSet = 7,
    NumberSet = 8,
    BinarySet = 9,
};

const AttributeDefinition = struct {
    name: []const u8,
    type: AttributeTypeDescriptor,
};
const TableInfo = struct {
    attribute_definitions: []*AttributeDefinition,
    // gsi_list: []const u8, // Not sure how this is used
    // gsi_description_list: []const u8, // Not sure how this is used
    // sqlite_index: []const u8, // Not sure how this is used
    table_key: [encryption.encoded_key_length]u8,
};

const Params = struct {
    table_name: []const u8,
    table_info: TableInfo,
    read_capacity_units: ?i64 = null,
    write_capacity_units: ?i64 = null,
    billing_mode_pay_per_request: bool = false,
};
pub fn handler(request: *AuthenticatedRequest, writer: anytype) ![]const u8 {
    const allocator = request.allocator;
    const account_id = request.account_id;

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, request.event_data, .{});
    defer parsed.deinit();
    const request_params = try parseRequest(request, parsed, writer);
    defer {
        for (request_params.table_info.attribute_definitions) |d| {
            allocator.free(d.*.name);
            allocator.destroy(d);
        }
        allocator.free(request_params.table_info.attribute_definitions);
    }
    var db = try dbForAccount(allocator, account_id);
    const account = try Account.accountForId(allocator, account_id); // This will get us the encryption key needed
    defer account.deinit();
    // TODO: better to do all encryption when request params are parsed?
    const table_name = try encryption.encryptAndEncode(allocator, account.root_account_key.*, request_params.table_name);
    defer allocator.free(table_name);
    // We'll json serialize our table_info structure, encrypt, encode, and plow in
    const table_info_string = try std.json.stringifyAlloc(allocator, request_params.table_info, .{ .whitespace = .indent_2 });
    defer allocator.free(table_info_string);
    const table_info = try encryption.encryptAndEncode(allocator, account.root_account_key.*, table_info_string);
    defer allocator.free(table_info);

    try insertIntoDm(
        &db,
        table_name,
        table_info,
        request_params.read_capacity_units orelse 0,
        request_params.write_capacity_units orelse 0,
        request_params.billing_mode_pay_per_request,
    );
    // Server side Input validation error on live DDB results in this for a 2 char table name
    // 400 - bad request
    // {"__type":"com.amazon.coral.validate#ValidationException","message":"TableName must be at least 3 characters long and at most 255 characters long"}
    // Tableinfo for Music collection example becomes:
    //
    // {
    //   "Attributes": [
    //     {
    //       "AttributeName": "Artist",
    //       "AttributeType": "S"
    //     },
    //     {
    //       "AttributeName": "SongTitle",
    //       "AttributeType": "S"
    //     }
    //   ],
    //   "GSIList": [],
    //   "GSIDescList": [],
    //   "SQLiteIndex": {
    //     "": [
    //       {
    //         "DynamoDBAttribute": {
    //           "AttributeName": "Artist",
    //           "AttributeType": "S"
    //         },
    //         "KeyType": "HASH",
    //         "SQLiteColumnName": "hashKey",
    //         "SQLiteDataType": "TEXT"
    //       },
    //       {
    //         "DynamoDBAttribute": {
    //           "AttributeName": "SongTitle",
    //           "AttributeType": "S"
    //         },
    //         "KeyType": "RANGE",
    //         "SQLiteColumnName": "rangeKey",
    //         "SQLiteDataType": "TEXT"
    //       }
    //     ]
    //   },
    //   "UniqueIndexes": [
    //     {
    //       "DynamoDBAttribute": {
    //         "AttributeName": "Artist",
    //         "AttributeType": "S"
    //       },
    //       "KeyType": "HASH",
    //       "SQLiteColumnName": "hashKey",
    //       "SQLiteDataType": "TEXT"
    //     },
    //     {
    //       "DynamoDBAttribute": {
    //         "AttributeName": "SongTitle",
    //         "AttributeType": "S"
    //       },
    //       "KeyType": "RANGE",
    //       "SQLiteColumnName": "rangeKey",
    //       "SQLiteDataType": "TEXT"
    //     }
    //   ],
    //   "UniqueGSIIndexes": []
    // }
    //
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
    , .{table_name});
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
        .{ table_name, table_name },
    );
    defer allocator.free(create_index_stmt);
    try db.execDynamic(create_index_stmt, .{}, .{});

    var al = std.ArrayList(u8).init(allocator);
    var response_writer = al.writer();
    try response_writer.print("table created for account {s}\n", .{account_id});
    return al.toOwnedSlice();
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
/// Gets the database for this account. If under test, a memory database is used
/// instead. Will initialize the database with appropriate metadata tables
fn dbForAccount(allocator: std.mem.Allocator, account_id: []const u8) !sqlite.Db {
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

fn parseRequest(
    request: *AuthenticatedRequest,
    parsed: std.json.Parsed(std.json.Value),
    writer: anytype,
) !Params {
    var param_iterator = parsed.value.object.iterator();
    var required: @typeInfo(RequiredFields).Enum.tag_type = 0;
    var request_params = Params{
        .table_name = undefined,
        .table_info = .{
            .attribute_definitions = undefined,
            .table_key = undefined,
        },
    };
    // This is a new table, so we will generate a random key for table data
    // In this way, key rotation can happen on the account without needing
    // re-encryption of the table data. Table info will be encrypted with the
    // account root key, and all data in 'dm' as well as table names will
    // need to be updated when that key is rotated.
    encryption.randomEncodedKey(&request_params.table_info.table_key);
    // Request:
    //
    //  "AttributeDefinitions": [
    //     {
    //       "AttributeName": "Artist",
    //       "AttributeType": "S"
    //     },
    //     {
    //       "AttributeName": "SongTitle",
    //       "AttributeType": "S"
    //     }
    //   ],
    //   "TableName": "dm",
    //   "KeySchema": [
    //     {
    //       "AttributeName": "Artist",
    //       "KeyType": "HASH"
    //     },
    //     {
    //       "AttributeName": "SongTitle",
    //       "KeyType": "RANGE"
    //     }
    //   ],
    //   "ProvisionedThroughput": {
    //     "ReadCapacityUnits": 5,
    //     "WriteCapacityUnits": 5
    //   },
    //   "Tags": [
    //     {
    //       "Key": "Owner",
    //       "Value": "blueTeam"
    //     }
    //   ]
    // }
    var attribute_definitions_assigned = false;
    errdefer {
        if (attribute_definitions_assigned) {
            for (request_params.table_info.attribute_definitions) |d| {
                request.allocator.free(d.*.name);
                request.allocator.destroy(d);
            }
            request.allocator.free(request_params.table_info.attribute_definitions);
        }
    }
    while (param_iterator.next()) |p| {
        const key = p.key_ptr.*;
        const val = p.value_ptr.*;
        if (std.mem.eql(u8, key, "TableName")) {
            if (val.string.len < 3 or val.string.len > 255) {
                try returnException(
                    request,
                    .bad_request,
                    error.ValidationException,
                    writer,
                    "TableName must be at least 3 characters long and at most 255 characters long",
                );
            }
            required |= @intFromEnum(RequiredFields.TableName);
            request_params.table_name = val.string;
            continue;
        }
        if (std.mem.eql(u8, key, "BillingMode")) {
            if (val != .string)
                try returnException(
                    request,
                    .bad_request,
                    error.ValidationException,
                    writer,
                    "KeySchema must be an array",
                );
            if (!std.mem.eql(u8, val.string, "PROVISIONED") and
                !std.mem.eql(u8, val.string, "PAY_PER_REQUEST"))
                try returnException(
                    request,
                    .bad_request,
                    error.ValidationException,
                    writer,
                    "BillingMode must be PROVISIONED or PAY_PER_REQUEST)",
                );
            if (std.mem.eql(u8, val.string, "PAY_PER_REQUEST"))
                request_params.billing_mode_pay_per_request = true;
        }
        if (std.mem.eql(u8, key, "KeySchema")) {
            required |= @intFromEnum(RequiredFields.KeySchema);
            if (val != .array)
                try returnException(
                    request,
                    .bad_request,
                    error.ValidationException,
                    writer,
                    "KeySchema must be an array",
                );
            if (val.array.items.len == 0)
                try returnException(
                    request,
                    .bad_request,
                    error.ValidationException,
                    writer,
                    "KeySchema array cannot be empty",
                );
            continue;
        }
        if (std.mem.eql(u8, key, "ProvisionedThroughput")) {
            if (val != .object) {
                try returnException(
                    request,
                    .bad_request,
                    error.ValidationException,
                    writer,
                    "ProvisionedThroughput must be an object",
                );
            }
            if (val.object.get("ReadCapacityUnits")) |v| {
                if (v != .integer or v.integer < 1) {
                    try returnException(
                        request,
                        .bad_request,
                        error.ValidationException,
                        writer,
                        "ReadCapacityUnits must be a positive number",
                    );
                }
                request_params.read_capacity_units = v.integer;
            }
            if (val.object.get("WriteCapacityUnits")) |v| {
                if (v != .integer or v.integer < 1) {
                    try returnException(
                        request,
                        .bad_request,
                        error.ValidationException,
                        writer,
                        "ReadCapacityUnits must be a positive number",
                    );
                }
                request_params.write_capacity_units = v.integer;
            }
            continue;
        }
        if (std.mem.eql(u8, key, "AttributeDefinitions")) {
            required |= @intFromEnum(RequiredFields.AttributeDefinitions);
            if (val != .array)
                try returnException(
                    request,
                    .bad_request,
                    error.ValidationException,
                    writer,
                    "AttributeDefinitions must be an array",
                );
            if (val.array.items.len == 0)
                try returnException(
                    request,
                    .bad_request,
                    error.ValidationException,
                    writer,
                    "AttributeDefinitions array cannot be empty",
                );
            request_params.table_info.attribute_definitions = try parseAttributeDefinitions(request, val.array.items, writer);
            attribute_definitions_assigned = true;
            continue;
        }
        if (std.mem.eql(u8, key, "Tags")) {
            continue;
        }
        if (std.mem.eql(u8, key, "LocalSecondaryIndexes")) {
            try writer.print("Parameter '{s}' not implemented", .{key});
            request.status = .not_implemented;
            return error.NotImplemented;
        }
        try writer.print("Unrecognized request parameter: {s}", .{key});
        request.status = .bad_request;
        return error.UnrecognizedRequestParameter;
    }
    if (required != std.math.maxInt(@typeInfo(RequiredFields).Enum.tag_type)) {
        // We are missing one or more required fields
        for (std.meta.tags(RequiredFields)) |t| {
            if (required & @intFromEnum(t) == 0) {
                try writer.print("Missing required request parameter: {s}", .{@tagName(t)});
                request.status = .bad_request;
                return error.MissingRequiredParameter;
            }
        }
    }
    if (!request_params.billing_mode_pay_per_request and
        (request_params.read_capacity_units == null or
        request_params.write_capacity_units == null))
        try returnException(
            request,
            .bad_request,
            error.ValidationException,
            writer,
            "ReadCapacityUnits and WriteCapacityUnits required when BillingMode = 'PAY_PER_REQUEST'",
        );
    return request_params;
}

fn parseAttributeDefinitions(request: *AuthenticatedRequest, definitions: []std.json.Value, writer: anytype) ![]*AttributeDefinition {
    const allocator = request.allocator;
    var rc = try allocator.alloc(*AttributeDefinition, definitions.len);
    errdefer allocator.free(rc);
    //  "AttributeDefinitions": [
    //     {
    //       "AttributeName": "Artist",
    //       "AttributeType": "S"
    //     },
    //     {
    //       "AttributeName": "SongTitle",
    //       "AttributeType": "S"
    //     }
    //   ],
    for (definitions, 0..) |d, i| {
        if (d != .object)
            try returnException(
                request,
                .bad_request,
                error.ValidationException,
                writer,
                "Attribute definitions array can only consist of objects with AttributeName and AttributeType strings",
            );
        const name = d.object.get("AttributeName");
        const attribute_type = d.object.get("AttributeType");
        if (name == null or name.? != .string or attribute_type == null or attribute_type.? != .string)
            try returnException(
                request,
                .bad_request,
                error.ValidationException,
                writer,
                "Attribute definitions array can only consist of objects with AttributeName and AttributeType strings",
            );
        const type_string = attribute_type.?.string;
        const type_enum = std.meta.stringToEnum(AttributeTypeDescriptor, type_string);
        if (type_enum == null)
            try returnException(
                request,
                .bad_request,
                error.ValidationException,
                writer,
                "Attribute type invalid",
            ); // TODO: This is kind of a lousy error message
        // TODO: This can leak memory if a later validation error occurs.
        // we are de-facto passed an arena here, but we shouldn't assume that
        var definition = try allocator.create(AttributeDefinition);
        definition.name = try allocator.dupe(u8, name.?.string);
        definition.type = type_enum.?;
        rc[i] = definition;
    }
    return rc;
}
fn returnException(
    request: *AuthenticatedRequest,
    status: std.http.Status,
    err: anyerror,
    writer: anytype,
    message: []const u8,
) !void {
    switch (request.output_format) {
        .json => try writer.print(
            \\{{"__type":"{s}","message":"{s}"}}
        ,
            .{ @errorName(err), message },
        ),

        .text => try writer.print(
            "{s}: {s}\n",
            .{ @errorName(err), message },
        ),
    }
    request.status = status;
    return err;
}
// Full request syntax:
//
// {
//    "AttributeDefinitions": [
//       {
//          "AttributeName": "string",
//          "AttributeType": "string"
//       }
//    ],
//    "BillingMode": "string",
//    "DeletionProtectionEnabled": boolean,
//    "GlobalSecondaryIndexes": [
//       {
//          "IndexName": "string",
//          "KeySchema": [
//             {
//                "AttributeName": "string",
//                "KeyType": "string"
//             }
//          ],
//          "Projection": {
//             "NonKeyAttributes": [ "string" ],
//             "ProjectionType": "string"
//          },
//          "ProvisionedThroughput": {
//             "ReadCapacityUnits": number,
//             "WriteCapacityUnits": number
//          }
//       }
//    ],
//    "KeySchema": [
//       {
//          "AttributeName": "string",
//          "KeyType": "string"
//       }
//    ],
//    "LocalSecondaryIndexes": [
//       {
//          "IndexName": "string",
//          "KeySchema": [
//             {
//                "AttributeName": "string",
//                "KeyType": "string"
//             }
//          ],
//          "Projection": {
//             "NonKeyAttributes": [ "string" ],
//             "ProjectionType": "string"
//          }
//       }
//    ],
//    "ProvisionedThroughput": {
//       "ReadCapacityUnits": number,
//       "WriteCapacityUnits": number
//    },
//    "SSESpecification": {
//       "Enabled": boolean,
//       "KMSMasterKeyId": "string",
//       "SSEType": "string"
//    },
//    "StreamSpecification": {
//       "StreamEnabled": boolean,
//       "StreamViewType": "string"
//    },
//    "TableClass": "string",
//    "TableName": "string",
//    "Tags": [
//       {
//          "Key": "string",
//          "Value": "string"
//       }
//    ]
// }
test "can create a table" {
    const allocator = std.testing.allocator;
    var request = AuthenticatedRequest{
        .allocator = allocator,
        .event_data =
        \\ {
        \\ "AttributeDefinitions":
        \\    [
        \\     {"AttributeName": "Artist", "AttributeType": "S"},
        \\     {"AttributeName": "SongTitle", "AttributeType": "S"}
        \\    ],
        \\ "TableName": "MusicCollection",
        \\ "KeySchema": [
        \\      {"AttributeName": "Artist", "KeyType": "HASH"},
        \\      {"AttributeName": "SongTitle", "KeyType": "RANGE"}
        \\ ],
        \\ "ProvisionedThroughput":
        \\   {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        \\ "Tags": [{"Key": "Owner", "Value": "blueTeam"}]
        \\ }
        ,
        .account_id = "1234",
        .status = .ok,
        .reason = null,
        .headers = std.http.Headers.init(allocator),
        .output_format = .text,
    };
    const output = try handler(&request, std.io.null_writer);
    defer allocator.free(output);
    // TODO: test output
}
test "will fail an unrecognized request parameter" {
    const allocator = std.testing.allocator;
    var request = AuthenticatedRequest{
        .allocator = allocator,
        .event_data =
        \\ {
        \\ "Unrecognized":
        \\    [
        \\     {"AttributeName": "Artist", "AttributeType": "S"},
        \\     {"AttributeName": "SongTitle", "AttributeType": "S"}
        \\    ],
        \\ "TableName": "MusicCollection",
        \\ "KeySchema": [
        \\      {"AttributeName": "Artist", "KeyType": "HASH"},
        \\      {"AttributeName": "SongTitle", "KeyType": "RANGE"}
        \\ ],
        \\ "ProvisionedThroughput":
        \\   {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        \\ "Tags": [{"Key": "Owner", "Value": "blueTeam"}]
        \\ }
        ,
        .account_id = "1234",
        .status = .ok,
        .reason = null,
        .headers = std.http.Headers.init(allocator),
        .output_format = .text,
    };
    var al = std.ArrayList(u8).init(allocator);
    defer al.deinit();
    try std.testing.expectError(error.UnrecognizedRequestParameter, handler(&request, al.writer()));
    try std.testing.expectEqual(std.http.Status.bad_request, request.status);
    try std.testing.expectEqualStrings("Unrecognized request parameter: Unrecognized", al.items);
}
test "will fail on short table names (json)" {
    try failOnShortTableNames(.json);
}
test "will fail on short table names (text)" {
    try failOnShortTableNames(.text);
}
fn failOnShortTableNames(format: AuthenticatedRequest.OutputFormat) !void {
    const allocator = std.testing.allocator;
    var request = AuthenticatedRequest{
        .allocator = allocator,
        .event_data =
        \\ {
        \\ "AttributeDefinitions":
        \\    [
        \\     {"AttributeName": "Artist", "AttributeType": "S"},
        \\     {"AttributeName": "SongTitle", "AttributeType": "S"}
        \\    ],
        \\ "TableName": "dm",
        \\ "KeySchema": [
        \\      {"AttributeName": "Artist", "KeyType": "HASH"},
        \\      {"AttributeName": "SongTitle", "KeyType": "RANGE"}
        \\ ],
        \\ "ProvisionedThroughput":
        \\   {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        \\ "Tags": [{"Key": "Owner", "Value": "blueTeam"}]
        \\ }
        ,
        .account_id = "1234",
        .status = .ok,
        .reason = null,
        .headers = std.http.Headers.init(allocator),
        .output_format = format,
    };
    var al = std.ArrayList(u8).init(allocator);
    defer al.deinit();
    try std.testing.expectError(error.ValidationException, handler(&request, al.writer()));
    try std.testing.expectEqual(std.http.Status.bad_request, request.status);
    switch (format) {
        .json => try std.testing.expectEqualStrings(
        // This is the actual message. Also, what should we do about content type here?
        // and what about running from console? and...and...
        //\\{"__type":"com.amazon.coral.validate#ValidationException","message":"TableName must be at least 3 characters long and at most 255 characters long"}
            \\{"__type":"ValidationException","message":"TableName must be at least 3 characters long and at most 255 characters long"}
        , al.items),
        .text => try std.testing.expectEqualStrings(
        // This is the actual message. Also, what should we do about content type here?
        // and what about running from console? and...and...
        //\\{"__type":"com.amazon.coral.validate#ValidationException","message":"TableName must be at least 3 characters long and at most 255 characters long"}
        "ValidationException: TableName must be at least 3 characters long and at most 255 characters long\n", al.items),
    }
}
