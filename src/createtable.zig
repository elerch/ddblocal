const std = @import("std");
const AuthenticatedRequest = @import("AuthenticatedRequest.zig");
const Account = @import("Account.zig");
const encryption = @import("encryption.zig");
const returnException = @import("main.zig").returnException;
const ddb = @import("ddb.zig");

// These are in the original casing so as to make the error messages nice
const RequiredFields = enum(u3) {
    // zig fmt: off
    TableName            = 1 << 0,
    AttributeDefinitions = 1 << 1,
    KeySchema            = 1 << 2,
    // zig fmt: on
};

const Params = struct {
    table_name: []const u8,
    table_info: ddb.TableInfo,
    read_capacity_units: ?i64 = null,
    write_capacity_units: ?i64 = null,
    billing_mode_pay_per_request: bool = false,
};
pub fn handler(request: *AuthenticatedRequest, writer: anytype) ![]const u8 {
    const allocator = request.allocator;
    const account_id = request.account_id;

    // NOTE: Please do not use this as an example. Check out batchwriteitem for
    // much better code, which was developed later. Most of the work in the
    // handler here is to parse and validate the incoming JSON data. From
    // there, the interface to the underlying data storage is handled by
    // ddb.zig
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
    // Parsing does most validation for us, but we also need to make sure that
    // the attributes specified in the key schema actually exist
    var found_keys: u2 = if (request_params.table_info.range_key_attribute_name == null) 0b01 else 0b00;
    for (request_params.table_info.attribute_definitions) |def| {
        if (std.mem.eql(u8, def.name, request_params.table_info.hash_key_attribute_name)) {
            found_keys |= 0b10;
            continue;
        }
        if (request_params.table_info.range_key_attribute_name) |n| {
            if (std.mem.eql(u8, def.name, n))
                found_keys |= 0b01;
        }
    }
    if (found_keys != 0b11)
        try returnException(
            request,
            .bad_request,
            error.ValidationException,
            writer,
            "Attribute names in KeySchema must also exist in AttributeDefinitions",
        );
    var db = try Account.dbForAccount(allocator, account_id);
    defer allocator.destroy(db);
    defer db.deinit();
    const account = try Account.accountForId(allocator, account_id); // This will get us the encryption key needed
    defer account.deinit();

    try ddb.createDdbTable(
        allocator,
        db,
        account,
        request_params.table_name,
        request_params.table_info,
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

    var al = std.ArrayList(u8).init(allocator);
    var response_writer = al.writer();
    try response_writer.print("table created for account {d:0>12}\n", .{account_id});
    return al.toOwnedSlice();
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
            .hash_key_attribute_name = undefined,
            .range_key_attribute_name = null,
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
                request.allocator.free(d.name);
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
            if (val.array.items.len < 1 or val.array.items.len > 2)
                try returnException(
                    request,
                    .bad_request,
                    error.ValidationException,
                    writer,
                    "KeySchema array must consist of only 1 or 2 elements",
                );
            var found_hash = false;
            for (val.array.items) |item| {
                //     {
                //       "AttributeName": "Artist",
                //       "KeyType": "HASH"
                //     },
                if (item != .object)
                    try returnException(
                        request,
                        .bad_request,
                        error.ValidationException,
                        writer,
                        "KeySchemaElement must be an object",
                    );
                const attribute_name = item.object.get("AttributeName");
                const key_type = item.object.get("KeyType");
                if (attribute_name == null or key_type == null or attribute_name.? != .string or key_type.? != .string)
                    try returnException(
                        request,
                        .bad_request,
                        error.ValidationException,
                        writer,
                        "KeySchemaElement must contain AttributeName and KeyType strings",
                    );
                if (!std.mem.eql(u8, key_type.?.string, "HASH") and !std.mem.eql(u8, key_type.?.string, "RANGE"))
                    try returnException(
                        request,
                        .bad_request,
                        error.ValidationException,
                        writer,
                        "Invalid KeyType. Valid values are HASH | RANGE",
                    );
                const is_hash = std.mem.eql(u8, key_type.?.string, "HASH");
                found_hash = found_hash or is_hash;
                if (is_hash)
                    request_params.table_info.hash_key_attribute_name = attribute_name.?.string
                else
                    request_params.table_info.range_key_attribute_name = attribute_name.?.string;
            }
            if (!found_hash)
                try returnException(
                    request,
                    .bad_request,
                    error.ValidationException,
                    writer,
                    "KeySchema missing hash key",
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

fn parseAttributeDefinitions(request: *AuthenticatedRequest, definitions: []std.json.Value, writer: anytype) ![]*ddb.AttributeDefinition {
    const allocator = request.allocator;
    var rc = try allocator.alloc(*ddb.AttributeDefinition, definitions.len);
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
        const type_enum = std.meta.stringToEnum(ddb.AttributeTypeDescriptor, type_string);
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
        var definition = try allocator.create(ddb.AttributeDefinition);
        definition.name = try allocator.dupe(u8, name.?.string);
        definition.type = type_enum.?;
        rc[i] = definition;
    }
    return rc;
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
        .account_id = 1234,
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
        .account_id = 1234,
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
        .account_id = 1234,
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
