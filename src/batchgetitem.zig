const std = @import("std");
const AuthenticatedRequest = @import("AuthenticatedRequest.zig");
const Account = @import("Account.zig");
const encryption = @import("encryption.zig");
const ddb = @import("ddb.zig");
const returnException = @import("main.zig").returnException;

pub fn handler(request: *AuthenticatedRequest, writer: anytype) ![]const u8 {
    const allocator = request.allocator;
    const account_id = request.account_id;

    var params = try Params.parseRequest(allocator, request, writer);
    defer params.deinit();
    if (params.return_item_collection_metrics) return error.NotImplemented;
    // for (params.request_items)
    var response_writer_al = std.ArrayList(u8).init(allocator);
    defer response_writer_al.deinit();
    var response_writer = response_writer_al.writer();
    try response_writer.writeAll(
        \\{
        \\    "Responses": {
    );
    var more = false;
    var account_tables = try ddb.tablesForAccount(allocator, account_id);
    defer account_tables.deinit();
    for (params.request_items) |r| {
        var request_table: ddb.Table = undefined;
        var found = false;
        for (account_tables.items) |tbl| {
            if (std.mem.eql(u8, tbl.name, r.table_name)) {
                request_table = tbl;
                found = true;
            }
        }
        if (!found) {
            std.log.warn("Table name in request does not exist in account. Table name specified: {s}", .{r.table_name});
            continue; // TODO: This API has the concept of returning the list of unprocessed stuff. We need to do that here
        }
        const all_attributes = r.projection_expression == null;
        var projection_attributes = std.StringHashMap(void).init(allocator);
        defer projection_attributes.deinit();
        if (!all_attributes) {
            var iter = std.mem.splitScalar(u8, r.projection_expression.?, ',');
            while (iter.next()) |e| {
                try projection_attributes.put(std.mem.trim(u8, e, " "), {});
            }
        }
        if (more) try response_writer.writeByte(',');
        try response_writer.print(
            \\
            \\        "{s}": [
        , .{r.table_name});
        var more_tbl = false;
        for (r.keys) |key| {
            const hash_value = try std.json.stringifyAlloc(allocator, key.hash_key.value, .{});
            defer allocator.free(hash_value);
            const range_value = if (key.range_key) |rk|
                try std.json.stringifyAlloc(allocator, rk.value, .{})
            else
                null;
            defer if (range_value) |rv| allocator.free(rv);
            const rows = try request_table.getItem(hash_value, range_value);
            defer allocator.free(rows);
            if (rows.len > 0 and more_tbl) try response_writer.writeByte(',');
            more_tbl = true;
            for (rows) |row| {
                defer allocator.free(row);
                // Our row is a stringified array of ddb.Attribute objects
                const attributes = try std.json.parseFromSlice([]ddb.Attribute, allocator, row, .{});
                defer attributes.deinit();
                try response_writer.writeAll(
                    \\
                    \\            {
                    \\                "
                );
                var more_attr = false;
                for (attributes.value) |attr| {
                    if (all_attributes or projection_attributes.contains(attr.name)) {
                        if (more_attr) try response_writer.writeAll(",\n                \"");
                        more_attr = true;
                        try response_writer.writeAll(attr.name);
                        try response_writer.writeAll("\": ");
                        const attribute_str = try std.json.stringifyAlloc(allocator, attr.value, .{ .whitespace = .indent_2 });
                        defer allocator.free(attribute_str);
                        var line_iter = std.mem.splitScalar(u8, attribute_str, '\n');
                        var first = true;
                        var next = line_iter.next();
                        while (next) |line| {
                            next = line_iter.next();
                            if (!first) {
                                if (next) |_| {
                                    try response_writer.writeAll("                  ");
                                } else {
                                    try response_writer.writeAll("                ");
                                }
                            }

                            first = false;
                            try response_writer.writeAll(line);
                            if (next) |_| try response_writer.writeByte('\n');
                        }
                    }
                }
                try response_writer.writeAll(
                    \\
                    \\            }
                );
            }
        }

        try response_writer.writeAll(
            \\
            \\        ]
        );
        more = true;
    }

    try response_writer.writeAll(
        \\
        \\    },
        \\    "UnprocessedKeys": {
        \\    }
        \\}
    );
    return try response_writer_al.toOwnedSlice();
}
const Key = struct {
    hash_key: ddb.Attribute,
    range_key: ?ddb.Attribute = null,

    pub fn jsonParseFromValue(allocator: std.mem.Allocator, source: std.json.Value, options: std.json.ParseOptions) !Key {
        if (source != .object) return error.UnexpectedToken;
        const count = source.object.count();
        if (count != 1 and count != 2) return error.LengthMismatch;
        var iterator = source.object.iterator();
        const hash = iterator.next().?;
        const range = iterator.next();
        return .{
            .hash_key = .{
                .name = hash.key_ptr.*,
                .value = try std.json.innerParseFromValue(ddb.AttributeValue, allocator, hash.value_ptr.*, options),
            },
            .range_key = if (range) |r| .{
                .name = r.key_ptr.*,
                .value = try std.json.innerParseFromValue(ddb.AttributeValue, allocator, r.value_ptr.*, options),
            } else null,
        };
    }
};
const RequestItem = struct {
    table_name: []const u8,
    consistent_read: bool = false,
    expression_attribute_names: ?std.StringHashMap([]const u8) = null,
    keys: []Key,
    projection_expression: ?[]const u8 = null,

    pub fn validate(self: RequestItem) !void {
        for (self.keys) |item|
            try item.validate();
    }
};
const Params = struct {
    request_items: []RequestItem,
    return_consumed_capacity: ddb.ReturnConsumedCapacity = .none,
    return_item_collection_metrics: bool = false,
    arena: *std.heap.ArenaAllocator,

    pub fn deinit(self: *Params) void {
        const allocator = self.arena.child_allocator;
        self.arena.deinit();
        allocator.destroy(self.arena);
    }
    pub fn validate(self: Params) !void {
        for (self.request_items) |item|
            try item.validate();
    }
    pub fn parseRequest(allocator: std.mem.Allocator, request: *AuthenticatedRequest, writer: anytype) !Params {
        // This pattern borrowed from https://ziglang.org/documentation/0.11.0/std/src/std/json/static.zig.html
        var rc = Params{
            .arena = try allocator.create(std.heap.ArenaAllocator),
            .request_items = undefined,
        };
        errdefer allocator.destroy(rc.arena);
        // I think the idea here is that we've created the allocator above, and this
        // line here rewrites the values (internal state) at the original pointer address
        rc.arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer rc.arena.deinit();
        var aa = rc.arena.allocator();

        var parsed = try std.json.parseFromSliceLeaky(std.json.Value, aa, request.event_data, .{});

        // RequestItems is most important, and is required. Check it first
        const ri = parsed.object.get("RequestItems");
        if (ri == null or ri.? != .object or ri.?.object.count() == 0)
            try returnException(
                request,
                .bad_request,
                error.ValidationException,
                writer,
                "Request missing RequestItems",
            );
        if (parsed.object.get("ReturnConsumedCapacity")) |rcc| {
            if (rcc != .string or
                (!std.mem.eql(u8, rcc.string, "INDEXES") and
                !std.mem.eql(u8, rcc.string, "TOTAL") and
                !std.mem.eql(u8, rcc.string, "NONE")))
                try returnException(
                    request,
                    .bad_request,
                    error.ValidationException,
                    writer,
                    "ReturnConsumedCapacity value invalid. Valid values are INDEXES | TOTAL | NONE",
                );
            const val = try std.ascii.allocLowerString(aa, rcc.string);
            rc.return_consumed_capacity = std.meta.stringToEnum(ddb.ReturnConsumedCapacity, val).?;
        }
        const request_items = ri.?.object.count();
        // Good so far...let's allocate the request item array and process
        var request_items_al = try std.ArrayList(RequestItem).initCapacity(aa, request_items);
        defer request_items_al.deinit();
        var inx: usize = 0;
        var param_iterator = ri.?.object.iterator();
        while (param_iterator.next()) |p| : (inx += 1) {
            const key = p.key_ptr.*;
            const val = p.value_ptr.*;
            if (val != .object)
                try returnException(
                    request,
                    .bad_request,
                    error.ValidationException,
                    writer,
                    "RequestItems object value must be request object",
                );

            var request_item = request_items_al.addOneAssumeCapacity();
            errdefer aa.destroy(request_item);
            const keys = val.object.get("Keys");
            if (keys == null)
                try returnException(
                    request,
                    .bad_request,
                    error.ValidationException,
                    writer,
                    "Request item table missing Keys as part of request",
                );
            if (keys.? != .array or keys.?.array.items.len == 0)
                try returnException(
                    request,
                    .bad_request,
                    error.ValidationException,
                    writer,
                    "Request item table Keys must be an non zero-length array",
                );

            // This arena doesn't deinit until after Params is done, so
            // we should be good to *NOT* duplicate these
            request_item.table_name = key; // try aa.dupe(key);
            var parsed_attributes = try std.json.parseFromValue([]Key, aa, keys.?, .{});
            defer parsed_attributes.deinit(); // TODO: do we want this?

            var keys_al = try std.ArrayList(Key).initCapacity(aa, keys.?.array.items.len);
            defer keys_al.deinit();

            keys_al.appendSliceAssumeCapacity(parsed_attributes.value);
            request_item.keys = try keys_al.toOwnedSlice();
            // Optional stuff. ConsistentRead, ExpressionAttributeNames, ProjectionExpression
            if (val.object.get("ConsistentRead")) |v| {
                if (v != .bool)
                    try returnException(
                        request,
                        .bad_request,
                        error.ValidationException,
                        writer,
                        "ConsistentRead must be a boolean",
                    );
                request_item.consistent_read = v.bool;
            }
            if (val.object.get("ProjectionExpression")) |v| {
                if (v != .string)
                    try returnException(
                        request,
                        .bad_request,
                        error.ValidationException,
                        writer,
                        "ProjectionExpression must be a string",
                    );
                request_item.projection_expression = v.string;
            }
            if (val.object.get("ExpressionAttributeNames")) |v| {
                if (v != .object)
                    try returnException(
                        request,
                        .bad_request,
                        error.ValidationException,
                        writer,
                        "ExpressionAttributeNames must be an object",
                    );
                var count = v.object.count();
                var names = v.object.iterator();
                var hashmap = std.StringHashMap([]const u8).init(aa);
                try hashmap.ensureTotalCapacity(@as(u32, @intCast(count)));
                errdefer hashmap.deinit();
                while (names.next()) |n|
                    hashmap.putAssumeCapacity(n.key_ptr.*, n.value_ptr.*.string);
                request_item.expression_attribute_names = hashmap;
            }
        }

        rc.request_items = try request_items_al.toOwnedSlice();
        return rc;
    }
};
// Response: {
//   "ConsumedCapacity": [
//      {
//         "CapacityUnits": number,
//         "GlobalSecondaryIndexes": {
//            "string" : {
//               "CapacityUnits": number,
//               "ReadCapacityUnits": number,
//               "WriteCapacityUnits": number
//            }
//         },
//         "LocalSecondaryIndexes": {
//            "string" : {
//               "CapacityUnits": number,
//               "ReadCapacityUnits": number,
//               "WriteCapacityUnits": number
//            }
//         },
//         "ReadCapacityUnits": number,
//         "Table": {
//            "CapacityUnits": number,
//            "ReadCapacityUnits": number,
//            "WriteCapacityUnits": number
//         },
//         "TableName": "string",
//         "WriteCapacityUnits": number
//      }
//   ],
//   "Responses": {
//      "string" : [
//         {
//            "string" : {
//               "B": blob,
//               "BOOL": boolean,
//               "BS": [ blob ],
//               "L": [
//                  "AttributeValue"
//               ],
//               "M": {
//                  "string" : "AttributeValue"
//               },
//               "N": "string",
//               "NS": [ "string" ],
//               "NULL": boolean,
//               "S": "string",
//               "SS": [ "string" ]
//            }
//         }
//      ]
//   },
//   "UnprocessedKeys": {
//      "string" : {
//         "AttributesToGet": [ "string" ],
//         "ConsistentRead": boolean,
//         "ExpressionAttributeNames": {
//            "string" : "string"
//         },
//         "Keys": [
//            {
//               "string" : {
//                  "B": blob,
//                  "BOOL": boolean,
//                  "BS": [ blob ],
//                  "L": [
//                     "AttributeValue"
//                  ],
//                  "M": {
//                     "string" : "AttributeValue"
//                  },
//                  "N": "string",
//                  "NS": [ "string" ],
//                  "NULL": boolean,
//                  "S": "string",
//                  "SS": [ "string" ]
//               }
//            }
//         ],
//         "ProjectionExpression": "string"
//      }
//   }
//}

test "basic request parsing" {
    const allocator = std.testing.allocator;
    var request = AuthenticatedRequest{
        .output_format = .text,
        .event_data =
        \\{
        \\    "RequestItems": {
        \\        "Forum": {
        \\            "Keys": [
        \\                {
        \\                    "Name":{"S":"Amazon DynamoDB"}
        \\                },
        \\                {
        \\                    "Name":{"S":"Amazon RDS"}
        \\                },
        \\                {
        \\                    "Name":{"S":"Amazon Redshift"}
        \\                }
        \\            ],
        \\            "ProjectionExpression":"Name, Threads, Messages, Views"
        \\        },
        \\        "Thread": {
        \\            "Keys": [
        \\                {
        \\                    "ForumName":{"S":"Amazon DynamoDB"},
        \\                    "Subject":{"S":"Concurrent reads"}
        \\                }
        \\            ],
        \\            "ProjectionExpression":"Tags, Message"
        \\        }
        \\    },
        \\    "ReturnConsumedCapacity": "TOTAL"
        \\}
        ,
        .headers = undefined,
        .status = .ok,
        .reason = "",
        .account_id = 1234,
        .allocator = allocator,
    };
    var al = std.ArrayList(u8).init(allocator);
    defer al.deinit();
    var writer = al.writer();
    var parms = try Params.parseRequest(allocator, &request, writer);
    defer parms.deinit();
    try std.testing.expect(parms.return_consumed_capacity == .total);
    try std.testing.expectEqual(@as(usize, 2), parms.request_items.len);
    const forum = parms.request_items[0];
    try std.testing.expectEqualStrings("Forum", forum.table_name);
    try std.testing.expect(forum.keys.len == 3);
    const thread = parms.request_items[1];
    try std.testing.expectEqualStrings("Thread", thread.table_name);
    try std.testing.expect(thread.keys.len == 1);
    const key = thread.keys[0];
    try std.testing.expectEqualStrings("ForumName", key.hash_key.name);
    try std.testing.expect(key.hash_key.value == .string);
    try std.testing.expectEqualStrings("Amazon DynamoDB", key.hash_key.value.string);
    try std.testing.expect(key.range_key != null);
    const range = key.range_key.?;
    try std.testing.expectEqualStrings("Subject", range.name);
    try std.testing.expect(range.value == .string);
    try std.testing.expectEqualStrings("Concurrent reads", range.value.string);
    try std.testing.expectEqualStrings("Name, Threads, Messages, Views", forum.projection_expression.?);
}

test "read item" {
    // This is all in memory, so we need a table set up and populated to read
    Account.test_retain_db = true;
    defer Account.test_retain_db = false;
    const allocator = std.testing.allocator;
    const account_id = 1234;
    var db = try Account.dbForAccount(allocator, account_id);
    defer allocator.destroy(db);
    defer Account.testDbDeinit();

    { // Create DB
        const account = try Account.accountForId(allocator, account_id); // This will get us the encryption key needed
        defer account.deinit();
        var hash = ddb.AttributeDefinition{ .name = "Artist", .type = .S };
        var range = ddb.AttributeDefinition{ .name = "SongTitle", .type = .S };
        var definitions = @constCast(&[_]*ddb.AttributeDefinition{
            &hash,
            &range,
        });
        var table_info: ddb.TableInfo = .{
            .table_key = undefined,
            .attribute_definitions = definitions[0..],
            .hash_key_attribute_name = "Artist",
            .range_key_attribute_name = "SongTitle",
        };
        encryption.randomEncodedKey(&table_info.table_key);
        try ddb.createDdbTable(
            allocator,
            db,
            account,
            "MusicCollection",
            table_info,
            5,
            5,
            false,
        );
    }
    { // Populate table
        var request = AuthenticatedRequest{
            .output_format = .text,
            .event_data =
            \\ {
            \\    "RequestItems": {
            \\        "MusicCollection": [
            \\            {
            \\                "PutRequest": {
            \\                    "Item": {
            \\                        "Artist": {
            \\                            "S": "Mettalica"
            \\                        },
            \\                        "SongTitle": {
            \\                            "S": "Master of Puppets"
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
            \\                }
            \\            },
            \\            {
            \\                "PutRequest": {
            \\                    "Item": {
            \\                        "Artist": {
            \\                            "S": "System of a Down"
            \\                        },
            \\                        "SongTitle": {
            \\                            "S": "Chop Suey!"
            \\                        },
            \\                        "Foo": { "S": "Bar" }
            \\                    }
            \\                }
            \\            }
            \\        ]
            \\ }
            \\ }
            ,
            .headers = undefined,
            .status = .ok,
            .reason = "",
            .account_id = 1234,
            .allocator = allocator,
        };
        var al = std.ArrayList(u8).init(allocator);
        defer al.deinit();
        var writer = al.writer();
        _ = try @import("batchwriteitem.zig").handler(&request, writer);
    }

    { // Read from table
        var request = AuthenticatedRequest{
            .output_format = .text,
            .headers = undefined,
            .status = .ok,
            .reason = "",
            .account_id = 1234,
            .allocator = allocator,
            .event_data =
            \\{
            \\    "RequestItems": {
            \\        "MusicCollection": {
            \\            "Keys": [
            \\                {
            \\                  "Artist": { "S": "Mettalica" },
            \\                  "SongTitle": { "S": "Master of Puppets" }
            \\                },
            \\                {
            \\                  "Artist": { "S": "System of a Down" },
            \\                  "SongTitle": { "S": "Chop Suey!" }
            \\                }
            \\            ],
            \\            "ProjectionExpression":"Binary, Boolean, List, Foo"
            \\        }
            \\    }
            \\}
            ,
        };
        var al = std.ArrayList(u8).init(allocator);
        defer al.deinit();
        var writer = al.writer();
        const output = try handler(&request, writer);
        defer allocator.free(output);
        // TODO: Fix this
        try std.testing.expectEqualStrings(
            \\{
            \\    "Responses": {
            \\        "MusicCollection": [
            \\            {
            \\                "Binary": {
            \\                    "B": "dGhpcyB0ZXh0IGlzIGJhc2U2NC1lbmNvZGVk"
            \\                },
            \\                "Boolean": {
            \\                    "BOOL": true
            \\                },
            \\                "List": {
            \\                    "L": [
            \\                      {
            \\                        "S": "Cookies"
            \\                      },
            \\                      {
            \\                        "S": "Coffee"
            \\                      },
            \\                      {
            \\                        "N": "3.14159"
            \\                      }
            \\                    ]
            \\                }
            \\            },
            \\            {
            \\                "Foo": {
            \\                    "S": "Bar"
            \\                }
            \\            }
            \\        ]
            \\    },
            \\    "UnprocessedKeys": {
            \\    }
            \\}
        , output);
    }
}
