const std = @import("std");
const sqlite = @import("sqlite");
const AuthenticatedRequest = @import("AuthenticatedRequest.zig");
const Account = @import("Account.zig");
const encryption = @import("encryption.zig");
const ddb = @import("ddb.zig");
const returnException = @import("main.zig").returnException;

const Request = struct {
    put_request: ?[]ddb.Attribute,
    delete_request: ?[]ddb.Attribute,
};
const RequestItem = struct {
    table_name: []const u8,
    requests: []Request,
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
        for (self.request_items) |item| {
            for (item.requests) |request| {
                if (request.put_request) |put| {
                    for (put) |attribute| try attribute.value.validate();
                }
                if (request.delete_request) |del| {
                    for (del) |attribute| try attribute.value.validate();
                }
            }
        }
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
        const request_items = ri.?.object.count();
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
        if (parsed.object.get("ReturnItemCollectionMetrics")) |rcm| {
            if (rcm != .string or
                (!std.mem.eql(u8, rcm.string, "SIZE") and
                !std.mem.eql(u8, rcm.string, "NONE")))
                try returnException(
                    request,
                    .bad_request,
                    error.ValidationException,
                    writer,
                    "ReturnCollectionMetrics value invalid. Valid values are SIZE | NONE",
                );
            rc.return_item_collection_metrics = std.mem.eql(u8, rcm.string, "SIZE");
        }
        // Good so far...let's allocate the request item array and process
        rc.request_items = try aa.alloc(RequestItem, request_items);
        var inx: usize = 0;
        var param_iterator = ri.?.object.iterator();
        while (param_iterator.next()) |p| : (inx += 1) {
            const key = p.key_ptr.*;
            const val = p.value_ptr.*;
            if (val != .array or val.array.items.len == 0)
                try returnException(
                    request,
                    .bad_request,
                    error.ValidationException,
                    writer,
                    "RequestItems object values must be non-zero length arrays",
                );

            var request_item = try aa.create(RequestItem);
            // This arena doesn't deinit until after Params is done, so
            // we should be good to *NOT* duplicate these
            request_item.table_name = key; // try aa.dupe(key);
            request_item.requests = try aa.alloc(Request, val.array.items.len);
            rc.request_items[inx] = request_item.*;
            for (val.array.items, 0..) |req, jnx| {
                if (req != .object)
                    try returnException(
                        request,
                        .bad_request,
                        error.ValidationException,
                        writer,
                        "Non-object found in RequestItems array",
                    );
                const request_key_count = req.object.count();
                if (request_key_count == 0)
                    try returnException(
                        request,
                        .bad_request,
                        error.ValidationException,
                        writer,
                        "Found unsupported request in RequestItems. Request has no PutRequest or DeleteRequest",
                    );
                if (request_key_count > 2)
                    try returnException(
                        request,
                        .bad_request,
                        error.ValidationException,
                        writer,
                        "Found unsupported request in RequestItems. Too many keys",
                    );

                var table_request = try aa.create(Request);
                table_request.put_request = null;
                table_request.delete_request = null;
                var req_item_iterator = req.object.iterator();
                while (req_item_iterator.next()) |put_or_delete| {
                    if (!std.mem.eql(u8, put_or_delete.key_ptr.*, "DeleteRequest") and
                        !std.mem.eql(u8, put_or_delete.key_ptr.*, "PutRequest"))
                        try returnException(
                            request,
                            .bad_request,
                            error.ValidationException,
                            writer,
                            "Found unsupported request in RequestItems. Valid requests are PutRequest and DeleteRequest",
                        );
                    if (put_or_delete.value_ptr.* != .object)
                        try returnException(
                            request,
                            .bad_request,
                            error.ValidationException,
                            writer,
                            "Request in RequestItems found with non-object value",
                        );
                    // We have a put or a delete with an object value. ok to proceed
                    const is_put = std.mem.eql(u8, put_or_delete.key_ptr.*, "PutRequest");
                    const pod_val = put_or_delete.value_ptr.*;
                    if (is_put) {
                        const put_val = pod_val.object.get("Item");
                        if (put_val == null or put_val.? != .object)
                            try returnException(
                                request,
                                .bad_request,
                                error.ValidationException,
                                writer,
                                "PutRequest in RequestItems found without Item object",
                            );
                        // Parse item object and assign to array
                        table_request.put_request = try ddb.Attribute.parseAttributes(aa, put_val.?.object, request, writer);
                    } else {
                        const del_val = pod_val.object.get("Keys");
                        if (del_val == null or del_val.? != .object)
                            try returnException(
                                request,
                                .bad_request,
                                error.ValidationException,
                                writer,
                                "DeleteRequest in RequestItems found without Key object",
                            );
                        // Parse key object and assign to array
                        table_request.delete_request = try ddb.Attribute.parseAttributes(aa, del_val.?.object, request, writer);
                    }
                }
                rc.request_items[inx].requests[jnx] = table_request.*;
            }
        }
        return rc;
        // {
        //    "RequestItems": {
        //       "string" : [
        //          {
        //             "DeleteRequest": {
        //                "Key": {
        //                   "string" : {...attribute value...}
        //                }
        //             },
        //             "PutRequest": {
        //                "Item": {
        //                   "string" : {...attribute value...}
        //                }
        //             }
        //          }
        //       ]
        //    },
        //    "ReturnConsumedCapacity": "string",
        //    "ReturnItemCollectionMetrics": "string"
        // }
    }
};

pub fn handler(request: *AuthenticatedRequest, writer: anytype) ![]const u8 {
    const allocator = request.allocator;
    const account_id = request.account_id;

    var params = try Params.parseRequest(allocator, request, writer);
    defer params.deinit();
    try params.validate();

    // 1. Get the list of encrypted table names using the account id root key
    var account_tables = try ddb.tablesForAccount(allocator, account_id);
    defer account_tables.deinit();
    // 2. For each table request:
    for (params.request_items) |table_req| {
        var request_table: ddb.Table = undefined;
        var found = false;
        for (account_tables.items) |tbl| {
            if (std.mem.eql(u8, tbl.name, table_req.table_name)) {
                request_table = tbl;
                found = true;
            }
        }
        if (!found) {
            std.log.warn("Table name in request does not exist in account. Table name specified: {s}", .{table_req.table_name});
            continue; // TODO: This API has the concept of returning the list of unprocessed stuff. We need to do that here
        }
        for (table_req.requests) |req| {
            if (req.put_request) |p|
                try process_request(allocator, account_tables.db, &request_table, .put, p);
            if (req.delete_request) |d|
                try process_request(allocator, account_tables.db, &request_table, .delete, d);
        }
    }
    // TODO: Capacity limiting and metrics
    if (params.return_consumed_capacity != .none or params.return_item_collection_metrics)
        try returnException(
            request,
            .internal_server_error,
            error.NotImplemented,
            writer,
            "Changes processed, but metrics/capacity are not yet implemented",
        );
    // {
    //     "UnprocessedItems": {
    //         "Forum": [
    //             {
    //                 "PutRequest": {
    //                     "Item": {
    //                         "Name": {
    //                             "S": "Amazon ElastiCache"
    //                         },
    //                         "Category": {
    //                             "S": "Amazon Web Services"
    //                         }
    //                     }
    //                 }
    //             }
    //         ]
    //     },
    //     "ConsumedCapacity": [
    //         {
    //             "TableName": "Forum",
    //             "CapacityUnits": 3
    //         }
    //     ]
    // }
    return "{}";
}
const RequestType = enum {
    put,
    delete,
};
fn process_request(
    allocator: std.mem.Allocator,
    db: anytype,
    table: *ddb.Table,
    req_type: RequestType,
    req_attributes: []ddb.Attribute,
) !void {
    _ = db;
    // 1. Find the hash values of put and delete requests in the request
    const hash_key_attribute_name = table.info.value.hash_key_attribute_name;
    const range_key_attribute_name = table.info.value.range_key_attribute_name;
    var hash_attribute: ?ddb.Attribute = null;
    var range_attribute: ?ddb.Attribute = null;
    for (req_attributes) |*att| {
        if (std.mem.eql(u8, att.name, hash_key_attribute_name)) {
            hash_attribute = att.*;
            continue;
        }
        if (range_key_attribute_name) |r| {
            if (std.mem.eql(u8, att.name, r))
                range_attribute = att.*;
        }
    }
    if (hash_attribute == null) return error.HashAttributeNotFound;
    if (range_attribute == null and range_key_attribute_name != null) return error.RangeAttributeNotFound;

    const hash_value = try std.json.stringifyAlloc(allocator, hash_attribute.?.value, .{});
    defer allocator.free(hash_value);
    const range_value = if (range_attribute) |r|
        try std.json.stringifyAlloc(allocator, r.value, .{})
    else
        null;
    defer if (range_value) |r| allocator.free(r);
    if (req_type == .delete) {
        try table.deleteItem(hash_value, range_value);
    } else {
        const attributes_as_string = try std.json.stringifyAlloc(allocator, req_attributes, .{});
        defer allocator.free(attributes_as_string);
        try table.putItem(hash_value, range_value, attributes_as_string);
    }
}

test "basic request parsing failure" {
    const allocator = std.testing.allocator;
    var request = AuthenticatedRequest{
        .output_format = .text,
        .event_data =
        \\ {
        \\    "RequestItems": {
        \\        "Forum": [
        \\            {
        \\                "PutRequest": {
        \\                    "Item": {
        \\                        "Name": {
        \\                            "BS": ["Amazon DynamoDB"]
        \\                        }
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
        .account_id = "1234",
        .allocator = allocator,
    };
    var al = std.ArrayList(u8).init(allocator);
    defer al.deinit();
    var writer = al.writer();
    var parms = try Params.parseRequest(allocator, &request, writer);
    defer parms.deinit();
    try std.testing.expectError(error.InvalidPadding, parms.validate());
}
test "basic request parsing" {
    const allocator = std.testing.allocator;
    var request = AuthenticatedRequest{
        .output_format = .text,
        .event_data =
        \\ {
        \\    "RequestItems": {
        \\        "Forum": [
        \\            {
        \\                "PutRequest": {
        \\                    "Item": {
        \\                        "Name": {
        \\                            "S": "Amazon DynamoDB"
        \\                        },
        \\                        "Category": {
        \\                            "S": "Amazon Web Services"
        \\                        }
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
        .account_id = "1234",
        .allocator = allocator,
    };
    var al = std.ArrayList(u8).init(allocator);
    defer al.deinit();
    var writer = al.writer();
    var parms = try Params.parseRequest(allocator, &request, writer);
    defer parms.deinit();
    try std.testing.expect(parms.return_consumed_capacity == .none);
    try std.testing.expect(!parms.return_item_collection_metrics);
    try std.testing.expect(parms.request_items.len == 1);
    const forum = parms.request_items[0];
    try std.testing.expectEqualStrings("Forum", forum.table_name);
    try std.testing.expect(forum.requests.len == 1);
    const put_and_or_delete = forum.requests[0];
    try std.testing.expect(put_and_or_delete.put_request != null);
    const put = put_and_or_delete.put_request.?;
    try std.testing.expect(put.len == 2);
    const name = put[0];
    const category = put[1];
    try std.testing.expectEqualStrings("Name", name.name);
    try std.testing.expectEqualStrings("Category", category.name);
    try std.testing.expect(name.value == .string);
    try std.testing.expect(category.value == .string);
    try std.testing.expectEqualStrings("Amazon DynamoDB", name.value.string);
    try std.testing.expectEqualStrings("Amazon Web Services", category.value.string);
    try std.testing.expect(put_and_or_delete.delete_request == null);
}
test "all types request parsing" {
    const allocator = std.testing.allocator;
    var request = AuthenticatedRequest{
        .output_format = .text,
        .event_data =
        \\ {
        \\    "RequestItems": {
        \\        "Forum": [
        \\            {
        \\                "PutRequest": {
        \\                    "Item": {
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
        \\                }
        \\            }
        \\        ]
        \\ }
        \\ }
        ,
        .headers = undefined,
        .status = .ok,
        .reason = "",
        .account_id = "1234",
        .allocator = allocator,
    };
    var al = std.ArrayList(u8).init(allocator);
    defer al.deinit();
    var writer = al.writer();
    var parms = try Params.parseRequest(allocator, &request, writer);
    defer parms.deinit();
    try parms.validate();
    try std.testing.expect(parms.return_consumed_capacity == .none);
    try std.testing.expect(!parms.return_item_collection_metrics);
    try std.testing.expect(parms.request_items.len == 1);
    const forum = parms.request_items[0];
    try std.testing.expectEqualStrings("Forum", forum.table_name);
    try std.testing.expect(forum.requests.len == 1);
    const put_and_or_delete = forum.requests[0];
    try std.testing.expect(put_and_or_delete.put_request != null);
    const put = put_and_or_delete.put_request.?;
    try std.testing.expect(put.len == 10);
    try std.testing.expectEqualStrings("String", put[0].name);
    try std.testing.expectEqualStrings("Number", put[1].name);
    try std.testing.expect(put[1].value == .number);
    try std.testing.expectEqualStrings("Binary", put[2].name);
    try std.testing.expect(put[2].value == .binary);
    try std.testing.expect(put[2].value.binary.len > 0);
    var buf = try allocator.alloc(u8, "this text is base64-encoded".len);
    defer allocator.free(buf);
    try std.base64.standard.Decoder.decode(buf, put[2].value.binary);
    try std.testing.expectEqualStrings("this text is base64-encoded", buf);
    try std.testing.expect(put_and_or_delete.delete_request == null);
}

test "write item" {
    Account.test_retain_db = true;
    defer Account.testDbDeinit();
    const allocator = std.testing.allocator;
    const account_id = "1234";
    var db = try Account.dbForAccount(allocator, account_id);
    defer allocator.destroy(db);
    defer Account.testDbDeinit();
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
        \\            }
        \\        ]
        \\ }
        \\ }
        ,
        .headers = undefined,
        .status = .ok,
        .reason = "",
        .account_id = "1234",
        .allocator = allocator,
    };
    var al = std.ArrayList(u8).init(allocator);
    defer al.deinit();
    var writer = al.writer();
    _ = try handler(&request, writer);
}
