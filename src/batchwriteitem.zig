const std = @import("std");
const sqlite = @import("sqlite");
const AuthenticatedRequest = @import("AuthenticatedRequest.zig");
const Account = @import("Account.zig");
const encryption = @import("encryption.zig");
const ddb = @import("ddb.zig");
const returnException = @import("main.zig").returnException;

const AttributeValue = union(ddb.AttributeTypeName) {
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
        var rc: Self = undefined;
        if (std.mem.eql(u8, token.string, "string"))
            rc = Self{ .string = try std.json.innerParse([]const u8, allocator, source, options) };
        if (std.mem.eql(u8, token.string, "number"))
            rc = Self{ .number = try std.json.innerParse([]const u8, allocator, source, options) };
        if (std.mem.eql(u8, token.string, "binary"))
            rc = Self{ .binary = try std.json.innerParse([]const u8, allocator, source, options) };
        if (std.mem.eql(u8, token.string, "boolean"))
            rc = Self{ .boolean = try std.json.innerParse(bool, allocator, source, options) };
        if (std.mem.eql(u8, token.string, "null"))
            rc = Self{ .null = try std.json.innerParse(bool, allocator, source, options) };
        if (std.mem.eql(u8, token.string, "string_set"))
            rc = Self{ .string_set = try std.json.innerParse([][]const u8, allocator, source, options) };
        if (std.mem.eql(u8, token.string, "number_set"))
            rc = Self{ .number_set = try std.json.innerParse([][]const u8, allocator, source, options) };
        if (std.mem.eql(u8, token.string, "binary_set"))
            rc = Self{ .binary_set = try std.json.innerParse([][]const u8, allocator, source, options) };
        if (std.mem.eql(u8, token.string, "list")) {
            var json = try std.json.Value.jsonParse(allocator, source, options);
            rc = Self{ .list = json.array };
        }
        if (std.mem.eql(u8, token.string, "map")) {
            var json = try std.json.Value.jsonParse(allocator, source, options);
            rc = Self{ .map = json.object };
        }
        if (.object_end != try source.next()) return error.UnexpectedToken;
        return rc;
    }

    pub fn jsonStringify(self: Self, jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField(@tagName(self));
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
const Attribute = struct {
    name: []const u8,
    value: AttributeValue,
};

const Request = struct {
    put_request: ?[]Attribute,
    delete_request: ?[]Attribute,
};
const RequestItem = struct {
    table_name: []const u8,
    requests: []Request,
};

const ReturnConsumedCapacity = enum {
    indexes,
    total,
    none,
};
const Params = struct {
    request_items: []RequestItem,
    return_consumed_capacity: ReturnConsumedCapacity = .none,
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
            rc.return_consumed_capacity = std.meta.stringToEnum(ReturnConsumedCapacity, val).?;
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
                        table_request.put_request = try parseAttributes(aa, put_val.?.object, request, writer);
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
                        table_request.delete_request = try parseAttributes(aa, del_val.?.object, request, writer);
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
        //                   "string" : {
        //                      "B": blob,
        //                      "BOOL": boolean,
        //                      "BS": [ blob ],
        //                      "L": [
        //                         "AttributeValue"
        //                      ],
        //                      "M": {
        //                         "string" : "AttributeValue"
        //                      },
        //                      "N": "string",
        //                      "NS": [ "string" ],
        //                      "NULL": boolean,
        //                      "S": "string",
        //                      "SS": [ "string" ]
        //                   }
        //                }
        //             },
        //             "PutRequest": {
        //                "Item": {
        //                   "string" : {
        //                      "B": blob,
        //                      "BOOL": boolean,
        //                      "BS": [ blob ],
        //                      "L": [
        //                         "AttributeValue"
        //                      ],
        //                      "M": {
        //                         "string" : "AttributeValue"
        //                      },
        //                      "N": "string",
        //                      "NS": [ "string" ],
        //                      "NULL": boolean,
        //                      "S": "string",
        //                      "SS": [ "string" ]
        //                   }
        //                }
        //             }
        //          }
        //       ]
        //    },
        //    "ReturnConsumedCapacity": "string",
        //    "ReturnItemCollectionMetrics": "string"
        // }
    }
    fn parseAttributes(
        arena: std.mem.Allocator,
        value: anytype,
        request: *AuthenticatedRequest,
        writer: anytype,
    ) ![]Attribute {
        //  {
        //    "string" : {
        //       "B": blob,
        //       "BOOL": boolean,
        //       "BS": [ blob ],
        //       "L": [
        //          "AttributeValue"
        //       ],
        //       "M": {
        //          "string" : "AttributeValue"
        //       },
        //       "N": "string",
        //       "NS": [ "string" ],
        //       "NULL": boolean,
        //       "S": "string",
        //       "SS": [ "string" ]
        //    }
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
            var val_iterator = val.object.iterator();
            var val_val = val_iterator.next().?;
            const attribute_type = val_val.key_ptr.*; // This should be "S", "N", "NULL", "BOOL", etc
            const attribute_value = val_val.value_ptr.*;
            // Convert this to our enum
            const attribute_type_enum = std.meta.stringToEnum(ddb.AttributeTypeDescriptor, attribute_type);
            if (attribute_type_enum == null)
                try returnException(
                    request,
                    .bad_request,
                    error.ValidationException,
                    writer,
                    "Request in RequestItems found attribute with invalid type",
                );
            // Now we need to get *THIS* enum over to our union, which uses the same values
            // We'll just use a switch here, because each of these cases must
            // be handled slightly differently
            var final_attribute_value: AttributeValue = undefined;
            switch (attribute_type_enum.?.toAttributeTypeName()) {
                .string => {
                    try expectType(attribute_value, .string, request, writer);
                    final_attribute_value = .{ .string = attribute_value.string };
                },
                .number => {
                    // There is a .number_string, but I think that is for stringify?
                    try expectType(attribute_value, .string, request, writer);
                    final_attribute_value = .{ .number = attribute_value.string };
                },
                .binary => {
                    try expectType(attribute_value, .string, request, writer);
                    final_attribute_value = .{ .binary = attribute_value.string };
                },
                .boolean => {
                    try expectType(attribute_value, .bool, request, writer);
                    final_attribute_value = .{ .boolean = attribute_value.bool };
                },
                .null => {
                    try expectType(attribute_value, .bool, request, writer);
                    final_attribute_value = .{ .null = attribute_value.bool };
                },
                .map => {
                    try expectType(attribute_value, .object, request, writer);
                    final_attribute_value = .{ .map = attribute_value.object };
                },
                .list => {
                    try expectType(attribute_value, .array, request, writer);
                    final_attribute_value = .{ .list = attribute_value.array };
                },
                .string_set => {
                    try expectType(attribute_value, .array, request, writer);
                    final_attribute_value = .{ .string_set = try toStringArray(arena, attribute_value.array, request, writer) };
                },
                .number_set => {
                    try expectType(attribute_value, .array, request, writer);
                    final_attribute_value = .{ .number_set = try toStringArray(arena, attribute_value.array, request, writer) };
                },
                .binary_set => {
                    try expectType(attribute_value, .array, request, writer);
                    final_attribute_value = .{ .binary_set = try toStringArray(arena, attribute_value.array, request, writer) };
                },
            }
            rc[inx].value = final_attribute_value;
        }
        return rc;
    }

    fn toStringArray(
        arena: std.mem.Allocator,
        arr: std.json.Array,
        request: *AuthenticatedRequest,
        writer: anytype,
    ) ![][]const u8 {
        var rc = try arena.alloc([]const u8, arr.items.len);
        for (arr.items, 0..) |item, inx| {
            try expectType(item, .string, request, writer);
            rc[inx] = item.string;
        }
        return rc;
    }

    fn expectType(actual: std.json.Value, comptime expected: @TypeOf(.enum_literal), request: *AuthenticatedRequest, writer: anytype) !void {
        if (actual != expected)
            try returnException(
                request,
                .bad_request,
                error.ValidationException,
                writer,
                "Attribute type does not match expected type",
            );
        if (actual == .array and actual.array.items.len == 0)
            try returnException(
                request,
                .bad_request,
                error.ValidationException,
                writer,
                "Attribute array cannot be empty",
            );
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
    req_attributes: []Attribute,
) !void {
    _ = db;
    // 1. Find the hash values of put and delete requests in the request
    const hash_key_attribute_name = table.info.value.hash_key_attribute_name;
    const range_key_attribute_name = table.info.value.range_key_attribute_name;
    var hash_attribute: ?Attribute = null;
    var range_attribute: ?Attribute = null;
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
        \\      "string": "bar"
        \\    }
        \\  },
        \\  {
        \\    "name": "foo",
        \\    "value": {
        \\      "number": "42"
        \\    }
        \\  },
        \\  {
        \\    "name": "foo",
        \\    "value": {
        \\      "binary": "YmFy"
        \\    }
        \\  },
        \\  {
        \\    "name": "foo",
        \\    "value": {
        \\      "boolean": true
        \\    }
        \\  },
        \\  {
        \\    "name": "foo",
        \\    "value": {
        \\      "null": false
        \\    }
        \\  },
        \\  {
        \\    "name": "foo",
        \\    "value": {
        \\      "string_set": [
        \\        "foo",
        \\        "bar"
        \\      ]
        \\    }
        \\  },
        \\  {
        \\    "name": "foo",
        \\    "value": {
        \\      "number_set": [
        \\        "41",
        \\        "42"
        \\      ]
        \\    }
        \\  },
        \\  {
        \\    "name": "foo",
        \\    "value": {
        \\      "binary_set": [
        \\        "Zm9v",
        \\        "YmFy"
        \\      ]
        \\    }
        \\  },
        \\  {
        \\    "name": "foo",
        \\    "value": {
        \\      "map": {
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
        \\      "list": [
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
