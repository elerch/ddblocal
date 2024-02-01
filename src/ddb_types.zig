const encryption = @import("encryption.zig");

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

pub const AttributeDefinition = struct {
    name: []const u8,
    type: AttributeTypeDescriptor,
};

pub const TableInfo = struct {
    attribute_definitions: []*const AttributeDefinition,
    // gsi_list: []const u8, // Not sure how this is used
    // gsi_description_list: []const u8, // Not sure how this is used
    // sqlite_index: []const u8, // Not sure how this is used
    table_key: [encryption.encoded_key_length]u8,
};
