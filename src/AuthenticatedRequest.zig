const std = @import("std");

allocator: std.mem.Allocator,
event_data: []const u8,
headers: std.http.Headers,
status: std.http.Status,
reason: ?[]const u8,
account_id: []const u8,
output_format: OutputFormat,

pub const OutputFormat = enum {
    text,
    json,
};
