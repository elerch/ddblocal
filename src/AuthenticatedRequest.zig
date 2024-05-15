const std = @import("std");

allocator: std.mem.Allocator,
event_data: []const u8,
headers: []const std.http.Header,
status: std.http.Status,
reason: ?[]const u8,
account_id: u40,
output_format: OutputFormat,

pub const OutputFormat = enum {
    text,
    json,
};
