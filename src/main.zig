const builtin = @import("builtin");
const std = @import("std");
const universal_lambda = @import("universal_lambda_handler");
const universal_lambda_interface = @import("universal_lambda_interface");
const universal_lambda_options = @import("universal_lambda_build_options");
const signing = @import("aws-signing");
const AuthenticatedRequest = @import("AuthenticatedRequest.zig");
const Account = @import("Account.zig");

const log = std.log.scoped(.dynamodb);

pub const std_options = struct {
    pub const log_scope_levels = &[_]std.log.ScopeLevel{.{ .scope = .aws_signing, .level = .info }};
};

pub fn main() !u8 {
    var fb_allocator = std.heap.FixedBufferAllocator.init(&creds_buf);
    const allocator = fb_allocator.allocator();
    fillRootCreds(allocator) catch |e| {
        log.err("Error filling root creds. Base authentication will not work until this is fixed: {}", .{e});
        return e;
    };

    return try universal_lambda.run(null, handler);
}

pub fn handler(allocator: std.mem.Allocator, event_data: []const u8, context: universal_lambda_interface.Context) ![]const u8 {
    const access_key = try allocator.dupe(u8, "ACCESS");
    const secret_key = try allocator.dupe(u8, "SECRET");
    test_credential = signing.Credentials.init(allocator, access_key, secret_key, null);
    defer test_credential.deinit();
    var fis = std.io.fixedBufferStream(event_data);

    try authenticateUser(allocator, context, context.request.target, context.request.headers, fis.reader());
    try setContentType(&context.headers, "application/x-amz-json-1.0", false);
    // https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html#API_CreateTable_Examples
    // Operation is in X-Amz-Target
    // event_data is json
    // X-Amz-Target: DynamoDB_20120810.CreateTable
    const target_value_or_null = context.request.headers.getFirstValue("X-Amz-Target");
    const target_value = if (target_value_or_null) |t| t else {
        context.status = .bad_request;
        context.reason = "Missing X-Amz-Target header";
        return error.XAmzTargetHeaderMissing;
    };
    const operation_or_null = std.mem.lastIndexOf(u8, target_value, ".");
    const operation = if (operation_or_null) |o| target_value[o + 1 ..] else {
        context.status = .bad_request;
        context.reason = "Missing operation in X-Amz-Target";
        return error.XAmzTargetHeaderMalformed;
    };
    var authenticated_request = AuthenticatedRequest{
        .allocator = allocator,
        .event_data = event_data,
        .account_id = try accountId(allocator, context.request.headers),
        .status = context.status,
        .reason = context.reason,
        .headers = context.request.headers,
        .output_format = switch (universal_lambda_options.build_type) {
            // This may seem to be dumb, but we want to be cognizant of
            // any new platforms and explicitly consider them
            .awslambda, .standalone_server, .cloudflare, .flexilib => .json,
            .exe_run => .text,
        },
    };

    const writer = context.writer();
    if (std.ascii.eqlIgnoreCase("CreateTable", operation))
        return executeOperation(&authenticated_request, context, writer, @import("createtable.zig").handler);
    if (std.ascii.eqlIgnoreCase("BatchWriteItem", operation))
        return executeOperation(&authenticated_request, context, writer, @import("batchwriteitem.zig").handler);
    if (std.ascii.eqlIgnoreCase("BatchGetItem", operation))
        return executeOperation(&authenticated_request, context, writer, @import("batchgetitem.zig").handler);

    try writer.print("Operation '{s}' unsupported\n", .{operation});
    context.status = .bad_request;
    return error.OperationUnsupported;
}
fn setContentType(headers: *std.http.Headers, content_type: []const u8, overwrite: bool) !void {
    if (headers.contains("content-type")) {
        if (!overwrite) return;
        _ = headers.delete("content-type");
    }
    try headers.append("Content-Type", content_type);
}
fn executeOperation(
    request: *AuthenticatedRequest,
    context: universal_lambda_interface.Context,
    writer: anytype,
    operation: fn (*AuthenticatedRequest, anytype) anyerror![]const u8,
) ![]const u8 {
    return operation(request, writer) catch |err| {
        context.status = request.status;
        context.reason = request.reason;
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
        return err;
    };
}
fn authenticateUser(allocator: std.mem.Allocator, context: universal_lambda_interface.Context, target: []const u8, headers: std.http.Headers, body_reader: anytype) !void {
    var request = signing.UnverifiedRequest{
        .method = std.http.Method.POST,
        .target = target,
        .headers = headers,
    };
    const auth_bypass =
        @import("builtin").os.tag == .linux and @import("builtin").mode == .Debug and try std.process.hasEnvVar(allocator, "DEBUG_AUTHN_BYPASS");
    const is_authenticated = auth_bypass or
        signing.verify(allocator, request, body_reader, getCreds) catch |err| {
        if (std.mem.eql(u8, "AuthorizationHeaderMissing", @errorName(err))) {
            context.status = .unauthorized;
            return error.Unauthenticated;
        }
        log.err("Caught error on signature verifcation: {any}", .{err});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }

        context.status = .unauthorized;
        return error.Unauthenticated;
    };
    // Universal lambda should check these and convert them to http
    if (!is_authenticated) {
        context.status = .unauthorized;
        return error.Unauthenticated;
    }
}

var test_credential: signing.Credentials = undefined;
var root_creds: std.StringHashMap(signing.Credentials) = undefined;
// var root_account_mapping: std.StringHashMap([]const u8) = undefined;
var creds_buf: [8192]u8 = undefined;
fn getCreds(access: []const u8) ?signing.Credentials {
    // We have 3 levels of access here
    //
    // 1. Test creds, used strictly for debugging
    // 2. Creds from the root file, ideally used only for bootstrapping
    // 3. Creds from STS GetAccessKeyInfo API call, which should be 99%+ of ops
    if (std.mem.eql(u8, access, "ACCESS")) return test_credential;
    log.debug("Creds for access key {s}: {any}", .{ access, root_creds.get(access) != null });
    if (root_creds.get(access)) |c| return c;
    log.err("Creds not found in store. STS GetAccessKeyInfo call is not yet implemented", .{});
    return null;
}

fn fillRootCreds(allocator: std.mem.Allocator) !void {
    root_creds = std.StringHashMap(signing.Credentials).init(allocator);
    // root_account_mapping = std.StringHashMap([]const u8).init(allocator);
    Account.root_key_mapping = std.AutoHashMap(u40, []const u8).init(allocator);
    var file = std.fs.cwd().openFile("access_keys.csv", .{}) catch |e| {
        log.err("Could not open access_keys.csv to access root creds: {}", .{e});
        return e;
    };
    defer file.close();
    var buf_reader = std.io.bufferedReader(file.reader());
    const reader = buf_reader.reader();

    var file_buf: [8192]u8 = undefined; // intentionally kept small here...this should be used sparingly
    var file_fb_allocator = std.heap.FixedBufferAllocator.init(&file_buf);
    const file_allocator = file_fb_allocator.allocator();

    var line = std.ArrayList(u8).init(file_allocator);
    defer line.deinit();

    const line_writer = line.writer();
    var line_num: usize = 1;
    while (reader.streamUntilDelimiter(line_writer, '\n', null)) : (line_num += 1) {
        defer line.clearRetainingCapacity();
        var relevant_line = line.items[0 .. std.mem.indexOfScalar(u8, line.items, '#') orelse line.items.len];
        const relevant_line_trimmed = std.mem.trim(u8, relevant_line, " \t");
        var value_iterator = std.mem.splitScalar(u8, relevant_line_trimmed, ',');
        if (std.mem.trim(u8, value_iterator.peek().?, " \t").len == 0) continue;
        var val_num: usize = 0;
        var access_key: []const u8 = undefined;
        var secret_key: []const u8 = undefined;
        var account_id: []const u8 = undefined;
        var existing_key: []const u8 = undefined;
        var new_key: []const u8 = undefined;
        while (value_iterator.next()) |val| : (val_num += 1) {
            const actual_val = std.mem.trim(u8, val, " \t");
            switch (val_num) {
                0 => access_key = actual_val,
                1 => secret_key = actual_val,
                2 => account_id = actual_val,
                3 => existing_key = actual_val,
                4 => new_key = actual_val,
                else => {
                    log.err("access_keys.csv Error on line {d}: too many values", .{line_num});
                    return error.TooManyValues;
                },
            }
        }
        if (val_num < 4) {
            log.err("access_keys.csv Error on line {d}: too few values", .{line_num});
            return error.TooFewValues;
        }
        const global_access_key = try allocator.dupe(u8, access_key);
        try root_creds.put(global_access_key, .{
            .access_key = global_access_key, // we need to copy all these into our global buffer
            .secret_key = try allocator.dupe(u8, secret_key),
            .session_token = null,
            .allocator = NullAllocator.init(),
        });
        const global_account_id = try std.fmt.parseInt(u40, account_id, 10);
        // unnecessary. Account ids are embedded in access keys!
        // try root_account_mapping.put(global_access_key, global_account_id);
        try Account.root_key_mapping.?.put(global_account_id, try allocator.dupe(u8, existing_key));
        // TODO: key rotation will need another hash map, can be triggered on val_num == 5

    } else |e| switch (e) {
        error.EndOfStream => {}, // will this work without \n at the end of file?
        else => return e,
    }
}

const NullAllocator = struct {
    const thing = 0;
    const vtable = std.mem.Allocator.VTable{
        .alloc = alloc,
        .resize = resize,
        .free = free,
    };

    fn alloc(ctx: *anyopaque, len: usize, ptr_align: u8, ret_addr: usize) ?[*]u8 {
        _ = ctx;
        _ = len;
        _ = ptr_align;
        _ = ret_addr;
        return null;
    }

    fn resize(ctx: *anyopaque, buf: []u8, buf_align: u8, new_len: usize, ret_addr: usize) bool {
        _ = ctx;
        _ = buf;
        _ = buf_align;
        _ = new_len;
        _ = ret_addr;
        return false;
    }

    fn free(ctx: *anyopaque, buf: []u8, buf_align: u8, ret_addr: usize) void {
        _ = ctx;
        _ = buf;
        _ = buf_align;
        _ = ret_addr;
    }

    pub fn init() std.mem.Allocator {
        return .{
            .ptr = @ptrFromInt(@intFromPtr(&thing)),
            .vtable = &vtable,
        };
    }
};

fn accountForAccessKey(allocator: std.mem.Allocator, access_key: []const u8) !u40 {
    _ = allocator;
    log.debug("Finding account for access key: '{s}'", .{access_key});
    if (access_key.len != 20) return error.InvalidAccessKey;
    return try accountIdForAccessKey(@as(*[20]u8, @ptrCast(@constCast(access_key))).*);
    // Since this happens after authentication, we can assume our root creds store
    // is populated
    // if (root_account_mapping.get(access_key)) |account| return account;
    // log.err("Creds not found in store. STS GetAccessKeyInfo call is not yet implemented", .{});
    // return error.NotImplemented;
}
/// Function assumes an authenticated request, so signing.verify must be called
/// and returned true before calling this function. If authentication header
/// is not found, environment variable will be used
fn accountId(allocator: std.mem.Allocator, headers: std.http.Headers) !u40 {
    const auth_header = headers.getFirstValue("Authorization");
    if (auth_header) |h| {
        // AWS4-HMAC-SHA256 Credential=ACCESS/20230908/us-west-2/s3/aws4_request, SignedHeaders=accept;content-length;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, Signature=fcc43ce73a34c9bd1ddf17e8a435f46a859812822f944f9eeb2aabcd64b03523
        const start = std.mem.indexOf(u8, h, "Credential=").? + "Credential=".len;
        var split = std.mem.split(u8, h[start..], "/");
        return try accountForAccessKey(allocator, split.first());
    }
    return try iamAccountId(allocator);
}

pub fn returnException(
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

// These never need to be freed because we will need them throughout the program
var iam_account_id: ?[]const u8 = null;
var iam_access_key: ?[]const u8 = null;
var iam_secret_key: ?[]const u8 = null;
var iam_credential: ?signing.Credentials = null;
fn iamCredentials(allocator: std.mem.Allocator) ![]const u8 {
    if (iam_credential) |cred| return cred;
    iam_credential = signing.Credentials.init(allocator, try iamAccessKey(allocator), try iamSecretKey(allocator), null);
    return iam_credential.?;
}
fn iamAccountId(allocator: std.mem.Allocator) !u40 {
    return std.fmt.parseInt(u40, try getVariable(allocator, &iam_account_id, "IAM_ACCOUNT_ID"), 10);
}
fn iamAccessKey(allocator: std.mem.Allocator) ![]const u8 {
    return try getVariable(allocator, &iam_access_key, "IAM_ACCESS_KEY");
}
fn iamSecretKey(allocator: std.mem.Allocator) ![]const u8 {
    return try getVariable(allocator, &iam_secret_key, "IAM_SECRET_KEY");
}
fn getVariable(allocator: std.mem.Allocator, global: *?[]const u8, env_var_name: []const u8) ![]const u8 {
    if (global.*) |gl| return gl;
    global.* = try std.process.getEnvVarOwned(allocator, env_var_name);
    return global.*.?;
}

test {
    std.testing.refAllDecls(@import("createtable.zig"));
    std.testing.refAllDecls(@import("batchwriteitem.zig"));
    std.testing.refAllDecls(@import("batchgetitem.zig"));
}

test "can get account id from access key" {
    // ELAKM5YGIGQQAD2B54IZ, Account 888534479904
    // Also, https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489
    // aws_access_key_id: ASIAY34FZKBOKMUTVV7A yields the expected account id "609629065308"
    try std.testing.expectEqual(@as(u40, 609629065308), try accountIdForAccessKey(@as(*[20]u8, @ptrCast(@constCast("ASIAY34FZKBOKMUTVV7A"))).*));
    try std.testing.expectEqual(@as(u40, 888534479904), try accountIdForAccessKey(@as(*[20]u8, @ptrCast(@constCast("ELAKM5YGIGQQAD2B54IZ"))).*));
}

fn accountIdForAccessKey(access_key: [20]u8) !u40 {
    const ak_integer_part = access_key[4..];
    const ak_integer = try base32Decode(u80, @as(*[16]u8, @ptrCast(@constCast(ak_integer_part.ptr))).*);
    const account_id = ak_integer >> 39;
    return @as(u40, @truncate(account_id));
    // Do we want an array like this? Probably so
    // import base64
    // import binascii
    //
    // def AWSAccount_from_AWSKeyID(AWSKeyID):
    //
    //     trimmed_AWSKeyID = AWSKeyID[4:] #remove KeyID prefix
    //     x = base64.b32decode(trimmed_AWSKeyID) #base32 decode
    //     y = x[0:6]
    //
    //     z = int.from_bytes(y, byteorder='big', signed=False)
    //     mask = int.from_bytes(binascii.unhexlify(b'7fffffffff80'), byteorder='big', signed=False)
    //
    //     e = (z & mask)>>7
    //     return (e)
}

fn base32Decode(comptime T: type, data: [@typeInfo(T).Int.bits / 5]u8) !T {
    // const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const ti = @typeInfo(T);
    if (ti != .Int or ti.Int.signedness != .unsigned)
        @compileError("decode only works with unsigned integers");
    if (ti.Int.bits % 5 != 0)
        @compileError("unsigned integer bit length must be a multiple of 5 to use this function");
    const Shift_type = @Type(.{ .Int = .{
        .signedness = .unsigned,
        .bits = @ceil(@log2(@as(f128, @floatFromInt(ti.Int.bits)))),
    } });
    var rc: T = 0;
    for (data, 0..) |b, i| {
        var curr: T = 0;
        if (b >= 'A' and b <= 'Z') {
            curr = b - 'A';
        } else if (b >= '2' and b <= '7') {
            curr = b - '2' + 26;
        } else return error.InvalidCharacter;
        curr <<= @as(Shift_type, @intCast((data.len - 1 - i) * 5));
        rc |= curr;
    }
    return rc;
}
