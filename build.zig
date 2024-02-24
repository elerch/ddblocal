const std = @import("std");
const universal_lambda = @import("universal_lambda_build");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) !void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "ddblocal",
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const unit_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    _ = try universal_lambda.addModules(b, unit_tests);

    const run_unit_tests = b.addRunArtifact(unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    try universal_lambda.configureBuild(b, exe);

    const aws_dep = b.dependency("aws", .{
        .target = target,
        .optimize = optimize,
    });
    const aws_signing_module = aws_dep.module("aws-signing");
    const sqlite_dep = b.dependency("sqlite", .{
        .target = target,
        .optimize = optimize,
        .use_bundled = true,
    });
    const sqlite_module = sqlite_dep.module("sqlite");
    for (&[_]*std.Build.Step.Compile{ exe, unit_tests }) |cs| {
        cs.addModule("aws-signing", aws_signing_module);
        cs.addModule("sqlite", sqlite_module);
        cs.addIncludePath(.{ .path = "c" });
        cs.linkLibrary(sqlite_dep.artifact("sqlite"));
    }

    var creds_step = b.step("generate_credentials", "Generate credentials for access_keys.csv");
    creds_step.makeFn = generateCredentials;
}

fn generateCredentials(s: *std.build.Step, prog_node: *std.Progress.Node) error{ MakeFailed, MakeSkipped }!void {
    // Format:
    // Access Key,Account Id,Existing encoded encryption key, New encoded encryption
    _ = prog_node;
    const encryption = @import("src/encryption.zig");
    var key: [encryption.encoded_key_length]u8 = undefined;
    encryption.randomEncodedKey(&key);

    const seed = @as(u64, @truncate(@as(u128, @bitCast(std.time.nanoTimestamp()))));
    var prng = std.rand.DefaultPrng.init(seed);
    var rand = prng.random();
    const account_number = rand.intRangeAtMost(u64, 100000000000, 999999999999);
    const access_key_suffix: u128 = blk: { // workaround for u64 max on rand.intRangeAtMost
        const min = 0xECFF3BCC40CA2000000000;
        // const max = 0x2153E468B91C6E0000000000;
        // const diff = max - min; // 0x2066e52cecdba40000000000 (is 12 bytes/96 bits)
        // So we can use a full 64 bit range and just add to the min
        break :blk @as(u128, rand.int(u64)) + min;
    };
    const access_key_suffix_encoded = encode(
        u128,
        s.owner.allocator,
        access_key_suffix,
    ) catch return error.MakeFailed;
    var secret_key: [30]u8 = undefined;
    rand.bytes(&secret_key); // The rest don't need to be cryptographically secure...does this?
    var encoded_secret: [40]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&encoded_secret, secret_key[0..]);

    std.debug.print(
        "access_key: EL{s}, secret_key: {s}, account_number: {d}, db_encryption_key: {s}",
        .{
            access_key_suffix_encoded,
            encoded_secret,
            account_number,
            key,
        },
    );
    // Documentation describes account id as a 12 digit number:
    // https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-identifiers.html
    // Random u64
    // Max: 0x3b9ac9ff (0d999999999)
    // Min: 0x05f5e100 (0d100000000)
    //
    // Access key and secret key are probably more loose. Here is one:
    //
    //     "AccessKey": {
    //     "AccessKeyId": "AKIAYAM4POHXNMQUDBNG",
    //     "SecretAccessKey": "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",
    // }
    // Access key appears 20 characters A-Z, 0-9. Starts with AK or AS, so
    // 18 characters of random, and it looks like base36
    // https://ziglang.org/documentation/0.11.0/std/src/std/base64.zig.html
    // https://en.wikipedia.org/wiki/Base36
    // For 18 characters, the lower end would be:
    // NN100000000000000000 (hex: ECFF3BCC40CA2000000000)
    // Upper:
    // NNZZZZZZZZZZZZZZZZZZ (hex: 2153E468B91C6E0000000000)
    // Which can be stored in u24
    // Secret key here is 40 characters and roughly looks like base64 encoded
    // random binary data, which it probably is. 40 characters of base64 is 32 bytes of data
}

/// encodes an unsigned integer into base36
pub fn encode(comptime T: type, allocator: std.mem.Allocator, data: T) ![]const u8 {
    const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const ti = @typeInfo(T);
    if (ti != .Int or ti.Int.signedness != .unsigned)
        @compileError("encode only works with unsigned integers");
    const bits = ti.Int.bits;
    // We cannot have more than 6 bits (2^6 = 64) represented per byte in our final output
    var al = try std.ArrayList(u8).initCapacity(allocator, bits / 6);
    defer al.deinit();

    var remaining = data;
    while (remaining > 0) : (remaining /= 36) {
        al.appendAssumeCapacity(alphabet[@as(usize, @intCast(remaining % 36))]);
    }
    // This is not exact, but 6 bits
    var rc = try al.toOwnedSlice();
    std.mem.reverse(u8, rc);
    return rc;
}
