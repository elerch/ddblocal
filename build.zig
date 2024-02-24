const std = @import("std");
const universal_lambda = @import("universal_lambda_build");

// This seems to fail for some reason. zig-sqlite does a lot of messing with
// the target. So instead, we will handle this in the CI/CD system at the
// command line
const test_targets = [_]std.zig.CrossTarget{
    .{}, // native
    // .{
    //     .cpu_arch = .x86_64,
    //     .os_tag = .linux,
    // },
    // .{
    //     .cpu_arch = .aarch64,
    //     .os_tag = .linux,
    // },
    // .{
    //     .cpu_arch = .riscv64,
    //     .os_tag = .linux,
    // },
    // will not work
    // .{
    //     .cpu_arch = .arm,
    //     .os_tag = .linux,
    // },
    // .{
    //     .cpu_arch = .x86_64,
    //     .os_tag = .windows,
    // },
    // .{
    //     .cpu_arch = .aarch64,
    //     .os_tag = .macos,
    // },
    // .{
    //     .cpu_arch = .x86_64,
    //     .os_tag = .macos,
    // },
    // Since we are using sqlite, we cannot use wasm32/wasi at this time. Even
    // with compile errors above, I do not believe wasi will be easily supported
    // .{
    //     .cpu_arch = .wasm32,
    //     .os_tag = .wasi,
    // },
};

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

    try universal_lambda.configureBuild(b, exe);

    const exe_aws_dep = b.dependency("aws", .{
        .target = target,
        .optimize = optimize,
    });
    const exe_aws_signing_module = exe_aws_dep.module("aws-signing");
    const exe_sqlite_dep = b.dependency("sqlite", .{
        .target = target,
        .optimize = optimize,
        .use_bundled = true,
    });
    const exe_sqlite_module = exe_sqlite_dep.module("sqlite");
    exe.addModule("aws-signing", exe_aws_signing_module);
    exe.addModule("sqlite", exe_sqlite_module);
    exe.addIncludePath(.{ .path = "c" });
    exe.linkLibrary(exe_sqlite_dep.artifact("sqlite"));
    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    for (test_targets) |t| {
        const aws_dep = b.dependency("aws", .{
            .target = t,
            .optimize = optimize,
        });
        const aws_signing_module = aws_dep.module("aws-signing");
        const sqlite_dep = b.dependency("sqlite", .{
            .target = t,
            .optimize = optimize,
            .use_bundled = true,
        });
        const sqlite_module = sqlite_dep.module("sqlite");
        // Creates a step for unit testing. This only builds the test executable
        // but does not run it.
        const unit_tests = b.addTest(.{
            .root_source_file = .{ .path = "src/main.zig" },
            .target = t,
            .optimize = optimize,
        });
        _ = try universal_lambda.addModules(b, unit_tests);

        const run_unit_tests = b.addRunArtifact(unit_tests);
        // run_unit_tests.skip_foreign_checks = true;

        test_step.dependOn(&run_unit_tests.step);

        unit_tests.addModule("aws-signing", aws_signing_module);
        unit_tests.addModule("sqlite", sqlite_module);
        unit_tests.addIncludePath(.{ .path = "c" });
        unit_tests.linkLibrary(sqlite_dep.artifact("sqlite"));
    }

    var creds_step = b.step("generate_credentials", "Generate credentials for access_keys.csv");
    creds_step.makeFn = generateCredentials;
}

fn generateCredentials(s: *std.build.Step, prog_node: *std.Progress.Node) error{ MakeFailed, MakeSkipped }!void {
    // Account id:
    //     Documentation describes account id as a 12 digit number:
    //     https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-identifiers.html
    //     This can be a random u64, but must be in a 12 digit range, which
    //     is:
    //
    //     Min: 0x05f5e100 (0d100000000)
    //     Max: 0x3b9ac9ff (0d999999999)
    //
    // Access key:
    //     Access key is 20 characters and can be represented by base36
    //     https://en.wikipedia.org/wiki/Base36
    //     (it is nearly definitely base36 in AWS in practice)
    //     At least the first two characters are not part of the number...they
    //     have meaning. AK for a permanent key, AS for a session token.
    //     We shall use "EL" just...because. Maybe ET later for session tokens.
    //     This gives us 18 characters to work with, making our range like this:
    //
    //     Min:
    //     NN100000000000000000 (hex: 0xECFF3BCC40CA2000000000)
    //     Max:
    //     NNZZZZZZZZZZZZZZZZZZ (hex: 0x2153E468B91C6E0000000000)
    //
    //     The max value therefore requires a u96 to represent, as does the
    //     difference between max and min (0x2066e52cecdba40000000000). However,
    //     Zig 0.11.0 cannot handle random numbers that large
    //     (https://github.com/ziglang/zig/blob/0.11.0/lib/std/rand.zig#L145),
    //     so for now we use a random u64 and call it good.
    //
    // Secret Access Key:
    //     In the wild, these are 40 characters and appear to be base64 encoded.
    //     Base64 encoding of 30 bytes is always exactly 40 characters and have
    //     no padding, which is exactly what we observe
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

    const stdout_raw = std.io.getStdOut().writer();
    var stdout_writer = std.io.bufferedWriter(stdout_raw);
    const stdout = stdout_writer.writer();
    stdout.print(
        "# access_key: EL{s}, secret_key: {s}, account_number: {d}, db_encryption_key: {s}",
        .{
            access_key_suffix_encoded,
            encoded_secret,
            account_number,
            key,
        },
    ) catch return error.MakeFailed;
    stdout.print(
        "\n#\n# You can copy/paste the following line into access_keys.csv:\nEL{s},{s}{d}{s}\n",
        .{
            access_key_suffix_encoded,
            encoded_secret,
            account_number,
            key,
        },
    ) catch return error.MakeFailed;
    stdout_writer.flush() catch return error.MakeFailed;
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
