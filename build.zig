const std = @import("std");
const universal_lambda_build = @import("universal-lambda-zig");

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
        .root_source_file = b.path("src/main.zig"),
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

    const universal_lambda_zig_dep = b.dependency("universal-lambda-zig", .{
        .target = target,
        .optimize = optimize,
    });
    // All modules should be added before this is called
    try universal_lambda_build.configureBuild(b, exe, universal_lambda_zig_dep);
    _ = universal_lambda_build.addImports(b, exe, universal_lambda_zig_dep);

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
    exe.root_module.addImport("aws-signing", exe_aws_signing_module);
    exe.root_module.addImport("sqlite", exe_sqlite_module);
    // exe.addIncludePath(.{ .path = "c" });
    exe.linkLibrary(exe_sqlite_dep.artifact("sqlite"));
    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    for (test_targets) |ct| {
        const t = b.resolveTargetQuery(ct);
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
            .root_source_file = b.path("src/main.zig"),
            .target = t,
            .optimize = optimize,
        });
        _ = universal_lambda_build.addImports(b, unit_tests, universal_lambda_zig_dep);

        const run_unit_tests = b.addRunArtifact(unit_tests);
        // run_unit_tests.skip_foreign_checks = true;

        test_step.dependOn(&run_unit_tests.step);

        unit_tests.root_module.addImport("aws-signing", aws_signing_module);
        unit_tests.root_module.addImport("sqlite", sqlite_module);
        // unit_tests.addIncludePath(b.path ("c" ));
        unit_tests.linkLibrary(sqlite_dep.artifact("sqlite"));
    }

    var creds_step = b.step("generate_credentials", "Generate credentials for access_keys.csv");
    creds_step.makeFn = generateCredentials;
}

fn generateCredentials(s: *std.Build.Step, prog_node: std.Progress.Node) error{ MakeFailed, MakeSkipped }!void {
    _ = s;
    // Account id:
    //     Documentation describes account id as a 12 digit number:
    //     https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-identifiers.html
    //     This can be a random number, but must be in a 12 digit range.
    //
    //     The access key is 32 bit encoded, which leaves us with
    //     8 * 5 = 40 bits of information to work with. The maximum value of
    //     a u40 in decimal is 1099511627775, a 13 digit number. So our maximum
    //     decimal is below, and fits into u40.
    //
    //     Min: 0x0000000000 (0d000000000000)
    //     Max: 0xe8d4a50fff (0d999999999999)
    //
    // Access key:
    //     This page shows how the access key is put together:
    //     https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489
    //     tl;dr
    //     * First 4 characters: designates type of key: We will use "ELAK" for access key
    //     * Next 8 characters: Account ID, base32 encoded, shifted by one bit
    //     * Next 8 characters: Unknown. Assume random base32, which would give us 8 * 5 = u40;
    //
    //
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
    const account_number = rand.intRangeAtMost(u40, 0, 999999999999); // 100000000000, 999999999999);
    const access_key_random_suffix = rand.int(u39);
    // We need the most significant bit as a 1 to make the key compatible with
    // AWS. Like...you can literally send these keys to public AWS `aws sts get-access-key-info --access-key-id <blah>`
    // and get your account number (after changing ELAK to AKIA!
    //
    // Without this bit set, AWS' sts will complain that this is not a valid key
    const access_key_suffix: u80 = (1 << 79) | (@as(u80, account_number) << 39) + @as(u80, access_key_random_suffix);
    var access_key_suffix_encoded: [16]u8 = undefined;
    base32Encode(u80, access_key_suffix, &access_key_suffix_encoded);
    // std.debug.assert(access_key_suffix_encoded.len == 16);
    var secret_key: [30]u8 = undefined;
    rand.bytes(&secret_key); // The rest don't need to be cryptographically secure...does this?
    var encoded_secret: [40]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&encoded_secret, secret_key[0..]);

    const stdout_raw = std.io.getStdOut().writer();
    var stdout_writer = std.io.bufferedWriter(stdout_raw);
    const stdout = stdout_writer.writer();
    // stdout.print(
    //     \\#    account_number: {b:0>80}
    //     \\#    random_suffix : {b:0>80}
    //     \\# access_key_suffix: {b:0>80}
    //     \\
    // ,
    //     .{
    //         @as(u80, account_number) << 39,
    //         @as(u80, access_key_random_suffix),
    //         access_key_suffix,
    //     },
    // ) catch return error.MakeFailed;
    stdout.print(
        "# access_key: ELAK{s}, secret_key: {s}, account_number: {d:0>12}, db_encryption_key: {s}",
        .{
            access_key_suffix_encoded,
            encoded_secret,
            account_number,
            key,
        },
    ) catch return error.MakeFailed;
    stdout.print(
        "\n#\n# You can copy/paste the following line into access_keys.csv:\nELAK{s},{s},{d:0>12},{s}\n",
        .{
            access_key_suffix_encoded,
            encoded_secret,
            account_number,
            key,
        },
    ) catch return error.MakeFailed;
    stdout_writer.flush() catch return error.MakeFailed;
}

/// encodes an unsigned integer into base36. Caller owns the memory returned
pub fn base36encode(comptime T: type, allocator: std.mem.Allocator, data: T) ![]const u8 {
    const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std.debug.assert(alphabet.len == 36);
    const ti = @typeInfo(T);
    if (ti != .Int or ti.Int.signedness != .unsigned)
        @compileError("encode only works with unsigned integers");
    const bits = ti.Int.bits;
    // We cannot have more than 6 bits (2^6 = 64) represented per byte in our final output
    var al = try std.ArrayList(u8).initCapacity(allocator, bits / 6);
    defer al.deinit();

    var remaining = data;
    while (remaining > 0) : (remaining /= @as(T, @intCast(alphabet.len))) {
        al.appendAssumeCapacity(alphabet[@as(usize, @intCast(remaining % alphabet.len))]);
    }
    // This is not exact, but 6 bits
    const rc = try al.toOwnedSlice();
    std.mem.reverse(u8, rc);
    return rc;
}

/// Because Base32 is a power of 2, we can directly return an array and avoid
/// allocations entirely. A pointer to the output array must be bits/5 long
/// To trim leading 0s, simply std.mem.trimLeft(u8, encoded_data, "A");
pub fn base32Encode(comptime T: type, data: T, encoded: *[@typeInfo(T).Int.bits / 5]u8) void {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std.debug.assert(alphabet.len == 32);
    const ti = @typeInfo(T);
    if (ti != .Int or ti.Int.signedness != .unsigned)
        @compileError("encode only works with unsigned integers");
    const bits = ti.Int.bits;
    // We will have exactly 5 bits (2^5 = 32) represented per byte in our final output
    // var rc: [bits / 5]u8 = undefined;
    var inx: usize = 0;
    const Shift_type = @Type(.{ .Int = .{
        .signedness = .unsigned,
        .bits = @ceil(@log2(@as(f128, @floatFromInt(bits)))),
    } });
    // TODO: I think we need a table here to determine the size below
    while (inx < encoded.len) : (inx += 1) {
        const char_bits: u5 = @as(u5, @truncate(data >> (@as(Shift_type, @intCast(inx * 5)))));
        encoded[encoded.len - @as(usize, @intCast(inx)) - 1] = alphabet[@as(usize, @intCast(char_bits))]; // 5 bits from inx
    }
}
