const std = @import("std");
const builtin = @import("builtin");

const required_zig_version = "0.16.0";

// Build script for the current Zig stable template.
// - Builds two example executables: quicz-echo-server and quicz-echo-client
// - Uses src/lib.zig as a shared module imported by both executables.
pub fn build(b: *std.Build) void {
    // Keep build semantics tied to the Zig version this repository is tested with.
    comptime {
        if (!std.mem.eql(u8, builtin.zig_version_string, required_zig_version)) {
            @compileError("quicz requires Zig " ++ required_zig_version ++ "; found " ++ builtin.zig_version_string);
        }
    }

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Shared quicz module (library logic lives in src/lib.zig)
    const quicz_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "quicz",
        .root_module = quicz_mod,
    });
    b.installArtifact(lib);

    // Echo server executable
    const exe_server = b.addExecutable(.{
        .name = "quicz-echo-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/echo_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_server);

    // Echo client executable
    const exe_client = b.addExecutable(.{
        .name = "quicz-echo-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/echo_client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_client);

    // zig build run-server
    const run_server = b.step("run-server", "Run quicz echo server");
    const run_server_cmd = b.addRunArtifact(exe_server);
    run_server.dependOn(&run_server_cmd.step);
    run_server_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_server_cmd.addArgs(args);
    }

    // zig build run-client
    const run_client = b.step("run-client", "Run quicz echo client");
    const run_client_cmd = b.addRunArtifact(exe_client);
    run_client.dependOn(&run_client_cmd.step);
    run_client_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_client_cmd.addArgs(args);
    }

    const lib_tests = b.addTest(.{
        .name = "quicz-tests",
        .root_module = quicz_mod,
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const test_step = b.step("test", "Run quicz unit tests");
    test_step.dependOn(&run_lib_tests.step);
}
