//! The quicz CLI is a separate package that references the quicz library as a
//! normal dependency. Build it from this directory:
//!
//!   zig build                        # build zig-out/bin/quicz
//!   zig build run -- --help          # build and run the CLI
//!   zig build run -- h3 https://127.0.0.1:4433/ -k
//!   zig build run -- serve --dir ../docs --port 4433

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const quicz_dep = b.dependency("quicz", .{
        .target = target,
        .optimize = optimize,
    });
    const quicz_mod = quicz_dep.module("quicz");
    const test_cert_mod = quicz_dep.module("quicz-test-cert");

    const exe = b.addExecutable(.{
        .name = "quicz",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
                .{ .name = "test_certs", .module = test_cert_mod },
            },
        }),
    });
    b.installArtifact(exe);

    const run = b.step("run", "Run the quicz CLI");
    const run_cmd = b.addRunArtifact(exe);
    run.dependOn(&run_cmd.step);
    run_cmd.addPassthruArgs();

    const cli_tests = b.addTest(.{
        .name = "quicz-cli-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
                .{ .name = "test_certs", .module = test_cert_mod },
            },
        }),
    });
    const run_cli_tests = b.addRunArtifact(cli_tests);
    const test_step = b.step("test", "Run quicz CLI unit tests");
    test_step.dependOn(&run_cli_tests.step);
}
