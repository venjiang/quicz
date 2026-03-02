const std = @import("std");

// Build script for Zig 0.15.2 based on the official template.
// - Builds two example executables: quicz-echo-server and quicz-echo-client
// - Uses src/lib.zig as a shared module imported by both executables.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Shared quicz module (library logic lives in src/lib.zig)
    const quicz_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

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
}
