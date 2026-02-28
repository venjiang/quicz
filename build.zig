const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardReleaseOptions();

    const lib = b.addStaticLibrary(.{
        .name = "quicz",
        .root_source_file = .{ .path = "src/lib.zig" },
        .target = target,
        .optimize = optimize,
    });
    lib.install();

    const exe_server = b.addExecutable(.{
        .name = "quicz-echo-server",
        .root_source_file = .{ .path = "examples/echo_server.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe_server.addModule("quicz", lib);
    b.installArtifact(exe_server);

    const exe_client = b.addExecutable(.{
        .name = "quicz-echo-client",
        .root_source_file = .{ .path = "examples/echo_client.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe_client.addModule("quicz", lib);
    b.installArtifact(exe_client);

    const run_server = b.addRunArtifact(exe_server);
    const run_client = b.addRunArtifact(exe_client);

    const step_server = b.step("run-server", "Run quicz echo server");
    step_server.dependOn(&run_server.step);

    const step_client = b.step("run-client", "Run quicz echo client");
    step_client.dependOn(&run_client.step);
}
