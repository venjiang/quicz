const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const mode = std.builtin.GlobalOptions.build_mode;

    const lib = b.addStaticLibrary("quicz", "src/lib.zig");
    lib.setTarget(target);
    lib.setBuildMode(mode);
    lib.install();

    const exe_server = b.addExecutable("quicz-echo-server", "examples/echo_server.zig");
    exe_server.setTarget(target);
    exe_server.setBuildMode(mode);
    exe_server.addPackagePath("quicz", "src/lib.zig");
    b.installArtifact(exe_server);

    const exe_client = b.addExecutable("quicz-echo-client", "examples/echo_client.zig");
    exe_client.setTarget(target);
    exe_client.setBuildMode(mode);
    exe_client.addPackagePath("quicz", "src/lib.zig");
    b.installArtifact(exe_client);

    const run_server = b.step("run-server", "Run quicz echo server");
    run_server.dependOn(&exe_server.run().step);

    const run_client = b.step("run-client", "Run quicz echo client");
    run_client.dependOn(&exe_client.run().step);
}
