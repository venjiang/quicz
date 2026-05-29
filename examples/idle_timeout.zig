const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{IdleTimeoutExampleFailed};

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var conn = try quicz.Connection.init(allocator, .client, .{
        .max_idle_timeout_ms = 100,
    });
    defer conn.deinit();

    try conn.applyPeerTransportParameters(.{
        .max_idle_timeout = 80,
    });
    if (conn.effectiveIdleTimeoutMillis() != 80) return error.IdleTimeoutExampleFailed;

    try conn.sendPing();
    var tx: [16]u8 = undefined;
    const ping_payload = (try conn.pollTx(10, &tx)) orelse return error.IdleTimeoutExampleFailed;
    if (ping_payload.len != 1) return error.IdleTimeoutExampleFailed;

    const deadline = conn.idleTimeoutDeadlineMillis() orelse return error.IdleTimeoutExampleFailed;
    try conn.checkIdleTimeouts(deadline - 1);
    if (conn.connectionState() != .active) return error.IdleTimeoutExampleFailed;

    conn.checkIdleTimeouts(deadline) catch |err| {
        if (err != error.ConnectionClosed) return err;
    };
    if (conn.connectionState() != .closed) return error.IdleTimeoutExampleFailed;

    std.debug.print(
        "[idle] effective_timeout_ms={} deadline={} state={s}\n",
        .{ conn.effectiveIdleTimeoutMillis().?, deadline, @tagName(conn.connectionState()) },
    );
}
