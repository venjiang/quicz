const std = @import("std");
const quicz = @import("quicz");

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var validated = try quicz.QuicConnection.init(allocator, .client, .{});
    defer validated.deinit();

    _ = try validated.recordEcnPacketSentInSpace(.application, 0, 1200, .ect0);
    try validated.receiveAckEcnInSpace(.application, 50, .{
        .ack = .{
            .largest_acknowledged = 0,
            .ack_delay = 0,
            .first_ack_range = 0,
        },
        .ecn_counts = .{
            .ect0_count = 1,
            .ect1_count = 0,
            .ecn_ce_count = 0,
        },
    });
    if (validated.ecnValidationState(.application) != .capable) return error.EcnValidationExampleFailed;
    std.debug.print(
        "[ecn] ECT0 ACK_ECN validated; bytes_in_flight={d}\n",
        .{validated.bytesInFlight(.application)},
    );

    var failed = try quicz.QuicConnection.init(allocator, .client, .{});
    defer failed.deinit();

    _ = try failed.recordEcnPacketSentInSpace(.application, 0, 1200, .ect0);
    try failed.receiveAckInSpace(.application, 50, .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    if (failed.ecnValidationState(.application) != .failed) return error.EcnValidationExampleFailed;
    std.debug.print("[ecn] missing ACK_ECN disabled ECN validation\n", .{});
}
