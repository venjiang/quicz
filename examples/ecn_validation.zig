const std = @import("std");
const quicz = @import("quicz");

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();
    const old_path = quicz.endpoint.Udp4Tuple{
        .local = quicz.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = quicz.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 50_000),
    };
    const migrated_path = quicz.endpoint.Udp4Tuple{
        .local = old_path.local,
        .remote = quicz.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 50_001),
    };
    var path_policy = quicz.endpoint.EcnPathPolicy.init(allocator);
    defer path_policy.deinit();

    var validated = try quicz.Connection.init(allocator, .client, .{});
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
    try path_policy.setStateForPath(old_path, .capable);
    std.debug.print(
        "[ecn] ECT0 ACK_ECN validated; bytes_in_flight={d}\n",
        .{validated.bytesInFlight(.application)},
    );
    if (path_policy.stateForPath(migrated_path) != .unknown) return error.EcnValidationExampleFailed;

    var failed = try quicz.Connection.init(allocator, .client, .{});
    defer failed.deinit();

    _ = try failed.recordEcnPacketSentInSpace(.application, 0, 1200, .ect0);
    try failed.receiveAckInSpace(.application, 50, .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    if (failed.ecnValidationState(.application) != .failed) return error.EcnValidationExampleFailed;
    try path_policy.setStateForPath(migrated_path, .failed);
    if (path_policy.stateForPath(old_path) != .capable) return error.EcnValidationExampleFailed;
    if (path_policy.mayUseEct(migrated_path)) return error.EcnValidationExampleFailed;
    std.debug.print("[ecn] missing ACK_ECN disabled ECN validation\n", .{});
    std.debug.print("[ecn] endpoint_path old={s} migrated={s}\n", .{
        @tagName(path_policy.stateForPath(old_path)),
        @tagName(path_policy.stateForPath(migrated_path)),
    });
}
