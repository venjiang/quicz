const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

fn require(condition: bool) !void {
    if (!condition) return error.UnexpectedState;
}

fn path(remote_port: u16) quicz.endpoint.Udp4Tuple {
    return .{
        .local = quicz.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = quicz.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, remote_port),
    };
}

pub fn main() !void {
    var router = quicz.endpoint.EndpointRouter.init(std.heap.page_allocator);
    defer router.deinit();

    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const reset_token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const client_path = path(50_000);
    try router.registerConnectionId(7, &server_dcid, client_path, .{
        .sequence_number = 0,
        .active_migration_disabled = true,
        .stateless_reset_token = reset_token,
    });

    const initial_datagram = [_]u8{
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x04, 0xaa, 0xbb, 0xcc, 0xdd,
        0x00,
    };
    const long_route = try router.routeDatagram(client_path, &initial_datagram);
    try require(long_route.connection_id == 7);
    try require(!long_route.path_changed);

    const short_datagram = [_]u8{ 0x40, 0xaa, 0xbb, 0xcc, 0xdd, 0x01 };
    const short_route = try router.routeDatagram(client_path, &short_datagram);
    try require(short_route.connection_id == 7);
    try require(short_route.sequence_number.? == 0);
    try require(std.mem.eql(u8, short_route.destination_connection_id.asSlice(), &server_dcid));

    const retry_original_dcid = [_]u8{ 0x90, 0x91, 0x92, 0x93 };
    const retry_source_cid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3 };
    const retry_path = path(50_006);
    const retry_original_datagram = [_]u8{
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x90, 0x91, 0x92, 0x93,
        0x00,
    };
    const retry_switched_datagram = [_]u8{
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x04, 0xa0, 0xa1, 0xa2, 0xa3,
        0x00,
    };
    try router.registerConnectionId(12, &retry_original_dcid, retry_path, .{});
    try require((try router.routeDatagram(retry_path, &retry_original_datagram)).connection_id == 12);
    const retry_switch = try router.switchInitialDestinationConnectionIdAfterRetry(
        &retry_original_dcid,
        &retry_source_cid,
        retry_path,
    );
    try require(retry_switch.connection_id == 12);
    try require(std.mem.eql(u8, retry_switch.destination_connection_id.asSlice(), &retry_source_cid));
    try require((try router.routeDatagram(retry_path, &retry_switched_datagram)).connection_id == 12);
    const retry_original_retired = if (router.routeDatagram(retry_path, &retry_original_datagram)) |_| false else |err| switch (err) {
        error.UnknownConnectionId => true,
        else => return err,
    };
    try require(retry_original_retired);

    const lifecycle_path = path(50_005);
    const lifecycle_dcid0 = [_]u8{ 0x70, 0x71, 0x72, 0x73 };
    const lifecycle_dcid1 = [_]u8{ 0x80, 0x81, 0x82, 0x83 };
    const lifecycle_token0 = [_]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const lifecycle_token1 = [_]u8{ 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47 };
    const lifecycle_datagram0 = [_]u8{ 0x40, 0x70, 0x71, 0x72, 0x73, 0x01 };
    const lifecycle_datagram1 = [_]u8{ 0x40, 0x80, 0x81, 0x82, 0x83, 0x01 };
    try router.registerConnectionId(10, &lifecycle_dcid0, lifecycle_path, .{
        .sequence_number = 0,
        .active_migration_disabled = true,
        .stateless_reset_token = lifecycle_token0,
    });
    const replacement = try router.registerReplacementConnectionId(10, &lifecycle_dcid1, lifecycle_path, 1, 1, .{
        .active_migration_disabled = true,
        .stateless_reset_token = lifecycle_token1,
    });
    const lifecycle_route = try router.routeDatagram(lifecycle_path, &lifecycle_datagram1);
    try require(lifecycle_route.connection_id == 10);
    try require(lifecycle_route.sequence_number.? == 1);
    const retired_before_one = replacement.retired_count;
    try require(replacement.retire_prior_to == 1);
    try require(retired_before_one == 1);
    try require((try router.statelessResetTokenForDatagram(lifecycle_path, &lifecycle_datagram0)) != null);
    try require((try router.routeDatagram(lifecycle_path, &lifecycle_datagram1)).sequence_number.? == 1);

    const migration_dcid = [_]u8{ 0x10, 0x11, 0x12, 0x13 };
    const migration_old_path = path(50_003);
    const migration_new_path = path(50_004);
    const migration_datagram = [_]u8{ 0x40, 0x10, 0x11, 0x12, 0x13, 0x01 };
    try router.registerConnectionId(9, &migration_dcid, migration_old_path, .{});
    const migration_probe = try router.routeDatagram(migration_new_path, &migration_datagram);
    try require(migration_probe.path_changed);
    const migration_update = try router.updateRoutePath(&migration_dcid, migration_old_path, migration_new_path);
    try require(!migration_update.path_changed);
    const migration_confirmed = try router.routeDatagram(migration_new_path, &migration_datagram);
    try require(!migration_confirmed.path_changed);

    const preferred_current_cid = [_]u8{ 0x30, 0x31, 0x32, 0x33 };
    const preferred_cid = [_]u8{ 0x34, 0x35, 0x36, 0x37 };
    const preferred_token = [_]u8{ 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53 };
    const preferred_old_path = path(50_007);
    const preferred_new_path = quicz.endpoint.Udp4Tuple{
        .local = quicz.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 8443),
        .remote = preferred_old_path.remote,
    };
    const preferred_current_datagram = [_]u8{ 0x40, 0x30, 0x31, 0x32, 0x33, 0x01 };
    const preferred_datagram = [_]u8{ 0x40, 0x34, 0x35, 0x36, 0x37, 0x01 };
    try router.registerConnectionId(13, &preferred_current_cid, preferred_old_path, .{});
    const preferred_route = try router.commitPreferredAddressMigration(
        &preferred_current_cid,
        preferred_old_path,
        &preferred_cid,
        preferred_new_path,
        preferred_token,
    );
    try require(preferred_route.connection_id == 13);
    try require(std.mem.eql(u8, preferred_route.destination_connection_id.asSlice(), &preferred_cid));
    try require((try router.routeDatagram(preferred_new_path, &preferred_datagram)).connection_id == 13);
    const preferred_old_retired = if (router.routeDatagram(preferred_old_path, &preferred_current_datagram)) |_| false else |err| switch (err) {
        error.UnknownConnectionId => true,
        else => return err,
    };
    try require(preferred_old_retired);

    const zero_cid = [_]u8{};
    const zero_path = path(50_002);
    try router.registerConnectionId(8, &zero_cid, zero_path, .{});
    const zero_cid_datagram = [_]u8{ 0x40, 0x01, 0x02, 0x03 };
    const zero_route = try router.routeDatagram(zero_path, &zero_cid_datagram);
    try require(zero_route.connection_id == 8);
    try require(zero_route.destination_connection_id.asSlice().len == 0);

    const migration_rejected = if (router.routeDatagram(path(50_001), &short_datagram)) |_| false else |err| switch (err) {
        error.ActiveMigrationDisabled => true,
        else => return err,
    };
    try require(migration_rejected);

    const retired = try router.retireConnectionId(&server_dcid);
    try require(retired);
    const retired_datagram = [_]u8{
        0x40, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    };
    const reset_for_retired = (try router.statelessResetTokenForDatagram(client_path, &retired_datagram)) orelse return error.UnexpectedState;
    try require(std.mem.eql(u8, &reset_for_retired, &reset_token));

    const reset_prefix = [_]u8{ 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde };
    var reset_out: [64]u8 = undefined;
    const reset_datagram = (try router.writeStatelessResetForDatagram(&reset_out, client_path, &retired_datagram, &reset_prefix)) orelse return error.UnexpectedState;
    try require(quicz.packet.matchesStatelessReset(reset_datagram, reset_token));
    try require(reset_datagram.len < retired_datagram.len);

    const routed_action = try router.handleDatagram(&reset_out, lifecycle_path, &lifecycle_datagram1, &reset_prefix);
    const action_routed = switch (routed_action) {
        .routed => |route| route.connection_id == 10 and route.sequence_number.? == 1,
        else => false,
    };
    try require(action_routed);

    const reset_action = try router.handleDatagram(&reset_out, client_path, &retired_datagram, &reset_prefix);
    const action_reset = switch (reset_action) {
        .stateless_reset => |reset| quicz.packet.matchesStatelessReset(reset, reset_token) and reset.len < retired_datagram.len,
        else => false,
    };
    try require(action_reset);

    const unknown_datagram = [_]u8{
        0x40, 0xee, 0xee, 0xee, 0xee, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    };
    const drop_action = try router.handleDatagram(&reset_out, client_path, &unknown_datagram, &reset_prefix);
    const action_dropped = switch (drop_action) {
        .dropped => true,
        else => false,
    };
    try require(action_dropped);

    const supported_versions = [_]quicz.packet.Version{ .v1, .v2 };
    const unsupported_version_datagram = [_]u8{
        0xc0, 0xfa, 0xce, 0xb0, 0x0c,
        0x02, 0xaa, 0xbb, 0x03, 0x11,
        0x22, 0x33, 0x00,
    };
    const version_negotiation_action = try router.handleDatagramWithVersionNegotiation(
        &reset_out,
        client_path,
        &unsupported_version_datagram,
        &reset_prefix,
        &supported_versions,
    );
    const version_negotiation_versions = switch (version_negotiation_action) {
        .version_negotiation => |response| blk: {
            var parsed = try quicz.packet.parseVersionNegotiationPacket(response, std.heap.page_allocator);
            defer quicz.packet.deinitVersionNegotiationPacket(&parsed, std.heap.page_allocator);
            try require(std.mem.eql(u8, parsed.dcid, &[_]u8{ 0x11, 0x22, 0x33 }));
            try require(std.mem.eql(u8, parsed.scid, &[_]u8{ 0xaa, 0xbb }));
            break :blk parsed.versions.len;
        },
        else => return error.UnexpectedState,
    };

    const accept_initial_datagram = [_]u8{
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x81, 0x82, 0x83, 0x84,
        0x85, 0x86, 0x87, 0x88, 0x04,
        0x91, 0x92, 0x93, 0x94, 0x02,
        0xa1, 0xa2, 0x02, 0x00, 0xff,
    };
    const accept_initial_action = try router.handleDatagramWithVersionNegotiation(
        &reset_out,
        path(50_008),
        &accept_initial_datagram,
        &reset_prefix,
        &supported_versions,
    );
    const action_accept_initial = switch (accept_initial_action) {
        .accept_initial => |accept| blk: {
            try require(accept.version == .v1);
            try require(std.mem.eql(u8, accept.original_destination_connection_id, &[_]u8{ 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88 }));
            try require(std.mem.eql(u8, accept.source_connection_id, &[_]u8{ 0x91, 0x92, 0x93, 0x94 }));
            try require(std.mem.eql(u8, accept.token, &[_]u8{ 0xa1, 0xa2 }));
            break :blk true;
        },
        else => false,
    };
    try require(action_accept_initial);

    std.debug.print("[endpoint] routed_long={} routed_short={} retry_switched={} preferred_migrated={} zero_cid={} cid_seq_retired={} path_changed={} path_updated={} migration_rejected={} retired={} stateless_reset={} reset_bytes={} action_routed={} action_reset={} action_dropped={} version_negotiation_versions={} action_accept_initial={} routes={}\n", .{
        long_route.connection_id,
        short_route.connection_id,
        retry_original_retired,
        preferred_old_retired,
        zero_route.connection_id,
        retired_before_one,
        short_route.path_changed,
        !migration_confirmed.path_changed,
        migration_rejected,
        retired,
        std.mem.eql(u8, &reset_for_retired, &reset_token),
        reset_datagram.len,
        action_routed,
        action_reset,
        action_dropped,
        version_negotiation_versions,
        action_accept_initial,
        router.routeCount(),
    });
}
