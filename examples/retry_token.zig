const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{RetryTokenExampleFailed};

fn clientPath(remote_port: u16) quicz.endpoint.Udp4Tuple {
    return .{
        .local = quicz.endpoint.Udp4Address.init(.{ 198, 51, 100, 1 }, 4433),
        .remote = quicz.endpoint.Udp4Address.init(.{ 203, 0, 113, 7 }, remote_port),
    };
}

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var server = try quicz.QuicConnection.init(allocator, .server, .{});
    defer server.deinit();
    var client = try quicz.QuicConnection.init(allocator, .client, .{});
    defer client.deinit();

    const token_secret: quicz.address_validation_token.Secret = [_]u8{0x42} ** quicz.address_validation_token.secret_len;
    const token_nonce: quicz.address_validation_token.Nonce = [_]u8{0x19} ** quicz.address_validation_token.nonce_len;
    const client_path = clientPath(50_000);
    const changed_client_path = clientPath(50_001);
    var token_policy = quicz.endpoint.AddressValidationPolicy.init(allocator, token_secret, .{
        .max_previous_secrets = 1,
        .max_replay_entries = 8,
    });
    defer token_policy.deinit();
    const retry_token = try token_policy.issueTokenForPath(
        allocator,
        .retry,
        0,
        60_000,
        client_path,
        token_nonce,
    );
    defer allocator.free(retry_token);
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_initial_scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const retry_scid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };

    const retry_datagram = try server.issueRetryDatagram(
        0,
        &original_dcid,
        &client_initial_scid,
        &retry_scid,
        retry_token,
    );
    defer allocator.free(retry_datagram);
    const retry_integrity_valid = try quicz.protection.verifyRetryIntegrityTag(allocator, &original_dcid, retry_datagram);
    if (!retry_integrity_valid) return error.RetryTokenExampleFailed;
    const v2_retry = quicz.packet.RetryPacket{
        .version = .v2,
        .dcid = &client_initial_scid,
        .scid = &retry_scid,
        .token = "token",
        .integrity_tag = [_]u8{0} ** quicz.protection.aead_tag_len,
    };
    const v2_retry_datagram = try quicz.protection.encodeRetryPacketWithIntegrity(
        allocator,
        &original_dcid,
        v2_retry,
    );
    defer allocator.free(v2_retry_datagram);
    const v2_retry_integrity_valid = try quicz.protection.verifyRetryIntegrityTag(allocator, &original_dcid, v2_retry_datagram);
    if (!v2_retry_integrity_valid) return error.RetryTokenExampleFailed;
    var parsed_v2_retry = try quicz.protection.parseRetryPacketWithIntegrity(allocator, &original_dcid, v2_retry_datagram);
    defer quicz.packet.deinitRetryPacket(&parsed_v2_retry, allocator);
    if (parsed_v2_retry.version != .v2) return error.RetryTokenExampleFailed;
    const server_original_dcid = server.originalDestinationConnectionId() orelse return error.RetryTokenExampleFailed;
    const server_retry_scid = server.retrySourceConnectionId() orelse return error.RetryTokenExampleFailed;
    if (!std.mem.eql(u8, server_original_dcid, &original_dcid)) return error.RetryTokenExampleFailed;
    if (!std.mem.eql(u8, server_retry_scid, &retry_scid)) return error.RetryTokenExampleFailed;

    try client.processRetryDatagram(0, &original_dcid, retry_datagram);
    const accepted_retry_token = client.latestRetryToken() orelse return error.RetryTokenExampleFailed;
    const accepted_original_dcid = client.originalDestinationConnectionId() orelse return error.RetryTokenExampleFailed;
    const accepted_retry_scid = client.retrySourceConnectionId() orelse return error.RetryTokenExampleFailed;
    if (!std.mem.eql(u8, accepted_original_dcid, &original_dcid)) return error.RetryTokenExampleFailed;
    if (!std.mem.eql(u8, accepted_retry_scid, &retry_scid)) return error.RetryTokenExampleFailed;

    client.applyPeerTransportParameters(.{}) catch |err| {
        if (err != error.InvalidPacket) return err;
    };
    try client.applyPeerTransportParameters(server.localTransportParameters());

    try server.sendPing();
    var tx: [16]u8 = undefined;
    if (try server.pollTx(0, &tx) != null) return error.RetryTokenExampleFailed;

    if (token_policy.validateTokenForPath(.retry, 10, changed_client_path, accepted_retry_token)) |_| {
        return error.RetryTokenExampleFailed;
    } else |err| {
        switch (err) {
            error.InvalidToken => {},
            else => return err,
        }
    }
    if (server.peerAddressValidated() or server.pendingRetryTokenCount() != 1) return error.RetryTokenExampleFailed;

    _ = try token_policy.validateTokenForPath(.retry, 10, client_path, accepted_retry_token);
    try server.validateRetryToken(accepted_retry_token);
    const payload = (try server.pollTx(11, &tx)) orelse return error.RetryTokenExampleFailed;
    if (!server.peerAddressValidated() or server.pendingRetryTokenCount() != 0) return error.RetryTokenExampleFailed;

    server.validateRetryToken(accepted_retry_token) catch |err| {
        if (err != error.InvalidPacket) return err;
    };

    std.debug.print(
        "[retry] token_len={} original_dcid_len={} retry_scid_len={} server_retry_scid_len={} address_bound={} path_bound={} tp_validated={} integrity={} v2_integrity={} address_validated={} ping_bytes={}\n",
        .{ accepted_retry_token.len, accepted_original_dcid.len, accepted_retry_scid.len, server_retry_scid.len, true, true, true, retry_integrity_valid, v2_retry_integrity_valid, server.peerAddressValidated(), payload.len },
    );
    std.debug.print("[retry] consumed token is not reusable\n", .{});
}
