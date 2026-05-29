const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{AddressValidationExampleFailed};

fn clientPath(remote_port: u16) quicz.endpoint.Udp4Tuple {
    return .{
        .local = quicz.endpoint.Udp4Address.init(.{ 198, 51, 100, 1 }, 4433),
        .remote = quicz.endpoint.Udp4Address.init(.{ 192, 0, 2, 9 }, remote_port),
    };
}

fn protectedTokenAndHandshakeDoneExample(allocator: std.mem.Allocator) !void {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);
    const previous_token_secret: quicz.address_validation_token.Secret = [_]u8{0xa5} ** quicz.address_validation_token.secret_len;
    const current_token_secret: quicz.address_validation_token.Secret = [_]u8{0x5c} ** quicz.address_validation_token.secret_len;
    const token_nonce: quicz.address_validation_token.Nonce = [_]u8{0x5a} ** quicz.address_validation_token.nonce_len;
    const v2_token_nonce: quicz.address_validation_token.Nonce = [_]u8{0x6b} ** quicz.address_validation_token.nonce_len;
    const client_path = clientPath(50_000);
    const changed_client_path = clientPath(50_001);
    var token_policy = quicz.endpoint.AddressValidationPolicy.init(allocator, previous_token_secret, .{
        .max_previous_secrets = 1,
        .max_replay_entries = 8,
    });
    defer token_policy.deinit();

    var server = try quicz.Connection.init(allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();
    var client = try quicz.Connection.init(allocator, .client, .{});
    defer client.deinit();

    try server.sendHandshakeDone();
    if (!server.packetNumberSpaceDiscarded(.handshake)) return error.AddressValidationExampleFailed;
    const address_token = try token_policy.issueTokenForPath(
        allocator,
        .new_token,
        10,
        60_000,
        client_path,
        token_nonce,
    );
    defer allocator.free(address_token);
    try server.issueNewToken(address_token);
    try token_policy.rotateSecret(current_token_secret);
    var secret_set = try token_policy.exportSecretSet(allocator);
    defer secret_set.deinit(allocator);
    var restored_policy = try quicz.endpoint.AddressValidationPolicy.initWithSecretSet(allocator, secret_set, .{
        .max_previous_secrets = 1,
        .max_replay_entries = 8,
    });
    defer restored_policy.deinit();
    if (restored_policy.previousSecretCount() != 1) return error.AddressValidationExampleFailed;

    const handshake_done = (try server.pollProtectedShortDatagram(10, &client_dcid, secrets.server)) orelse return error.AddressValidationExampleFailed;
    defer allocator.free(handshake_done);
    try client.processProtectedShortDatagram(11, secrets.server, client_dcid.len, handshake_done);
    if (!client.handshakeConfirmed()) return error.AddressValidationExampleFailed;

    const new_token = (try server.pollProtectedShortDatagram(12, &client_dcid, secrets.server)) orelse return error.AddressValidationExampleFailed;
    defer allocator.free(new_token);
    try client.processProtectedShortDatagram(13, secrets.server, client_dcid.len, new_token);
    const stored_token = client.latestNewToken() orelse return error.AddressValidationExampleFailed;

    var future_server = try quicz.Connection.init(allocator, .server, .{});
    defer future_server.deinit();
    try future_server.sendPing();
    var future_out: [16]u8 = undefined;
    if (try future_server.pollTx(14, &future_out) != null) return error.AddressValidationExampleFailed;
    if (restored_policy.validateTokenForPath(.new_token, 15, changed_client_path, stored_token)) |_| {
        return error.AddressValidationExampleFailed;
    } else |err| {
        switch (err) {
            error.InvalidToken => {},
            else => return err,
        }
    }
    _ = try restored_policy.validateTokenForPath(.new_token, 15, client_path, stored_token);
    try future_server.validatePeerAddress();
    const future_ping = (try future_server.pollTx(16, &future_out)) orelse return error.AddressValidationExampleFailed;
    if (!future_server.peerAddressValidated()) return error.AddressValidationExampleFailed;

    var replay_snapshot = try restored_policy.exportReplayFilter(allocator);
    defer replay_snapshot.deinit(allocator);
    var replay_restored_policy = try quicz.endpoint.AddressValidationPolicy.initWithSecretSetAndReplayFilter(allocator, secret_set, replay_snapshot, .{
        .max_previous_secrets = 1,
        .max_replay_entries = 8,
    });
    defer replay_restored_policy.deinit();
    if (replay_restored_policy.replayFilterEntryCount() != 1) return error.AddressValidationExampleFailed;

    var replay_rejected = false;
    if (replay_restored_policy.validateTokenForPath(.new_token, 17, client_path, stored_token)) |_| {
        return error.AddressValidationExampleFailed;
    } else |err| {
        switch (err) {
            error.TokenReplay => {
                replay_rejected = true;
            },
            else => return err,
        }
    }
    if (!replay_rejected) return error.AddressValidationExampleFailed;

    const v2_token = try restored_policy.issueTokenForPathForVersion(
        allocator,
        .new_token,
        .v2,
        18,
        60_000,
        client_path,
        v2_token_nonce,
    );
    defer allocator.free(v2_token);
    var version_rejected = false;
    if (restored_policy.validateTokenForPathForVersion(.new_token, .v1, 19, client_path, v2_token)) |_| {
        return error.AddressValidationExampleFailed;
    } else |err| {
        switch (err) {
            error.InvalidToken => {
                version_rejected = true;
            },
            else => return err,
        }
    }
    const v2_validation = try restored_policy.validateTokenForPathForVersion(.new_token, .v2, 19, client_path, v2_token);
    if (v2_validation.originating_version != .v2) return error.AddressValidationExampleFailed;

    std.debug.print("[address] protected_handshake_done bytes={} new_token_bytes={} stored_token_len={} server_handshake_discarded={} new_token_validated={} path_bound={} version_bound={} version_rejected={} secret_set_previous={} replay_entries={} replay_rejected={} future_ping_bytes={}\n", .{
        handshake_done.len,
        new_token.len,
        stored_token.len,
        server.packetNumberSpaceDiscarded(.handshake),
        future_server.peerAddressValidated(),
        true,
        true,
        version_rejected,
        secret_set.previous_secrets.len,
        replay_snapshot.fingerprints.len,
        replay_rejected,
        future_ping.len,
    });
}

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var server = try quicz.Connection.init(allocator, .server, .{});
    defer server.deinit();

    try server.sendPing();
    var out_buf: [32]u8 = undefined;
    if (try server.pollTx(0, &out_buf) != null) return error.AddressValidationExampleFailed;
    if (server.pending_ping_count != 1) return error.AddressValidationExampleFailed;

    std.debug.print("[address] unvalidated server blocked before received bytes\n", .{});

    try server.recordPeerAddressBytesReceived(1);
    const ping_payload = (try server.pollTx(1, &out_buf)) orelse return error.AddressValidationExampleFailed;
    if (ping_payload.len != 1) return error.AddressValidationExampleFailed;
    const remaining = server.antiAmplificationLimitRemaining() orelse return error.AddressValidationExampleFailed;

    std.debug.print("[address] recorded=1 sent={} remaining={}\n", .{ ping_payload.len, remaining });

    try server.sendCryptoInSpace(.handshake, "x");
    if (try server.pollTxInSpace(.handshake, 2, &out_buf) != null) return error.AddressValidationExampleFailed;

    try server.validatePeerAddress();
    const crypto_payload = (try server.pollTxInSpace(.handshake, 3, &out_buf)) orelse return error.AddressValidationExampleFailed;
    if (server.antiAmplificationLimitRemaining() != null) return error.AddressValidationExampleFailed;

    std.debug.print("[address] validation lifted limit crypto_bytes={}\n", .{crypto_payload.len});

    try protectedTokenAndHandshakeDoneExample(allocator);
}
