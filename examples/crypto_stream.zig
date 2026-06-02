const std = @import("std");
const quicz = @import("quicz");

const FixedWriter = struct {
    buffer: []u8,
    pos: usize = 0,

    pub fn writer(self: *FixedWriter) *FixedWriter {
        return self;
    }

    pub fn writeByte(self: *FixedWriter, byte: u8) !void {
        if (self.pos >= self.buffer.len) return error.NoSpaceLeft;
        self.buffer[self.pos] = byte;
        self.pos += 1;
    }

    pub fn writeAll(self: *FixedWriter, bytes: []const u8) !void {
        if (self.buffer.len - self.pos < bytes.len) return error.NoSpaceLeft;
        @memcpy(self.buffer[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    pub fn getWritten(self: FixedWriter) []const u8 {
        return self.buffer[0..self.pos];
    }
};

fn fixedWriter(buffer: []u8) FixedWriter {
    return .{ .buffer = buffer };
}

fn readCryptoRequired(
    conn: *quicz.Connection,
    space: quicz.PacketNumberSpace,
    out: []u8,
) ![]const u8 {
    const len = (try conn.recvCryptoInSpace(space, out)) orelse return error.UnexpectedState;
    return out[0..len];
}

fn appendCryptoPayload(
    allocator: std.mem.Allocator,
    payload: []const u8,
    out: []u8,
    out_len: *usize,
) !void {
    var payload_offset: usize = 0;
    while (payload_offset < payload.len) {
        var decoded = try quicz.frame.decodeFrameSlice(payload[payload_offset..], allocator);
        defer quicz.frame.deinitFrame(&decoded.frame, allocator);
        switch (decoded.frame) {
            .crypto => |crypto| {
                if (out.len - out_len.* < crypto.data.len) return error.NoSpaceLeft;
                @memcpy(out[out_len.*..][0..crypto.data.len], crypto.data);
                out_len.* += crypto.data.len;
            },
            .ack => {},
            else => return error.UnexpectedState,
        }
        payload_offset += decoded.len;
    }
}

fn appendProtectedShortCryptoPayload(
    allocator: std.mem.Allocator,
    keys: quicz.protection.Aes128PacketProtectionKeys,
    datagram: []const u8,
    dcid_len: usize,
    packet_number: u64,
    out: []u8,
    out_len: *usize,
) !void {
    var opened = try quicz.protection.unprotectShortPacketAes128(
        allocator,
        keys,
        datagram,
        dcid_len,
        packet_number,
    );
    defer quicz.protection.deinitProtectedShortPacket(&opened, allocator);
    try appendCryptoPayload(allocator, opened.packet.plaintext, out, out_len);
}

fn expectStreamClosed(
    conn: *quicz.Connection,
    stream_id: u64,
    out: []u8,
) !void {
    _ = conn.recvOnStream(stream_id, out) catch |err| {
        if (err == error.StreamClosed) return;
        return err;
    };
    return error.UnexpectedState;
}

fn processCryptoFrame(
    conn: *quicz.Connection,
    space: quicz.PacketNumberSpace,
    now_millis: i64,
    offset: u64,
    data: []const u8,
) !void {
    var raw: [96]u8 = undefined;
    var writer = fixedWriter(&raw);
    try quicz.frame.encodeFrame(writer.writer(), .{ .crypto = .{
        .offset = offset,
        .data = data,
    } });
    try conn.processDatagramInSpace(space, now_millis, writer.getWritten());
}

const MockCryptoBackend = struct {
    inbound: [64]u8 = undefined,
    inbound_len: usize = 0,
    outbound: []const u8,
    outbound_offset: usize = 0,
    local_transport_parameters_len: usize = 0,
    peer_transport_parameters: []const u8 = &[_]u8{},
    peer_transport_parameters_sent: bool = false,
    handshake_traffic_secrets: ?quicz.HandshakeTrafficSecrets = null,
    handshake_traffic_secrets_sent: bool = false,
    zero_rtt_traffic_secrets: ?quicz.ZeroRttTrafficSecrets = null,
    zero_rtt_traffic_secrets_sent: bool = false,
    traffic_secrets: ?quicz.OneRttTrafficSecrets = null,
    traffic_secrets_sent: bool = false,
    confirmed: bool = false,

    fn backend(self: *MockCryptoBackend) quicz.CryptoBackend {
        return .{
            .context = self,
            .receive = receive,
            .pull = pull,
            .set_local_transport_parameters = setLocalTransportParameters,
            .pull_peer_transport_parameters = pullPeerTransportParameters,
            .pull_handshake_traffic_secrets = pullHandshakeTrafficSecrets,
            .pull_zero_rtt_traffic_secrets = pullZeroRttTrafficSecrets,
            .pull_1rtt_traffic_secrets = pullOneRttTrafficSecrets,
            .handshake_confirmed = handshakeConfirmed,
        };
    }

    fn receive(context: *anyopaque, space: quicz.PacketNumberSpace, data: []const u8) quicz.Error!void {
        const self: *MockCryptoBackend = @ptrCast(@alignCast(context));
        if (space != .handshake) return error.CryptoError;
        if (self.inbound.len - self.inbound_len < data.len) return error.BufferTooSmall;
        @memcpy(self.inbound[self.inbound_len..][0..data.len], data);
        self.inbound_len += data.len;
        self.confirmed = std.mem.eql(u8, self.inbound[0..self.inbound_len], "client hello");
    }

    fn pull(context: *anyopaque, space: quicz.PacketNumberSpace, out_buf: []u8) quicz.Error!?[]const u8 {
        const self: *MockCryptoBackend = @ptrCast(@alignCast(context));
        if (space != .handshake or self.outbound_offset >= self.outbound.len) return null;
        const n = @min(out_buf.len, self.outbound.len - self.outbound_offset);
        @memcpy(out_buf[0..n], self.outbound[self.outbound_offset..][0..n]);
        self.outbound_offset += n;
        return out_buf[0..n];
    }

    fn setLocalTransportParameters(context: *anyopaque, data: []const u8) quicz.Error!void {
        const self: *MockCryptoBackend = @ptrCast(@alignCast(context));
        self.local_transport_parameters_len = data.len;
    }

    fn pullPeerTransportParameters(context: *anyopaque, out_buf: []u8) quicz.Error!?[]const u8 {
        const self: *MockCryptoBackend = @ptrCast(@alignCast(context));
        if (self.peer_transport_parameters_sent or self.peer_transport_parameters.len == 0) return null;
        if (out_buf.len < self.peer_transport_parameters.len) return error.BufferTooSmall;
        @memcpy(out_buf[0..self.peer_transport_parameters.len], self.peer_transport_parameters);
        self.peer_transport_parameters_sent = true;
        return out_buf[0..self.peer_transport_parameters.len];
    }

    fn pullHandshakeTrafficSecrets(context: *anyopaque) quicz.Error!?quicz.HandshakeTrafficSecrets {
        const self: *MockCryptoBackend = @ptrCast(@alignCast(context));
        if (self.handshake_traffic_secrets_sent) return null;
        const secrets = self.handshake_traffic_secrets orelse return null;
        self.handshake_traffic_secrets_sent = true;
        return secrets;
    }

    fn pullZeroRttTrafficSecrets(context: *anyopaque) quicz.Error!?quicz.ZeroRttTrafficSecrets {
        const self: *MockCryptoBackend = @ptrCast(@alignCast(context));
        if (self.zero_rtt_traffic_secrets_sent) return null;
        const secrets = self.zero_rtt_traffic_secrets orelse return null;
        self.zero_rtt_traffic_secrets_sent = true;
        return secrets;
    }

    fn pullOneRttTrafficSecrets(context: *anyopaque) quicz.Error!?quicz.OneRttTrafficSecrets {
        const self: *MockCryptoBackend = @ptrCast(@alignCast(context));
        if (self.traffic_secrets_sent) return null;
        const secrets = self.traffic_secrets orelse return null;
        self.traffic_secrets_sent = true;
        return secrets;
    }

    fn handshakeConfirmed(context: *anyopaque) bool {
        const self: *MockCryptoBackend = @ptrCast(@alignCast(context));
        return self.confirmed;
    }
};

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const initial_secrets = try quicz.protection.deriveInitialSecrets(.v1, &dcid);

    var client = try quicz.Connection.init(gpa, .client, .{});
    defer client.deinit();
    var server = try quicz.Connection.init(gpa, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    var crypto_buf: [128]u8 = undefined;

    var reassembly = try quicz.Connection.init(gpa, .server, .{});
    defer reassembly.deinit();
    try processCryptoFrame(&reassembly, .handshake, 100, 6, "flight");
    try processCryptoFrame(&reassembly, .handshake, 101, 6, "flight");
    if ((try reassembly.recvCryptoInSpace(.handshake, &crypto_buf)) != null) return error.UnexpectedState;
    try processCryptoFrame(&reassembly, .handshake, 102, 0, "hello ");
    const reassembled_crypto = try readCryptoRequired(&reassembly, .handshake, &crypto_buf);
    std.debug.print("[crypto] out_of_order_handshake data={s} state={s} duplicate_ignored=true pending_ack={?}\n", .{
        reassembled_crypto,
        @tagName(reassembly.handshakeState()),
        reassembly.pendingAckLargest(.handshake),
    });

    var crypto_limit = try quicz.Connection.init(gpa, .server, .{ .max_crypto_buffer_size = 5 });
    defer crypto_limit.deinit();
    try crypto_limit.validatePeerAddress();
    var limit_payload_buf: [32]u8 = undefined;
    var limit_out = fixedWriter(&limit_payload_buf);
    try quicz.frame.encodeFrame(limit_out.writer(), .{ .crypto = .{
        .offset = 3,
        .data = "abc",
    } });
    if (crypto_limit.processDatagramInSpaceOrClose(.handshake, 110, limit_out.getWritten())) |_| {
        return error.UnexpectedState;
    } else |err| {
        if (err != error.InvalidPacket) return err;
    }
    var limit_close_buf: [64]u8 = undefined;
    const limit_close_payload = (try crypto_limit.pollTx(111, &limit_close_buf)) orelse return error.UnexpectedState;
    var limit_close = try quicz.frame.decodeFrameSlice(limit_close_payload, gpa);
    defer quicz.frame.deinitFrame(&limit_close.frame, gpa);
    switch (limit_close.frame) {
        .connection_close => |close| {
            if (close.error_code != quicz.transport_error.codeValue(.crypto_buffer_exceeded)) return error.UnexpectedState;
            std.debug.print("[crypto] buffer_limit close_error={} frame_type={} reason={s} state={s}\n", .{
                close.error_code,
                close.frame_type,
                close.reason_phrase,
                @tagName(crypto_limit.connectionState()),
            });
        },
        else => return error.UnexpectedState,
    }

    var crypto_loss = try quicz.Connection.init(gpa, .client, .{});
    defer crypto_loss.deinit();
    try crypto_loss.sendCryptoInSpace(.handshake, "lost crypto");
    var loss_payload_buf: [96]u8 = undefined;
    _ = (try crypto_loss.pollTxInSpace(.handshake, 10, &loss_payload_buf)) orelse return error.UnexpectedState;
    _ = try crypto_loss.recordPacketSentInSpace(.handshake, 20, 1);
    _ = try crypto_loss.recordPacketSentInSpace(.handshake, 30, 1);
    _ = try crypto_loss.recordPacketSentInSpace(.handshake, 40, 1);
    try crypto_loss.receiveAckInSpace(.handshake, 70, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    const crypto_retransmit = (try crypto_loss.pollTxInSpace(.handshake, 80, &loss_payload_buf)) orelse return error.UnexpectedState;
    var retransmit_crypto: [32]u8 = undefined;
    var retransmit_crypto_len: usize = 0;
    try appendCryptoPayload(gpa, crypto_retransmit, &retransmit_crypto, &retransmit_crypto_len);
    std.debug.print("[crypto] loss_recovery retransmit={s} remaining={} inflight={}\n", .{
        retransmit_crypto[0..retransmit_crypto_len],
        crypto_loss.sentPacketCount(.handshake),
        crypto_loss.bytesInFlight(.handshake),
    });

    var protected_crypto_loss = try quicz.Connection.init(gpa, .client, .{});
    defer protected_crypto_loss.deinit();
    try protected_crypto_loss.sendCrypto("lost protected crypto");
    const lost_protected_crypto = (try protected_crypto_loss.pollProtectedShortDatagram(
        10,
        &server_scid,
        initial_secrets.client,
    )) orelse return error.UnexpectedState;
    defer gpa.free(lost_protected_crypto);
    _ = try protected_crypto_loss.recordPacketSentInSpace(.application, 20, 1);
    _ = try protected_crypto_loss.recordPacketSentInSpace(.application, 30, 1);
    _ = try protected_crypto_loss.recordPacketSentInSpace(.application, 40, 1);
    try protected_crypto_loss.receiveAckInSpace(.application, 70, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    const protected_crypto_retransmit = (try protected_crypto_loss.pollProtectedShortDatagram(
        80,
        &server_scid,
        initial_secrets.client,
    )) orelse return error.UnexpectedState;
    defer gpa.free(protected_crypto_retransmit);
    var protected_retransmit_crypto: [64]u8 = undefined;
    var protected_retransmit_crypto_len: usize = 0;
    try appendProtectedShortCryptoPayload(
        gpa,
        initial_secrets.client,
        protected_crypto_retransmit,
        server_scid.len,
        4,
        &protected_retransmit_crypto,
        &protected_retransmit_crypto_len,
    );
    std.debug.print("[crypto] protected_loss_recovery retransmit={s} remaining={} inflight={}\n", .{
        protected_retransmit_crypto[0..protected_retransmit_crypto_len],
        protected_crypto_loss.sentPacketCount(.application),
        protected_crypto_loss.bytesInFlight(.application),
    });

    var bridged = try quicz.Connection.init(gpa, .server, .{});
    defer bridged.deinit();
    try processCryptoFrame(&bridged, .handshake, 103, 6, " hello");
    try processCryptoFrame(&bridged, .handshake, 104, 0, "client");

    var backend_peer_tp_buf: [128]u8 = undefined;
    var backend_peer_tp_out = fixedWriter(&backend_peer_tp_buf);
    try quicz.transport_parameters.encode(backend_peer_tp_out.writer(), .{
        .initial_max_data = 4096,
        .initial_max_stream_data_bidi_local = 2048,
        .initial_max_stream_data_bidi_remote = 2048,
        .initial_max_stream_data_uni = 1024,
        .initial_max_streams_bidi = 4,
        .initial_max_streams_uni = 2,
    });

    var backend = MockCryptoBackend{
        .outbound = "server flight",
        .peer_transport_parameters = backend_peer_tp_out.getWritten(),
        .handshake_traffic_secrets = .{
            .local = initial_secrets.server.secret,
            .peer = initial_secrets.client.secret,
        },
        .zero_rtt_traffic_secrets = .{
            .peer = initial_secrets.client.secret,
        },
        .traffic_secrets = .{
            .local = initial_secrets.server.secret,
            .peer = initial_secrets.client.secret,
        },
    };
    var backend_scratch: [128]u8 = undefined;
    const backend_progress = try bridged.driveCryptoBackendInSpace(.handshake, backend.backend(), &backend_scratch);
    try bridged.validatePeerAddress();
    var backend_payload_buf: [96]u8 = undefined;
    var backend_output: [32]u8 = undefined;
    var backend_output_len: usize = 0;
    while (!bridged.packetNumberSpaceDiscarded(.handshake)) {
        const payload = (try bridged.pollTxInSpace(.handshake, 105, &backend_payload_buf)) orelse break;
        try appendCryptoPayload(gpa, payload, &backend_output, &backend_output_len);
    }
    std.debug.print("[crypto] backend_bridge inbound={s} outbound={s} in_chunks={} out_chunks={} local_tp={} peer_tp={} peer_tp_applied={} handshake_keys={} zero_rtt_keys={} one_rtt_keys={} confirmed={} state={s}\n", .{
        backend.inbound[0..backend.inbound_len],
        backend_output[0..backend_output_len],
        backend_progress.inbound_chunks,
        backend_progress.outbound_chunks,
        backend_progress.local_transport_parameters_bytes,
        backend_progress.peer_transport_parameters_bytes,
        backend_progress.peer_transport_parameters_applied,
        backend_progress.handshake_keys_installed,
        backend_progress.zero_rtt_keys_installed,
        backend_progress.one_rtt_keys_installed,
        backend_progress.handshake_confirmed,
        @tagName(bridged.handshakeState()),
    });

    const compatible_client_versions = [_]quicz.packet.Version{ .v1, .v2 };
    const compatible_server_versions = [_]quicz.packet.Version{ .v2, .v1 };
    const compatibilities = [_]quicz.VersionCompatibility{.{
        .original_version = .v1,
        .negotiated_version = .v2,
    }};
    var compatible_peer_tp_buf: [128]u8 = undefined;
    var compatible_peer_tp_out = fixedWriter(&compatible_peer_tp_buf);
    try quicz.transport_parameters.encode(compatible_peer_tp_out.writer(), .{
        .initial_max_data = 8192,
        .version_information = .{
            .chosen_version = .v1,
            .available_versions = &compatible_client_versions,
        },
    });
    var compatible_server = try quicz.Connection.init(gpa, .server, .{
        .chosen_version = .v2,
        .available_versions = &compatible_server_versions,
    });
    defer compatible_server.deinit();
    var compatible_backend = MockCryptoBackend{
        .outbound = "",
        .peer_transport_parameters = compatible_peer_tp_out.getWritten(),
    };
    const compatible_progress = try compatible_server.driveCryptoBackendInSpaceWithCompatibleVersion(
        .handshake,
        compatible_backend.backend(),
        &backend_scratch,
        &compatibilities,
    );
    const compatible_selected = compatible_progress.peer_compatible_version_selected orelse return error.UnexpectedState;
    const compatible_peer = compatible_server.peerVersionInformation() orelse return error.UnexpectedState;
    std.debug.print("[crypto] backend_compatible_version selected=0x{x} peer_versions={} peer_tp_applied={} peer_max_data={}\n", .{
        @intFromEnum(compatible_selected),
        compatible_peer.available_versions.len,
        compatible_progress.peer_transport_parameters_applied,
        compatible_server.peer_max_data,
    });

    var confirmed_no_output = try quicz.Connection.init(gpa, .server, .{});
    defer confirmed_no_output.deinit();
    try processCryptoFrame(&confirmed_no_output, .handshake, 106, 0, "client hello");
    var confirmed_backend = MockCryptoBackend{
        .outbound = "",
        .handshake_traffic_secrets = .{
            .local = initial_secrets.server.secret,
            .peer = initial_secrets.client.secret,
        },
    };
    const confirmed_progress = try confirmed_no_output.driveCryptoBackendInSpace(
        .handshake,
        confirmed_backend.backend(),
        &backend_scratch,
    );
    if (!confirmed_no_output.packetNumberSpaceDiscarded(.handshake)) return error.UnexpectedState;
    std.debug.print("[crypto] backend_confirmed_no_output confirmed={} discarded={} handshake_keys_installed={} keys_present={}\n", .{
        confirmed_progress.handshake_confirmed,
        confirmed_no_output.packetNumberSpaceDiscarded(.handshake),
        confirmed_progress.handshake_keys_installed,
        confirmed_no_output.hasHandshakeProtectionKeys(),
    });

    var confirmed_with_output = try quicz.Connection.init(gpa, .server, .{});
    defer confirmed_with_output.deinit();
    try confirmed_with_output.validatePeerAddress();
    try processCryptoFrame(&confirmed_with_output, .handshake, 107, 0, "client hello");
    var confirmed_output_backend = MockCryptoBackend{
        .outbound = "server finished",
        .handshake_traffic_secrets = .{
            .local = initial_secrets.server.secret,
            .peer = initial_secrets.client.secret,
        },
    };
    const confirmed_output_progress = try confirmed_with_output.driveCryptoBackendInSpace(
        .handshake,
        confirmed_output_backend.backend(),
        &backend_scratch,
    );
    if (confirmed_with_output.packetNumberSpaceDiscarded(.handshake)) return error.UnexpectedState;
    const keys_before_confirmed_output_send = confirmed_with_output.hasHandshakeProtectionKeys();
    var confirmed_output_buf: [96]u8 = undefined;
    var confirmed_output_crypto: [32]u8 = undefined;
    var confirmed_output_crypto_len: usize = 0;
    const confirmed_output_payload = (try confirmed_with_output.pollTxInSpace(
        .handshake,
        108,
        &confirmed_output_buf,
    )) orelse return error.UnexpectedState;
    try appendCryptoPayload(gpa, confirmed_output_payload, &confirmed_output_crypto, &confirmed_output_crypto_len);
    if (!confirmed_with_output.packetNumberSpaceDiscarded(.handshake)) return error.UnexpectedState;
    std.debug.print("[crypto] backend_confirmed_with_output outbound={s} confirmed={} keys_before_send={} discarded_after_send={} keys_present={}\n", .{
        confirmed_output_crypto[0..confirmed_output_crypto_len],
        confirmed_output_progress.handshake_confirmed,
        keys_before_confirmed_output_send,
        confirmed_with_output.packetNumberSpaceDiscarded(.handshake),
        confirmed_with_output.hasHandshakeProtectionKeys(),
    });

    var close_on_bad_tp = try quicz.Connection.init(gpa, .server, .{});
    defer close_on_bad_tp.deinit();
    try close_on_bad_tp.validatePeerAddress();
    try close_on_bad_tp.installHandshakeTrafficSecrets(.{
        .local = initial_secrets.server.secret,
        .peer = initial_secrets.client.secret,
    });
    var close_client = try quicz.Connection.init(gpa, .client, .{});
    defer close_client.deinit();
    try close_client.installHandshakeTrafficSecrets(.{
        .local = initial_secrets.client.secret,
        .peer = initial_secrets.server.secret,
    });
    var invalid_peer_tp = [_]u8{0x04};
    var closing_backend = MockCryptoBackend{
        .outbound = "blocked backend output",
        .peer_transport_parameters = &invalid_peer_tp,
    };
    if (close_on_bad_tp.driveCryptoBackendInSpaceOrClose(.handshake, closing_backend.backend(), &backend_scratch)) |_| {
        return error.UnexpectedState;
    } else |err| {
        if (err != error.InvalidPacket) return err;
    }
    if (closing_backend.outbound_offset != 0) return error.UnexpectedState;
    const close_packet = (try close_on_bad_tp.pollProtectedHandshakeDatagramWithInstalledKeys(
        110,
        &client_scid,
        &server_scid,
    )) orelse return error.UnexpectedState;
    defer gpa.free(close_packet);
    try close_client.processProtectedHandshakeDatagramWithInstalledKeys(111, close_packet);
    switch (close_client.peerClose() orelse return error.UnexpectedState) {
        .connection => |close| {
            if (close.error_code != quicz.transport_error.codeValue(.transport_parameter_error)) return error.UnexpectedState;
            if (close.frame_type != @intFromEnum(quicz.frame.FrameType.crypto)) return error.UnexpectedState;
            std.debug.print("[crypto] backend_tp_protected_close bytes={} error={} frame_type={} reason={s} output_pulled={} sender={s} receiver={s}\n", .{
                close_packet.len,
                close.error_code,
                close.frame_type,
                close.reason_phrase,
                closing_backend.outbound_offset != 0,
                @tagName(close_on_bad_tp.connectionState()),
                @tagName(close_client.connectionState()),
            });
        },
        else => return error.UnexpectedState,
    }

    var installed_client = try quicz.Connection.init(gpa, .client, .{});
    defer installed_client.deinit();
    var installed_server = try quicz.Connection.init(gpa, .server, .{});
    defer installed_server.deinit();
    try installed_server.validatePeerAddress();

    var installed_client_backend = MockCryptoBackend{
        .outbound = "",
        .handshake_traffic_secrets = .{
            .local = initial_secrets.client.secret,
            .peer = initial_secrets.server.secret,
        },
        .zero_rtt_traffic_secrets = .{
            .local = initial_secrets.client.secret,
        },
    };
    var installed_server_backend = MockCryptoBackend{
        .outbound = "",
        .handshake_traffic_secrets = .{
            .local = initial_secrets.server.secret,
            .peer = initial_secrets.client.secret,
        },
        .zero_rtt_traffic_secrets = .{
            .peer = initial_secrets.client.secret,
        },
        .traffic_secrets = .{
            .local = initial_secrets.server.secret,
            .peer = initial_secrets.client.secret,
        },
    };
    _ = try installed_client.driveCryptoBackendInSpace(.handshake, installed_client_backend.backend(), &backend_scratch);
    _ = try installed_server.driveCryptoBackendInSpace(.handshake, installed_server_backend.backend(), &backend_scratch);

    const installed_early_stream = try installed_client.openStream();
    try installed_client.sendOnStream(installed_early_stream, "installed early", true);
    const installed_zero_rtt = (try installed_client.pollProtectedZeroRttDatagramWithInstalledKeys(
        102,
        &server_scid,
        &client_scid,
    )) orelse return error.UnexpectedState;
    defer gpa.free(installed_zero_rtt);
    try installed_server.acceptZeroRtt();
    try installed_server.processProtectedZeroRttDatagramWithInstalledKeys(103, installed_zero_rtt);
    var installed_early_buf: [32]u8 = undefined;
    const installed_early_len = (try installed_server.recvOnStream(installed_early_stream, &installed_early_buf)) orelse return error.UnexpectedState;
    var installed_client_1rtt_backend = MockCryptoBackend{
        .outbound = "",
        .traffic_secrets = .{
            .local = initial_secrets.client.secret,
            .peer = initial_secrets.server.secret,
        },
    };
    _ = try installed_client.driveCryptoBackendInSpace(.handshake, installed_client_1rtt_backend.backend(), &backend_scratch);
    if (installed_client.hasLocalZeroRttProtectionKey()) return error.UnexpectedState;
    const installed_zero_ack = (try installed_server.pollProtectedShortDatagramWithInstalledKeys(
        104,
        &client_scid,
    )) orelse return error.UnexpectedState;
    defer gpa.free(installed_zero_ack);
    try installed_client.processProtectedShortDatagramWithInstalledKeys(105, client_scid.len, installed_zero_ack);
    std.debug.print("[crypto] installed_0rtt_keys data={s} bytes={} ack_bytes={} client_inflight={} client_zero_keys={} server_zero_keys={} accepted={}\n", .{
        installed_early_buf[0..installed_early_len],
        installed_zero_rtt.len,
        installed_zero_ack.len,
        installed_client.bytesInFlight(.application),
        installed_client.hasLocalZeroRttProtectionKey(),
        installed_server.hasPeerZeroRttProtectionKey(),
        installed_server.zeroRttAccepted(),
    });

    try installed_server.sendCryptoInSpace(.handshake, "installed handshake");
    const installed_handshake = (try installed_server.pollProtectedHandshakeDatagramWithInstalledKeys(
        106,
        &client_scid,
        &server_scid,
    )) orelse return error.UnexpectedState;
    defer gpa.free(installed_handshake);
    try installed_client.processProtectedHandshakeDatagramWithInstalledKeys(107, installed_handshake);
    const installed_handshake_data = try readCryptoRequired(&installed_client, .handshake, &crypto_buf);
    std.debug.print("[crypto] installed_handshake_keys data={s} bytes={} pending_ack={?}\n", .{
        installed_handshake_data,
        installed_handshake.len,
        installed_client.pendingAckLargest(.handshake),
    });

    try installed_client.confirmHandshake();
    try installed_server.confirmHandshake();
    try installed_client.initiateOneRttKeyUpdate();
    try installed_client.sendPing();
    const installed_ping = (try installed_client.pollProtectedShortDatagramWithInstalledKeys(
        108,
        &server_scid,
    )) orelse return error.UnexpectedState;
    defer gpa.free(installed_ping);
    const installed_key_phase = try quicz.protection.peekShortPacketKeyPhaseAes128(initial_secrets.client.hp, installed_ping, server_scid.len);
    try installed_server.processProtectedShortDatagramWithInstalledKeys(109, server_scid.len, installed_ping);
    std.debug.print("[crypto] installed_1rtt_keys ping_bytes={} key_phase={} server_peer_phase={} pending_ack={?} server_zero_keys={}\n", .{
        installed_ping.len,
        installed_key_phase,
        installed_server.peerOneRttKeyPhase().?,
        installed_server.pendingAckLargest(.application),
        installed_server.hasPeerZeroRttProtectionKey(),
    });

    try client.sendCryptoInSpace(.initial, "client initial flight");
    const protected_initial = (try client.pollInitialProtectedDatagram(
        0,
        &dcid,
        &client_scid,
        &[_]u8{},
        initial_secrets.client,
    )) orelse return error.UnexpectedState;
    defer gpa.free(protected_initial);
    const client_original_dcid = client.originalDestinationConnectionId() orelse return error.UnexpectedState;
    if (!std.mem.eql(u8, client_original_dcid, &dcid)) return error.UnexpectedState;
    const client_local_initial_scid = client.localTransportParameters().initial_source_connection_id orelse return error.UnexpectedState;
    if (!std.mem.eql(u8, client_local_initial_scid, &client_scid)) return error.UnexpectedState;
    try server.processInitialProtectedDatagram(1, initial_secrets.client, protected_initial);
    const initial_bytes = try readCryptoRequired(&server, .initial, &crypto_buf);
    std.debug.print("[crypto] protected_initial recv={s} original_dcid_len={} local_initial_scid_len={} pending_ack={?}\n", .{
        initial_bytes,
        client_original_dcid.len,
        client_local_initial_scid.len,
        server.pendingAckLargest(.initial),
    });

    try server.sendCryptoInSpace(.initial, "server initial flight");
    try server.sendCryptoInSpace(.handshake, "server handshake flight");
    const coalesced = (try server.pollProtectedLongDatagram(
        2,
        &client_scid,
        &server_scid,
        &[_]u8{},
        .{
            .initial = initial_secrets.server,
            .handshake = initial_secrets.server,
        },
    )) orelse return error.UnexpectedState;
    defer gpa.free(coalesced);

    const coalesced_count = try client.processProtectedLongDatagram(3, .{
        .initial = initial_secrets.server,
        .handshake = initial_secrets.server,
    }, coalesced);

    var server_initial_buf: [128]u8 = undefined;
    const server_initial_bytes = try readCryptoRequired(&client, .initial, &server_initial_buf);
    var server_handshake_buf: [128]u8 = undefined;
    const handshake_bytes = try readCryptoRequired(&client, .handshake, &server_handshake_buf);
    const server_initial_scid = client.peerInitialSourceConnectionId() orelse return error.UnexpectedState;
    if (!std.mem.eql(u8, server_initial_scid, &server_scid)) return error.UnexpectedState;
    const server_params = server.localTransportParameters();
    const server_original_dcid = server_params.original_destination_connection_id orelse return error.UnexpectedState;
    if (!std.mem.eql(u8, server_original_dcid, &dcid)) return error.UnexpectedState;
    const server_local_initial_scid = server_params.initial_source_connection_id orelse return error.UnexpectedState;
    if (!std.mem.eql(u8, server_local_initial_scid, &server_scid)) return error.UnexpectedState;
    client.applyPeerTransportParameters(.{}) catch |err| {
        if (err != error.InvalidPacket) return err;
    };
    try client.applyPeerTransportParameters(server_params);
    std.debug.print("[crypto] coalesced_server packets={} initial={s} handshake={s} original_dcid_len={} peer_initial_scid_len={} local_initial_scid_len={} pending_initial={?} pending_handshake={?}\n", .{
        coalesced_count,
        server_initial_bytes,
        handshake_bytes,
        server_original_dcid.len,
        server_initial_scid.len,
        server_local_initial_scid.len,
        client.pendingAckLargest(.initial),
        client.pendingAckLargest(.handshake),
    });

    try client.sendPingInSpace(.handshake);
    const client_ack_probe = (try client.pollProtectedLongDatagram(
        5,
        &server_scid,
        &client_scid,
        &[_]u8{},
        .{
            .initial = initial_secrets.client,
            .handshake = initial_secrets.client,
        },
    )) orelse return error.UnexpectedState;
    defer gpa.free(client_ack_probe);
    const ack_probe_count = try server.processProtectedLongDatagram(6, .{
        .initial = initial_secrets.client,
        .handshake = initial_secrets.client,
    }, client_ack_probe);
    std.debug.print("[crypto] coalesced_client_probe packets={} server_initial_inflight={} server_handshake_inflight={} pending_handshake_ack={?}\n", .{
        ack_probe_count,
        server.sentPacketCount(.initial),
        server.sentPacketCount(.handshake),
        server.pendingAckLargest(.handshake),
    });

    try client.confirmHandshake();
    try server.confirmHandshake();
    std.debug.print("[crypto] handshake_state client={s} server={s} confirmed={}\n", .{
        @tagName(client.handshakeState()),
        @tagName(server.handshakeState()),
        client.handshakeConfirmed(),
    });

    try client.sendPing();
    const one_rtt_ping = (try client.pollProtectedShortDatagram(
        7,
        &server_scid,
        initial_secrets.client,
    )) orelse return error.UnexpectedState;
    defer gpa.free(one_rtt_ping);
    try server.processProtectedShortDatagram(8, initial_secrets.client, server_scid.len, one_rtt_ping);

    const one_rtt_ack = (try server.pollProtectedShortDatagram(
        9,
        &client_scid,
        initial_secrets.server,
    )) orelse return error.UnexpectedState;
    defer gpa.free(one_rtt_ack);
    try client.processProtectedShortDatagram(10, initial_secrets.server, client_scid.len, one_rtt_ack);
    std.debug.print("[crypto] protected_1rtt ping_bytes={} ack_bytes={} client_inflight={} server_pending_ack={?}\n", .{
        one_rtt_ping.len,
        one_rtt_ack.len,
        client.bytesInFlight(.application),
        server.pendingAckLargest(.application),
    });

    try client.sendCrypto("protected application crypto");
    const one_rtt_crypto = (try client.pollProtectedShortDatagram(
        11,
        &server_scid,
        initial_secrets.client,
    )) orelse return error.UnexpectedState;
    defer gpa.free(one_rtt_crypto);
    try server.processProtectedShortDatagram(12, initial_secrets.client, server_scid.len, one_rtt_crypto);

    var one_rtt_crypto_buf: [64]u8 = undefined;
    const one_rtt_crypto_bytes = try readCryptoRequired(&server, .application, &one_rtt_crypto_buf);
    const one_rtt_crypto_ack = (try server.pollProtectedShortDatagram(
        13,
        &client_scid,
        initial_secrets.server,
    )) orelse return error.UnexpectedState;
    defer gpa.free(one_rtt_crypto_ack);
    try client.processProtectedShortDatagram(14, initial_secrets.server, client_scid.len, one_rtt_crypto_ack);
    std.debug.print("[crypto] protected_1rtt_crypto data={s} crypto_bytes={} ack_bytes={} client_inflight={} server_pending_ack={?}\n", .{
        one_rtt_crypto_bytes,
        one_rtt_crypto.len,
        one_rtt_crypto_ack.len,
        client.bytesInFlight(.application),
        server.pendingAckLargest(.application),
    });

    const app_stream = try client.openStream();
    try client.sendOnStream(app_stream, "protected application data", true);
    const one_rtt_stream = (try client.pollProtectedShortDatagram(
        15,
        &server_scid,
        initial_secrets.client,
    )) orelse return error.UnexpectedState;
    defer gpa.free(one_rtt_stream);
    try server.processProtectedShortDatagram(16, initial_secrets.client, server_scid.len, one_rtt_stream);

    var app_buf: [64]u8 = undefined;
    const app_len = (try server.recvOnStream(app_stream, &app_buf)) orelse return error.UnexpectedState;
    const one_rtt_stream_ack = (try server.pollProtectedShortDatagram(
        17,
        &client_scid,
        initial_secrets.server,
    )) orelse return error.UnexpectedState;
    defer gpa.free(one_rtt_stream_ack);
    try client.processProtectedShortDatagram(18, initial_secrets.server, client_scid.len, one_rtt_stream_ack);
    std.debug.print("[crypto] protected_1rtt_stream data={s} stream_bytes={} ack_bytes={} client_inflight={} server_pending_ack={?}\n", .{
        app_buf[0..app_len],
        one_rtt_stream.len,
        one_rtt_stream_ack.len,
        client.bytesInFlight(.application),
        server.pendingAckLargest(.application),
    });

    const reset_stream = try client.openStream();
    try client.sendOnStream(reset_stream, "reset me", false);
    try client.resetStream(reset_stream, 7);
    const one_rtt_reset = (try client.pollProtectedShortDatagram(
        19,
        &server_scid,
        initial_secrets.client,
    )) orelse return error.UnexpectedState;
    defer gpa.free(one_rtt_reset);
    try server.processProtectedShortDatagram(20, initial_secrets.client, server_scid.len, one_rtt_reset);

    var reset_buf: [32]u8 = undefined;
    try expectStreamClosed(&server, reset_stream, &reset_buf);
    const one_rtt_reset_ack = (try server.pollProtectedShortDatagram(
        21,
        &client_scid,
        initial_secrets.server,
    )) orelse return error.UnexpectedState;
    defer gpa.free(one_rtt_reset_ack);
    try client.processProtectedShortDatagram(22, initial_secrets.server, client_scid.len, one_rtt_reset_ack);
    if (try client.pollProtectedShortDatagram(23, &server_scid, initial_secrets.client)) |max_ack| {
        defer gpa.free(max_ack);
        try server.processProtectedShortDatagram(24, initial_secrets.client, server_scid.len, max_ack);
    }
    std.debug.print("[crypto] protected_1rtt_reset final_size={?} client_inflight={}\n", .{
        try server.recvStreamFinalSize(reset_stream),
        client.bytesInFlight(.application),
    });

    const stop_stream = try client.openStream();
    try client.sendOnStream(stop_stream, "stop me", false);
    const one_rtt_stop_data = (try client.pollProtectedShortDatagram(
        24,
        &server_scid,
        initial_secrets.client,
    )) orelse return error.UnexpectedState;
    defer gpa.free(one_rtt_stop_data);
    try server.processProtectedShortDatagram(25, initial_secrets.client, server_scid.len, one_rtt_stop_data);

    try server.stopSending(stop_stream, 23);
    const one_rtt_stop = (try server.pollProtectedShortDatagram(
        26,
        &client_scid,
        initial_secrets.server,
    )) orelse return error.UnexpectedState;
    defer gpa.free(one_rtt_stop);
    try client.processProtectedShortDatagram(27, initial_secrets.server, client_scid.len, one_rtt_stop);

    const one_rtt_reset_reply = (try client.pollProtectedShortDatagram(
        28,
        &server_scid,
        initial_secrets.client,
    )) orelse return error.UnexpectedState;
    defer gpa.free(one_rtt_reset_reply);
    try server.processProtectedShortDatagram(29, initial_secrets.client, server_scid.len, one_rtt_reset_reply);

    var stop_buf: [32]u8 = undefined;
    try expectStreamClosed(&server, stop_stream, &stop_buf);
    const one_rtt_stop_ack = (try server.pollProtectedShortDatagram(
        30,
        &client_scid,
        initial_secrets.server,
    )) orelse return error.UnexpectedState;
    defer gpa.free(one_rtt_stop_ack);
    try client.processProtectedShortDatagram(31, initial_secrets.server, client_scid.len, one_rtt_stop_ack);
    std.debug.print("[crypto] protected_1rtt_stop reset_final_size={?} client_inflight={} server_inflight={}\n", .{
        try server.recvStreamFinalSize(stop_stream),
        client.bytesInFlight(.application),
        server.bytesInFlight(.application),
    });

    var client_key_phase = quicz.protection.Aes128KeyPhaseState.init(initial_secrets.client, false);
    var server_client_key_phase = quicz.protection.Aes128KeyPhaseState.init(initial_secrets.client, false);
    client_key_phase.initiateKeyUpdate();
    try client.sendPing();
    const key_update_ping = (try client.pollProtectedShortDatagramWithKeyPhaseState(
        32,
        &server_scid,
        &client_key_phase,
    )) orelse return error.UnexpectedState;
    defer gpa.free(key_update_ping);
    try server.processProtectedShortDatagramWithKeyPhaseState(33, &server_client_key_phase, server_scid.len, key_update_ping);
    std.debug.print("[crypto] protected_1rtt_key_update ping_bytes={} next_peer_pn={} pending_ack={?} recv_key_phase={}\n", .{
        key_update_ping.len,
        server.nextPeerPacketNumber(.application),
        server.pendingAckLargest(.application),
        server_client_key_phase.currentKeyPhase(),
    });

    var spin_client = try quicz.Connection.init(gpa, .client, .{ .enable_spin_bit = true });
    defer spin_client.deinit();
    var spin_server = try quicz.Connection.init(gpa, .server, .{ .enable_spin_bit = true });
    defer spin_server.deinit();
    try spin_server.validatePeerAddress();

    try spin_client.sendPing();
    const spin_first = (try spin_client.pollProtectedShortDatagram(
        40,
        &server_scid,
        initial_secrets.client,
    )) orelse return error.UnexpectedState;
    defer gpa.free(spin_first);
    const first_spin = try quicz.protection.peekShortPacketSpinBit(spin_first);
    if (first_spin) return error.UnexpectedState;
    try spin_server.processProtectedShortDatagram(41, initial_secrets.client, server_scid.len, spin_first);

    const spin_ack = (try spin_server.pollProtectedShortDatagram(
        42,
        &client_scid,
        initial_secrets.server,
    )) orelse return error.UnexpectedState;
    defer gpa.free(spin_ack);
    const reflected_spin = try quicz.protection.peekShortPacketSpinBit(spin_ack);
    if (reflected_spin) return error.UnexpectedState;
    try spin_client.processProtectedShortDatagram(43, initial_secrets.server, client_scid.len, spin_ack);

    try spin_client.sendPing();
    const spin_second = (try spin_client.pollProtectedShortDatagram(
        44,
        &server_scid,
        initial_secrets.client,
    )) orelse return error.UnexpectedState;
    defer gpa.free(spin_second);
    const second_spin = try quicz.protection.peekShortPacketSpinBit(spin_second);
    if (!second_spin or !spin_client.nextOutgoingSpinBit()) return error.UnexpectedState;
    std.debug.print("[crypto] spin_bit first={} server_reflect={} second={} client_next={}\n", .{
        first_spin,
        reflected_spin,
        second_spin,
        spin_client.nextOutgoingSpinBit(),
    });
}
