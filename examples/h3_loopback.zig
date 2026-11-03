//! HTTP/3 + QPACK dynamic table over real loopback UDP (pure-Zig TLS 1.3).
//!
//! Two real Connections complete a TLS 1.3 handshake over UDP sockets, then
//! H3Server / H3Client are layered on top with the dynamic QPACK control flow:
//! control / encoder / decoder streams, SETTINGS, two request/response rounds
//! (the second uses acknowledged dynamic references), and decoder-stream
//! acknowledgments all travel over the wire.

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
const server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };

fn require(condition: bool) !void {
    if (!condition) return error.UnexpectedState;
}

fn recvTimeout() std.Io.Timeout {
    return .{
        .duration = .{
            .clock = .awake,
            .raw = std.Io.Duration.fromMilliseconds(2000),
        },
    };
}

fn makeServerConnAdapter(conn: *Connection) quicz.h3_server.H3Server.H3ServerConnection {
    const Adapter = struct {
        fn openUni(ctx: *anyopaque) anyerror!u64 {
            const c: *Connection = @ptrCast(@alignCast(ctx));
            return c.openUniStream();
        }
        fn send(ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) anyerror!void {
            const c: *Connection = @ptrCast(@alignCast(ctx));
            return c.sendOnStream(stream_id, data, fin);
        }
        fn recv(ctx: *anyopaque, stream_id: u64, buf: []u8) anyerror!?usize {
            const c: *Connection = @ptrCast(@alignCast(ctx));
            return c.recvOnStream(stream_id, buf);
        }
    };
    return .{
        .openUniStreamFn = Adapter.openUni,
        .sendOnStreamFn = Adapter.send,
        .recvOnStreamFn = Adapter.recv,
        .ctx = conn,
    };
}

fn makeClientConnAdapter(conn: *Connection) quicz.h3_client.H3Client.H3ClientConnection {
    const Adapter = struct {
        fn openBidi(ctx: *anyopaque) anyerror!u64 {
            const c: *Connection = @ptrCast(@alignCast(ctx));
            return c.openStream();
        }
        fn openUni(ctx: *anyopaque) anyerror!u64 {
            const c: *Connection = @ptrCast(@alignCast(ctx));
            return c.openUniStream();
        }
        fn send(ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) anyerror!void {
            const c: *Connection = @ptrCast(@alignCast(ctx));
            return c.sendOnStream(stream_id, data, fin);
        }
        fn recv(ctx: *anyopaque, stream_id: u64, buf: []u8) anyerror!?usize {
            const c: *Connection = @ptrCast(@alignCast(ctx));
            return c.recvOnStream(stream_id, buf);
        }
    };
    return .{
        .openBidiStreamFn = Adapter.openBidi,
        .openUniStreamFn = Adapter.openUni,
        .sendOnStreamFn = Adapter.send,
        .recvOnStreamFn = Adapter.recv,
        .ctx = conn,
    };
}

/// Poll every pending protected short datagram from `source` and send it to
/// `dest_socket`. Returns the number of datagrams sent.
fn sendPending(
    io: std.Io,
    allocator: std.mem.Allocator,
    now: *i64,
    source: *Connection,
    src_socket: *std.Io.net.Socket,
    dest_socket: *std.Io.net.Socket,
    dcid: []const u8,
) !usize {
    var count: usize = 0;
    while (true) {
        const datagram = (try source.pollProtectedShortDatagramWithInstalledKeys(now.*, dcid)) orelse break;
        {
            defer allocator.free(datagram);
            try src_socket.send(io, &dest_socket.address, datagram);
        }
        now.* += 1;
        count += 1;
    }
    return count;
}

/// Receive exactly `count` datagrams from `socket` and process them into
/// `dest` with the installed 1-RTT keys.
fn receiveAndProcess(
    io: std.Io,
    now: *i64,
    socket: *std.Io.net.Socket,
    dest: *Connection,
    dcid_len: usize,
    recv_buf: []u8,
    count: usize,
) !void {
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const received = try socket.receiveTimeout(io, recv_buf, recvTimeout());
        try dest.processProtectedShortDatagramWithInstalledKeys(now.*, dcid_len, received.data);
        now.* += 1;
    }
}

fn pumpClientToServer(
    io: std.Io,
    allocator: std.mem.Allocator,
    now: *i64,
    client: *Connection,
    client_socket: *std.Io.net.Socket,
    server: *Connection,
    server_socket: *std.Io.net.Socket,
    recv_buf: []u8,
) !void {
    const count = try sendPending(io, allocator, now, client, client_socket, server_socket, &server_scid);
    try receiveAndProcess(io, now, server_socket, server, server_scid.len, recv_buf, count);
}

fn pumpServerToClient(
    io: std.Io,
    allocator: std.mem.Allocator,
    now: *i64,
    server: *Connection,
    server_socket: *std.Io.net.Socket,
    client: *Connection,
    client_socket: *std.Io.net.Socket,
    recv_buf: []u8,
) !void {
    const count = try sendPending(io, allocator, now, server, server_socket, client_socket, &client_scid);
    try receiveAndProcess(io, now, client_socket, client, client_scid.len, recv_buf, count);
}

/// Feed a peer encoder-stream read into the target's decoder table, stripping
/// the 0x02 stream-type prefix on the first read.
fn feedPeerEncoderStream(conn: *Connection, stream_id: u64, buf: []u8, opened: *bool, target: anytype) !void {
    const n = (try conn.recvOnStream(stream_id, buf)) orelse return;
    const payload = if (opened.*) buf[0..n] else blk: {
        opened.* = true;
        break :blk buf[1..n];
    };
    if (payload.len > 0) try target.processPeerEncoderStream(payload);
}

/// Feed a peer decoder-stream read into the target's encoder table, stripping
/// the 0x03 stream-type prefix on the first read.
fn feedPeerDecoderStream(conn: *Connection, stream_id: u64, buf: []u8, opened: *bool, target: anytype) !void {
    const n = (try conn.recvOnStream(stream_id, buf)) orelse return;
    const payload = if (opened.*) buf[0..n] else blk: {
        opened.* = true;
        break :blk buf[1..n];
    };
    if (payload.len > 0) try target.processPeerDecoderStream(payload);
}

/// Assert that the peer control stream carries the stream type and SETTINGS,
/// then feed it into the peer control-stream processor.
fn readPeerControlStream(conn: *Connection, stream_id: u64, buf: []u8, target: anytype) !void {
    const n = (try conn.recvOnStream(stream_id, buf)) orelse return error.MissingControlStream;
    if (n < 2) return error.MissingControlStream;
    try require(buf[0] == 0x00); // control stream type
    try require(buf[1] == 0x04); // SETTINGS frame type
    try target.processPeerControlStream(buf[0..n]);
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var client_socket = try client_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);
    var server_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var server_socket = try server_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    const seed = @as([32]u8, @splat(0x55));
    const server_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const server_priv = server_kp.secret_key.bytes;
    const cert_der = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    const alpn = [_][]const u8{"h3"};
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try Connection.init(allocator, .client, .{
        .initial_max_data = 16384,
        .initial_max_stream_data = 4096,
        .initial_max_streams_bidi = 8,
        .initial_max_streams_uni = 8,
        .max_datagram_size = 8192,
    });
    defer client.deinit();
    var server = try Connection.init(allocator, .server, .{
        .initial_max_data = 16384,
        .initial_max_stream_data = 4096,
        .initial_max_streams_bidi = 8,
        .initial_max_streams_uni = 8,
        .max_datagram_size = 8192,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    var client_backend = Tls13Backend.initClient(.{
        .alpn = &alpn,
        .server_name = "example.com",
        .skip_cert_verify = true,
    });
    var server_backend = Tls13Backend.initServer(.{
        .alpn = &alpn,
        .cert_chain_der = &.{&cert_der},
        .private_key_bytes = &server_priv,
        .private_key_algorithm = .ecdsa_p256_sha256,
    });

    var scratch: [8192]u8 = undefined;
    var recv_buf: [2048]u8 = undefined;
    var now: i64 = 40;

    try client.setLocalInitialSourceConnectionId(&client_scid);
    try server.setLocalInitialSourceConnectionId(&server_scid);

    // Real TLS 1.3 handshake over loopback UDP.
    _ = try client.driveCryptoBackendInSpace(.initial, client_backend.cryptoBackend(), &scratch);
    const client_init_dgram = (try client.pollProtectedLongCryptoDatagramInSpace(
        .initial,
        now,
        &original_dcid,
        &client_scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.UnexpectedState;
    {
        defer allocator.free(client_init_dgram);
        try client_socket.send(io, &server_socket.address, client_init_dgram);
    }
    now += 1;

    const recv1 = try server_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try server.processProtectedLongDatagramInSpace(.initial, now, secrets.client, recv1.data);
    now += 1;
    const server_init_prog = try server.driveCryptoBackendInSpace(.initial, server_backend.cryptoBackend(), &scratch);
    try require(server_init_prog.handshake_keys_installed);

    const server_init_dgram = (try server.pollProtectedLongCryptoDatagramInSpace(
        .initial,
        now,
        &client_scid,
        &server_scid,
        &[_]u8{},
        secrets.server,
    )) orelse return error.UnexpectedState;
    {
        defer allocator.free(server_init_dgram);
        try server_socket.send(io, &client_socket.address, server_init_dgram);
    }
    now += 1;

    _ = try server.driveCryptoBackendInSpace(.handshake, server_backend.cryptoBackend(), &scratch);
    const server_hs_dgram = (try server.pollProtectedHandshakeDatagramWithInstalledKeys(
        now,
        &client_scid,
        &server_scid,
    )) orelse return error.UnexpectedState;
    {
        defer allocator.free(server_hs_dgram);
        try server_socket.send(io, &client_socket.address, server_hs_dgram);
    }
    now += 1;

    const recv2 = try client_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try client.processProtectedLongDatagramInSpace(.initial, now, secrets.server, recv2.data);
    now += 1;
    _ = try client.driveCryptoBackendInSpace(.initial, client_backend.cryptoBackend(), &scratch);

    const recv3 = try client_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try client.processProtectedHandshakeDatagramWithInstalledKeys(now, recv3.data);
    now += 1;
    const client_hs_prog = try client.driveCryptoBackendInSpace(.handshake, client_backend.cryptoBackend(), &scratch);
    try require(client_hs_prog.outbound_bytes > 0);
    const client_hs_dgram = (try client.pollProtectedHandshakeDatagramWithInstalledKeys(
        now,
        &server_scid,
        &client_scid,
    )) orelse return error.UnexpectedState;
    {
        defer allocator.free(client_hs_dgram);
        try client_socket.send(io, &server_socket.address, client_hs_dgram);
    }
    now += 1;

    const recv4 = try server_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try server.processProtectedHandshakeDatagramWithInstalledKeys(now, recv4.data);
    now += 1;
    const server_hs_drive = try server.driveCryptoBackendInSpace(.handshake, server_backend.cryptoBackend(), &scratch);
    try require(server_hs_drive.handshake_confirmed);
    try require(server.handshakeConfirmed());

    // HTTP/3 layer with dynamic QPACK over the confirmed connections.
    var server_adapter = makeServerConnAdapter(&server);
    var client_adapter = makeClientConnAdapter(&client);

    const handler = struct {
        fn handle(req: quicz.h3_request.DecodedRequest) quicz.h3_request.Response {
            if (!std.mem.eql(u8, req.method, "GET")) return .{ .status = 400, .body = "BAD METHOD" };
            if (!std.mem.eql(u8, req.path, "/api/data")) return .{ .status = 404, .body = "NOT FOUND" };
            if (!std.mem.eql(u8, req.authority.?, "service.internal")) return .{ .status = 400, .body = "BAD AUTHORITY" };
            return .{
                .status = 200,
                .extra_headers = &.{
                    .{ .name = "x-response-id", .value = "resp-001" },
                    .{ .name = "x-server", .value = "quicz-h3" },
                },
                .body = "OK",
            };
        }
    }.handle;

    var h3srv = try quicz.h3_server.H3Server.init(&server_adapter, handler, allocator, 4096, 8);
    defer h3srv.deinit();

    var h3cli = try quicz.h3_client.H3Client.init(&client_adapter, allocator, 4096, 8);
    defer h3cli.deinit();

    var stream_buf: [8192]u8 = undefined;
    var srv_enc_opened = false;
    var srv_dec_opened = false;
    var cli_enc_opened = false;
    var cli_dec_opened = false;

    // Deliver the control streams first so SETTINGS arrive before the QPACK
    // streams are opened.
    try pumpClientToServer(io, allocator, &now, &client, &client_socket, &server, &server_socket, &recv_buf);
    try readPeerControlStream(&server, h3cli.control_stream_id.?, &stream_buf, &h3srv);
    try pumpServerToClient(io, allocator, &now, &server, &server_socket, &client, &client_socket, &recv_buf);
    try readPeerControlStream(&client, h3srv.control_stream_id.?, &stream_buf, &h3cli);

    try h3srv.enableQpackDynamic(4096);
    try h3cli.enableQpackDynamic(4096);

    // Deliver the QPACK encoder/decoder streams in both directions.
    try pumpClientToServer(io, allocator, &now, &client, &client_socket, &server, &server_socket, &recv_buf);
    try feedPeerEncoderStream(&server, h3cli.enc_stream_id.?, &stream_buf, &srv_enc_opened, &h3srv);
    try feedPeerDecoderStream(&server, h3cli.dec_stream_id.?, &stream_buf, &srv_dec_opened, &h3srv);
    try pumpServerToClient(io, allocator, &now, &server, &server_socket, &client, &client_socket, &recv_buf);
    try feedPeerEncoderStream(&client, h3srv.enc_stream_id.?, &stream_buf, &cli_enc_opened, &h3cli);
    try feedPeerDecoderStream(&client, h3srv.dec_stream_id.?, &stream_buf, &cli_dec_opened, &h3cli);

    const request = quicz.h3_request.Request{
        .method = "GET",
        .path = "/api/data",
        .authority = "service.internal",
        .extra_headers = &.{
            .{ .name = "x-trace-id", .value = "trace-001" },
            .{ .name = "x-api-key", .value = "key-abc" },
        },
    };

    // Round 1: literals (insertions are not acknowledged yet) + encoder inserts.
    const stream1 = try h3cli.sendRequestDynamic(request);
    try pumpClientToServer(io, allocator, &now, &client, &client_socket, &server, &server_socket, &recv_buf);
    try feedPeerEncoderStream(&server, h3cli.enc_stream_id.?, &stream_buf, &srv_enc_opened, &h3srv);
    try h3srv.handleRequestStream(stream1);

    try pumpServerToClient(io, allocator, &now, &server, &server_socket, &client, &client_socket, &recv_buf);
    try feedPeerEncoderStream(&client, h3srv.enc_stream_id.?, &stream_buf, &cli_enc_opened, &h3cli);
    try feedPeerDecoderStream(&client, h3srv.dec_stream_id.?, &stream_buf, &cli_dec_opened, &h3cli);
    const resp1 = try h3cli.receiveResponseDynamic(stream1);
    try require(resp1.status == 200);
    try require(std.mem.eql(u8, resp1.body.?, "OK"));

    // Deliver the client's decoder-stream acknowledgments to the server.
    try pumpClientToServer(io, allocator, &now, &client, &client_socket, &server, &server_socket, &recv_buf);
    try feedPeerDecoderStream(&server, h3cli.dec_stream_id.?, &stream_buf, &srv_dec_opened, &h3srv);

    // Round 2: the entries are acknowledged, so dynamic references are used.
    const stream2 = try h3cli.sendRequestDynamic(request);
    try pumpClientToServer(io, allocator, &now, &client, &client_socket, &server, &server_socket, &recv_buf);
    try feedPeerEncoderStream(&server, h3cli.enc_stream_id.?, &stream_buf, &srv_enc_opened, &h3srv);
    try h3srv.handleRequestStream(stream2);

    try pumpServerToClient(io, allocator, &now, &server, &server_socket, &client, &client_socket, &recv_buf);
    try feedPeerEncoderStream(&client, h3srv.enc_stream_id.?, &stream_buf, &cli_enc_opened, &h3cli);
    try feedPeerDecoderStream(&client, h3srv.dec_stream_id.?, &stream_buf, &cli_dec_opened, &h3cli);
    const resp2 = try h3cli.receiveResponseDynamic(stream2);
    try require(resp2.status == 200);
    try require(std.mem.eql(u8, resp2.body.?, "OK"));

    try pumpClientToServer(io, allocator, &now, &client, &client_socket, &server, &server_socket, &recv_buf);
    try feedPeerDecoderStream(&server, h3cli.dec_stream_id.?, &stream_buf, &srv_dec_opened, &h3srv);

    // Both sides have acknowledged every insertion; nothing stays pending.
    try require(h3cli.enc_table.?.known_received_count == h3cli.enc_table.?.insert_count);
    try require(h3srv.enc_table.?.known_received_count == h3srv.enc_table.?.insert_count);
    try require(h3cli.pending_sections.?.count() == 0);
    try require(h3srv.pending_sections.?.count() == 0);
    try require(h3cli.enc_table.?.protected_entries == 0);
    try require(h3srv.enc_table.?.protected_entries == 0);

    std.debug.print(
        "h3_loopback: handshake + dynamic QPACK over UDP OK round1={d} round2={d} client_enc_entries={d} server_enc_entries={d} client_krc={d} server_krc={d}\n",
        .{
            resp1.status,
            resp2.status,
            h3cli.enc_table.?.entryCount(),
            h3srv.enc_table.?.entryCount(),
            h3cli.enc_table.?.known_received_count,
            h3srv.enc_table.?.known_received_count,
        },
    );
}
