const std = @import("std");
const quicz = @import("quicz");
const tls13 = quicz.tls13;
const root = quicz.quic;
const endpoint = root.endpoint;
const quic_packet = root.quic_packet;
const Tls13ClientEndpoint = quicz.Tls13ClientEndpoint;

const server_addr = "127.0.0.1";
const server_port = 4433;

fn receiveTimeout() std.Io.Timeout {
    return .{
        .duration = .{
            .clock = .awake,
            .raw = std.Io.Duration.fromMilliseconds(5000),
        },
    };
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Read server certificate from PEM file.
    const cert_pem = try std.fs.cwd().openFile("interop/server-cert.pem", .{});
    defer cert_pem.close();
    var pem_buf: [4096]u8 = undefined;
    const pem_len = try cert_pem.readAll(&pem_buf);
    const pem_data = pem_buf[0..pem_len];

    // Decode DER from PEM.
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    const begin = std.mem.indexOf(u8, pem_data, begin_marker) orelse return error.InvalidPem;
    const encoded_start = begin + begin_marker.len;
    const encoded_end = std.mem.indexOfPos(u8, pem_data, encoded_start, end_marker) orelse return error.InvalidPem;
    const encoded = std.mem.trim(u8, pem_data[encoded_start..encoded_end], " \t\r\n");
    var cert_der_storage: [2048]u8 = undefined;
    const decoder = std.base64.standard.decoderWithIgnore("\r\n");
    const cert_der_len = try decoder.decode(&cert_der_storage, encoded);
    const cert_der = cert_der_storage[0..cert_der_len];

    // Set up trust bundle.
    const now_sec: i64 = std.time.timestamp();
    var ca_bundle = std.crypto.Certificate.Bundle.empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.bytes.appendSlice(allocator, cert_der);
    try ca_bundle.parseCert(allocator, 0, now_sec);

    // Create UDP socket.
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var socket = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);

    const server_ip = std.net.Ip4Address.parse(server_addr, server_port) catch return error.InvalidAddress;
    const server_ip_addr = std.Io.net.IpAddress{ .ip4 = server_ip };

    // Create TLS 1.3 client endpoint.
    const alpn = [_][]const u8{"hq-interop"};
    const connection_config = root.Config{
        .initial_max_data = 65536,
        .initial_max_stream_data = 16384,
        .initial_max_streams_bidi = 8,
        .max_datagram_size = 1200,
        .chosen_version = .v1,
        .available_versions = &[_]quic_packet.Version{.v1},
    };
    const client_tls_config = tls13.Tls13Config{
        .alpn = &alpn,
        .server_name = "localhost",
        .skip_cert_verify = false,
        .trust_bundle = &ca_bundle,
        .now_sec = now_sec,
    };
    var scratch_storage: [8192]u8 = undefined;
    var client = try Tls13ClientEndpoint.init(
        allocator,
        connection_config,
        client_tls_config,
        &scratch_storage,
    );
    defer client.deinit();

    // Phase 1: Begin handshake — send ClientHello Initial.
    const begin_result = try client.beginWithRoutePath(0, &scratch_storage);
    defer allocator.free(begin_result.datagram);
    try socket.send(io, &server_ip_addr, begin_result.datagram);
    std.log.info("sent ClientHello ({d} bytes)", .{begin_result.datagram.len});

    // Phase 2: Receive server flight, produce Finished.
    var recv_buf: [2048]u8 = undefined;
    var client_finished: ?[]u8 = null;
    defer if (client_finished) |d| allocator.free(d);

    var handshake_done = false;
    var attempts: usize = 0;
    while (!handshake_done and attempts < 10) : (attempts += 1) {
        const received = socket.receiveTimeout(io, &recv_buf, receiveTimeout()) catch |err| {
            std.log.info("receive timeout/error: {}", .{err});
            break;
        };
        const r = try client.receiveWithRoutePath(1, &scratch_storage, received.data);
        if (r.outbound_initial) |o| {
            defer allocator.free(o.datagram);
            try socket.send(io, &server_ip_addr, o.datagram);
            std.log.info("sent Initial ({d} bytes)", .{o.datagram.len});
        }
        if (r.outbound_handshake) |h| {
            if (client_finished == null) {
                client_finished = h.datagram;
            } else {
                allocator.free(h.datagram);
            }
            try socket.send(io, &server_ip_addr, h.datagram);
            std.log.info("sent Handshake/Finished ({d} bytes)", .{h.datagram.len});
        }
        if (client.handshakeConfirmed()) {
            handshake_done = true;
            std.log.info("handshake confirmed", .{});
        }
    }

    if (!handshake_done) {
        std.log.err("handshake did not complete", .{});
        return error.HandshakeFailed;
    }

    // Phase 3: Send stream data.
    const stream_id = try client.openStream();
    const payload = "hello quic-go";
    var send_out: [4]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
    const send_result = try client.sendStreamWithRoutePathAndDrainDatagrams(
        stream_id,
        payload,
        true,
        2,
        &send_out,
    );
    for (send_out[0..send_result.drain.datagrams_written]) |o| {
        defer allocator.free(o.datagram);
        try socket.send(io, &server_ip_addr, o.datagram);
        std.log.info("sent STREAM ({d} bytes)", .{o.datagram.len});
    }

    // Phase 4: Receive echo.
    var echo_received = false;
    attempts = 0;
    while (!echo_received and attempts < 10) : (attempts += 1) {
        const received = socket.receiveTimeout(io, &recv_buf, receiveTimeout()) catch break;
        var recv_out: [4]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
        var due_out: [4]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
        const step = try client.receiveDatagramStepWithRoutePath(
            3,
            &scratch_storage,
            received.data,
            &recv_out,
            &due_out,
        );
        for (recv_out[0..step.receive.drain.datagrams_written]) |o| {
            defer allocator.free(o.datagram);
            try socket.send(io, &server_ip_addr, o.datagram);
        }
        if (step.due) |due| {
            for (due_out[0..due.drain.datagrams_written]) |o| allocator.free(o.datagram);
        }
        var echo_buf: [256]u8 = undefined;
        if (try client.recvStream(stream_id, &echo_buf)) |len| {
            std.log.info("echo received: {s}", .{echo_buf[0..len]});
            if (std.mem.eql(u8, echo_buf[0..len], payload)) {
                echo_received = true;
            }
        }
    }

    if (echo_received) {
        std.log.info("P0-F1 INTEROP PASS: quic-go handshake + stream echo verified", .{});
    } else {
        std.log.err("P0-F1 INTEROP FAIL: echo not received", .{});
        return error.InteropFailed;
    }

    // Phase 5: Close.
    var close_out: [4]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
    const close_result = try client.closeApplicationWithRoutePathAndDrainDatagrams(0, "done", 4, &close_out);
    for (close_out[0..close_result.drain.datagrams_written]) |o| {
        defer allocator.free(o.datagram);
        try socket.send(io, &server_ip_addr, o.datagram);
    }
    std.log.info("connection closed", .{});
}
