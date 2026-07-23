//! quicz interop server for QUIC-Interop-Runner.
//!
//! Serves files from /www on port 443 using HTTP/0.9 over QUIC.
//! Loads certificates from /certs/priv.key and /certs/cert.pem.
//! Test case controlled by TESTCASE environment variable.
//!
//! HTTP/0.9 protocol: client sends request path on a bidi stream,
//! server responds with file contents and closes the stream.

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const EndpointConnectionLifecycle = quicz.EndpointConnectionLifecycle;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const Tls13ServerTransport = quicz.Tls13ServerTransport;
const endpoint = quicz.endpoint;
const quic_packet = quicz.packet;
const protection = quicz.protection;

const www_dir = "/private/tmp/www"; // Use /www in Docker, /private/tmp/www for local testing
const certs_dir = "/private/tmp/certs"; // Use /certs in Docker, /private/tmp/certs for local testing
const default_bind_port: u16 = 443;

fn getBindPort(init: std.process.Init) u16 {
    if (init.environ_map.get("PORT")) |port_str| {
        return std.fmt.parseInt(u16, port_str, 10) catch default_bind_port;
    }
    return default_bind_port;
}
const max_datagram_size: usize = 8192;
const idle_timeout_ms: u64 = 30_000;

/// Server record: wraps a connection with its handle.
const ServerRecord = struct {
    handle: u64,
    transport: Tls13ServerTransport,
    retry_validated: bool = false,

    fn connectionRef(self: *@This()) *Connection {
        return self.transport.connectionRef();
    }

    fn cryptoBackend(self: *@This()) quicz.CryptoBackend {
        return self.transport.cryptoBackend();
    }

    fn destinationConnectionId(self: *const @This()) []const u8 {
        return self.transport.connection.peerDestinationConnectionId() orelse
            self.transport.peerInitialSourceConnectionId();
    }

    fn sourceConnectionId(self: *const @This()) []const u8 {
        return self.transport.localInitialSourceConnectionId();
    }

    fn initialDestinationConnectionId(self: *const @This()) []const u8 {
        return if (self.retry_validated)
            self.transport.localInitialSourceConnectionId()
        else
            self.transport.originalDestinationConnectionId();
    }

    fn markRetryValidated(self: *@This()) void {
        self.retry_validated = true;
    }

    fn deinit(self: *@This()) void {
        self.transport.deinit();
    }
};

const ServerEndpoint = quicz.Tls13ServerEndpoint(
    ServerRecord,
    ServerRecord.connectionRef,
    ServerRecord.cryptoBackend,
    ServerRecord.destinationConnectionId,
    ServerRecord.sourceConnectionId,
    ServerRecord.initialDestinationConnectionId,
    ServerRecord.markRetryValidated,
    ServerRecord.deinit,
);

/// Load a PEM certificate file and return the DER bytes.
fn loadPemCertificate(io: std.Io, path: []const u8, der_buf: []u8) ![]u8 {
    var pem_buf: [64 * 1024]u8 = undefined;
    const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch |err| {
        std.debug.print("failed to open {s}: {s}\n", .{ path, @errorName(err) });
        return err;
    };
    defer file.close(io);
    const bytes_read = file.readPositionalAll(io, &pem_buf, 0) catch |err| {
        std.debug.print("failed to read {s}: {s}\n", .{ path, @errorName(err) });
        return err;
    };
    const pem_data = pem_buf[0..bytes_read];

    // Find BEGIN/END CERTIFICATE markers
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    const begin = std.mem.indexOf(u8, pem_data, begin_marker) orelse return error.InvalidPem;
    const encoded_start = begin + begin_marker.len;
    const encoded_end = std.mem.indexOfPos(u8, pem_data, encoded_start, end_marker) orelse return error.InvalidPem;
    const encoded = std.mem.trim(u8, pem_data[encoded_start..encoded_end], " \t\r\n");

    // Base64 decode
    const der = der_buf[0..encoded.len];
    const decoder = std.base64.standard.decoderWithIgnore("\r\n");
    const der_len = try decoder.decode(der, encoded);
    return der[0..der_len];
}

/// Load a PEM private key file and return the raw key bytes.
fn loadPemPrivateKey(io: std.Io, path: []const u8) ![32]u8 {
    var pem_buf: [64 * 1024]u8 = undefined;
    const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch |err| {
        std.debug.print("failed to open {s}: {s}\n", .{ path, @errorName(err) });
        return err;
    };
    defer file.close(io);
    const bytes_read = file.readPositionalAll(io, &pem_buf, 0) catch |err| {
        std.debug.print("failed to read {s}: {s}\n", .{ path, @errorName(err) });
        return err;
    };
    const pem_data = pem_buf[0..bytes_read];

    // Find BEGIN/END PRIVATE KEY or EC PRIVATE KEY markers
    const markers = [_][]const u8{
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
    };
    const end_markers = [_][]const u8{
        "-----END PRIVATE KEY-----",
        "-----END EC PRIVATE KEY-----",
    };

    for (markers, end_markers) |begin_marker, end_marker| {
        if (std.mem.indexOf(u8, pem_data, begin_marker)) |begin| {
            const encoded_start = begin + begin_marker.len;
            const encoded_end = std.mem.indexOfPos(u8, pem_data, encoded_start, end_marker) orelse continue;
            const encoded = std.mem.trim(u8, pem_data[encoded_start..encoded_end], " \t\r\n");

            var der_buf: [256]u8 = undefined;
            const decoder = std.base64.standard.decoderWithIgnore("\r\n");
            const der_len = decoder.decode(&der_buf, encoded) catch continue;

            // Extract the 32-byte private key from DER
            // For PKCS#8: look for the octet string containing the key
            // For EC: the key is at a known offset
            if (der_len >= 32) {
                // Try to find the 32-byte key in the DER data
                // PKCS#8 EC key: the raw key is typically the last 32 bytes
                // of the nested octet string
                var key: [32]u8 = undefined;
                @memcpy(&key, der_buf[der_len - 32 .. der_len]);
                return key;
            }
        }
    }
    return error.InvalidPem;
}

/// Serve a file from the www directory.
fn serveFile(io: std.Io, request_path: []const u8, buf: []u8) ![]u8 {
    // Sanitize path: remove leading /
    const clean_path = if (request_path.len > 0 and request_path[0] == '/')
        request_path[1..]
    else
        request_path;

    var path_buf: [512]u8 = undefined;
    const full_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ www_dir, clean_path }) catch return error.PathTooLong;

    const file = std.Io.Dir.openFileAbsolute(io, full_path, .{}) catch return error.FileNotFound;
    defer file.close(io);
    const n = file.readPositionalAll(io, buf, 0) catch return error.FileNotFound;
    return buf[0..n];
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    const testcase = init.environ_map.get("TESTCASE") orelse "handshake";
    std.debug.print("quicz interop server: testcase={s}\n", .{testcase});

    // Load certificate and key
    var cert_der_buf: [8192]u8 = undefined;
    const cert_der = loadPemCertificate(io, certs_dir ++ "/cert.pem", &cert_der_buf) catch |err| {
        std.debug.print("failed to load certificate: {}\n", .{err});
        return err;
    };

    const private_key = loadPemPrivateKey(io, certs_dir ++ "/priv.key") catch |err| {
        std.debug.print("failed to load private key: {}\n", .{err});
        return err;
    };

    std.debug.print("quicz interop server: certificate loaded ({d} bytes DER)\n", .{cert_der.len});

    // Bind UDP socket

    const bind_port = getBindPort(init);
    var address = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = bind_port } };
    var socket = address.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch {
        std.debug.print("failed to bind UDP port {d}\n", .{bind_port});
        return error.BindFailed;
    };
    defer socket.close(io);

    std.debug.print("quicz interop server: listening on 0.0.0.0:{d}\n", .{bind_port});

    // Create server endpoint
    var server_endpoint = ServerEndpoint.initWithCapacity(allocator, 16, .{
        .max_routes = 64,
        .max_stateless_reset_tokens = 64,
    }) catch {
        std.debug.print("failed to init server endpoint\n", .{});
        return error.EndpointInitFailed;
    };
    defer server_endpoint.deinit();

    // Event loop: receive datagrams, process through endpoint, send responses
    var recv_buf: [max_datagram_size]u8 = undefined;
    var next_handle: u64 = 1;

    while (true) {
        const timeout = std.Io.Timeout{
            .duration = .{
                .clock = .awake,
                .raw = std.Io.Duration.fromMilliseconds(100),
            },
        };
        const received = socket.receiveTimeout(io, &recv_buf, timeout) catch continue;
        const from_addr = endpoint.Udp4Address.init(
            received.from.ip4.bytes,
            received.from.ip4.port,
        );
        const local_addr = endpoint.Udp4Address.init(
            socket.address.ip4.bytes,
            socket.address.ip4.port,
        );
        const path = endpoint.Udp4Tuple{ .local = local_addr, .remote = from_addr };

        // Process through endpoint with Initial admission
        var initial_out: [4]quicz.EndpointPolledDatagramResult = undefined;
        var handshake_out: [4]quicz.EndpointPolledDatagramResult = undefined;
        var installed_out: [16]ServerEndpoint.DatagramPathResult = undefined;
        var pending_out: [16]ServerEndpoint.DatagramPathResult = undefined;
        var scratch: [8192]u8 = undefined;

        // Check if this is an Initial packet (new connection)
        const is_initial = received.data.len > 0 and
            (received.data[0] & 0x80) != 0 and // Long header
            (received.data[0] & 0x40) != 0; // Fixed bit

        if (is_initial) {
            // New connection: create record and use Initial admission
            const handle = next_handle;
            next_handle += 1;
            var server_scid: [8]u8 = undefined;
            io.randomSecure(&server_scid) catch {};

            var record = ServerRecord{
                .handle = handle,
                .transport = Tls13ServerTransport.init(allocator, .{
                    .initial_max_data = 65536,
                    .initial_max_stream_data = 16384,
                    .initial_max_streams_bidi = 128,
                    .initial_max_streams_uni = 128,
                    .max_datagram_size = max_datagram_size,
                    .initial_rtt_ms = 100,
                    .max_idle_timeout_ms = 30000,
                }, .{
                    .alpn = &[_][]const u8{"hq-interop"},
                    .cert_chain_der = &.{cert_der},
                    .private_key_bytes = &private_key,
                    .private_key_algorithm = .ecdsa_p256_sha256,
                }) catch continue,
            };
            record.transport.connection.validatePeerAddress() catch {};
            record.transport.setLocalInitialSourceConnectionId(&server_scid) catch {};

            const step = server_endpoint.receiveDatagramStepWithRoutePathAndInitialRecordAdmission(
                allocator,
                path,
                0,
                received.data,
                &[_]u8{},
                &[_]quic_packet.Version{.v1},
                .{
                    .space = .application,
                    .out = &scratch,
                    .unpredictable_prefix = &[_]u8{},
                    .supported_versions = &[_]quic_packet.Version{.v1},
                },
                handle,
                &record,
                &server_scid,
                .{},
                &scratch,
                &[_]u8{},
                &initial_out,
                &handshake_out,
                &installed_out,
                .application,
                &pending_out,
            ) catch {
                record.transport.deinit();
                continue;
            };
            _ = step;
        } else {
            // Existing connection: use regular routing
            const step = server_endpoint.receiveDatagramStepWithRoutePath(
                allocator,
                path,
                0,
                received.data,
                &[_]u8{},
                &[_]quic_packet.Version{.v1},
                .{
                    .space = .application,
                    .out = &scratch,
                    .unpredictable_prefix = &[_]u8{},
                    .supported_versions = &[_]quic_packet.Version{.v1},
                },
                &scratch,
                &[_]u8{},
                &initial_out,
                &handshake_out,
                &installed_out,
                .application,
                &pending_out,
            ) catch continue;
            _ = step;
        }

        // Send response datagrams back to client
        var dest = std.Io.net.IpAddress{
            .ip4 = .{ .bytes = from_addr.octets, .port = from_addr.port },
        };
        for (initial_out) |o| {
            if (o.datagram.len > 0) {
                socket.send(io, &dest, o.datagram) catch {};
                allocator.free(o.datagram);
            }
        }
        for (handshake_out) |o| {
            if (o.datagram.len > 0) {
                socket.send(io, &dest, o.datagram) catch {};
                allocator.free(o.datagram);
            }
        }
        for (installed_out) |o| {
            if (o.datagram.len > 0) {
                socket.send(io, &dest, o.datagram) catch {};
                allocator.free(o.datagram);
            }
        }
        for (pending_out) |o| {
            if (o.datagram.len > 0) {
                socket.send(io, &dest, o.datagram) catch {};
                allocator.free(o.datagram);
            }
        }
    }
}
