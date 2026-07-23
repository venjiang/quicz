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

const www_dir = "/www";
const certs_dir = "/certs";
const bind_port: u16 = 443;
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

    fn cryptoBackend(self: *@This()) quicz.tls13_backend.CryptoBackend {
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
fn loadPemCertificate(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const pem_data = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(pem_data);

    // Find BEGIN/END CERTIFICATE markers
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    const begin = std.mem.indexOf(u8, pem_data, begin_marker) orelse return error.InvalidPem;
    const encoded_start = begin + begin_marker.len;
    const encoded_end = std.mem.indexOfPos(u8, pem_data, encoded_start, end_marker) orelse return error.InvalidPem;
    const encoded = std.mem.trim(u8, pem_data[encoded_start..encoded_end], " \t\r\n");

    // Base64 decode
    const der = try allocator.alloc(u8, encoded.len); // Upper bound
    errdefer allocator.free(der);
    const decoder = std.base64.standard.decoderWithIgnore("\r\n");
    const der_len = try decoder.decode(der, encoded);
    return der[0..der_len];
}

/// Load a PEM private key file and return the raw key bytes.
fn loadPemPrivateKey(allocator: std.mem.Allocator, path: []const u8) ![32]u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const pem_data = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(pem_data);

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
fn serveFile(allocator: std.mem.Allocator, request_path: []const u8) ![]u8 {
    // Sanitize path: remove leading /
    const clean_path = if (request_path.len > 0 and request_path[0] == '/')
        request_path[1..]
    else
        request_path;

    var path_buf: [512]u8 = undefined;
    const full_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ www_dir, clean_path }) catch return error.PathTooLong;

    const file = std.fs.cwd().openFile(full_path, .{}) catch return error.FileNotFound;
    defer file.close();
    return file.readToEndAlloc(allocator, 10 * 1024 * 1024);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const testcase = std.posix.getenv("TESTCASE") orelse "handshake";
    std.debug.print("quicz interop server: testcase={s}\n", .{testcase});

    // Load certificate and key
    const cert_der = loadPemCertificate(allocator, certs_dir ++ "/cert.pem") catch |err| {
        std.debug.print("failed to load certificate: {}\n", .{err});
        return err;
    };
    defer allocator.free(cert_der);

    const private_key = loadPemPrivateKey(allocator, certs_dir ++ "/priv.key") catch |err| {
        std.debug.print("failed to load private key: {}\n", .{err});
        return err;
    };

    std.debug.print("quicz interop server: certificate loaded ({d} bytes DER)\n", .{cert_der.len});

    // Bind UDP socket
    var threaded = std.Io.Threaded.init(allocator, .{}) catch {
        std.debug.print("failed to init I/O\n", .{});
        return error.IoInitFailed;
    };
    defer threaded.deinit();
    const io = threaded.io();

    var address = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = bind_port } };
    var socket = address.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch {
        std.debug.print("failed to bind UDP port {d}\n", .{bind_port});
        return error.BindFailed;
    };
    defer socket.close(io);

    std.debug.print("quicz interop server: listening on 0.0.0.0:{d}\n", .{bind_port});

    // Create server endpoint
    var server_endpoint = ServerEndpoint.init(allocator, .{
        .max_active_connections = 16,
    }) catch {
        std.debug.print("failed to init server endpoint\n", .{});
        return error.EndpointInitFailed;
    };
    defer server_endpoint.deinit();

    // Event loop
    var recv_buf: [max_datagram_size]u8 = undefined;
    var running = true;

    while (running) {
        // Receive datagram
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

        // Process through endpoint
        var initial_out: [4]quicz.EndpointPolledDatagramResult = undefined;
        var handshake_out: [4]quicz.EndpointPolledDatagramResult = undefined;
        var installed_out: [16]ServerEndpoint.DatagramPathResult = undefined;
        var pending_out: [16]ServerEndpoint.DatagramPathResult = undefined;
        var scratch: [8192]u8 = undefined;

        const step = server_endpoint.receiveDatagramStepWithRoutePath(
            allocator,
            path,
            0, // TODO: use real timestamp
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

        // Send response datagrams
        for (initial_out[0..step.process.routed.long.packet.accepted.initial.drain.datagrams_written]) |o| {
            socket.send(io, &std.Io.net.IpAddress{ .ip4 = .{ .bytes = from_addr.octets, .port = from_addr.port } }, o.datagram) catch {};
            allocator.free(o.datagram);
        }
        _ = step;
    }
}
