//! quicz interop client for QUIC-Interop-Runner.
//!
//! Downloads files from URLs in REQUESTS environment variable.
//! Saves downloaded files to /downloads.
//! Test case controlled by TESTCASE environment variable.
//!
//! HTTP/0.9 protocol: client sends request path on a bidi stream,
//! server responds with file contents and closes the stream.

const std = @import("std");
const quicz = @import("quicz");

const endpoint = quicz.endpoint;
const Tls13ClientEndpoint = quicz.Tls13ClientEndpoint;

const downloads_dir = "/downloads";
const certs_dir = "/certs";
const max_datagram_size: usize = 8192;
const recv_timeout_ms: u64 = 5000;

fn recvTimeout() std.Io.Timeout {
    return .{ .duration = .{
        .clock = .awake,
        .raw = std.Io.Duration.fromMilliseconds(recv_timeout_ms),
    } };
}

/// Parse a URL into host, port, and path.
fn parseUrl(url: []const u8) !struct { host: []const u8, port: u16, path: []const u8 } {
    // Expected format: https://host:port/path
    var rest = url;

    // Strip scheme
    if (std.mem.indexOf(u8, rest, "://")) |scheme_end| {
        rest = rest[scheme_end + 3 ..];
    }

    // Split host:port from path
    const path_start = std.mem.indexOf(u8, rest, "/") orelse rest.len;
    const host_port = rest[0..path_start];
    const path = if (path_start < rest.len) rest[path_start..] else "/";

    // Split host and port
    var host = host_port;
    var port: u16 = 443;
    if (std.mem.lastIndexOf(u8, host_port, ":")) |colon| {
        host = host_port[0..colon];
        port = std.fmt.parseInt(u16, host_port[colon + 1 ..], 10) catch 443;
    }

    return .{ .host = host, .port = port, .path = path };
}

/// Save downloaded data to a file in the downloads directory.
fn saveFile(path: []const u8, data: []const u8) !void {
    // Extract filename from path
    const filename = if (std.mem.lastIndexOf(u8, path, "/")) |slash|
        path[slash + 1 ..]
    else
        path;

    var buf: [512]u8 = undefined;
    const full_path = std.fmt.bufPrint(&buf, "{s}/{s}", .{ downloads_dir, filename }) catch return;

    const file = try std.fs.cwd().createFile(full_path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(data);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    const testcase = init.environ_map.get("TESTCASE") orelse "handshake";
    const requests_env = init.environ_map.get("REQUESTS") orelse "";
    std.debug.print("quicz interop client: testcase={s}\n", .{testcase});

    if (requests_env.len == 0) {
        std.debug.print("quicz interop client: no REQUESTS, nothing to download\n", .{});
        return;
    }

    // Parse REQUESTS (space-separated URLs)
    var urls: [32][]const u8 = undefined;
    var url_count: usize = 0;
    var iter = std.mem.splitScalar(u8, requests_env, ' ');
    while (iter.next()) |url| {
        if (url.len == 0) continue;
        if (url_count >= urls.len) break;
        urls[url_count] = url;
        url_count += 1;
    }

    if (url_count == 0) {
        std.debug.print("quicz interop client: no valid URLs\n", .{});
        return;
    }

    // Parse first URL to get server address
    const first_url = try parseUrl(urls[0]);
    std.debug.print("quicz interop client: connecting to {s}:{d}\n", .{ first_url.host, first_url.port });

    // Initialize I/O

    // Bind client UDP socket
    var address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var socket = address.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch {
        std.debug.print("failed to bind client socket\n", .{});
        return error.BindFailed;
    };
    defer socket.close(io);

    // Create client endpoint
    var client = Tls13ClientEndpoint.init(
        allocator,
        .{
            .initial_max_data = 1_048_576,
            .initial_max_stream_data = 1_048_576,
            .initial_max_streams_bidi = 128,
            .initial_max_streams_uni = 128,
            .max_datagram_size = max_datagram_size,
            .chosen_version = .v1,
            .available_versions = &[_]quicz.packet.Version{.v1},
        },
        .{
            .alpn = &[_][]const u8{"hq-interop"},
            .server_name = first_url.host,
            .skip_cert_verify = true, // TODO: load CA from /certs
        },
        undefined, // scratch
    ) catch {
        std.debug.print("failed to init client endpoint\n", .{});
        return error.ClientInitFailed;
    };
    defer client.deinit();

    // Begin handshake
    var scratch: [8192]u8 = undefined;
    const begin_result = client.beginWithRoutePath(0, &scratch) catch {
        std.debug.print("failed to begin handshake\n", .{});
        return error.HandshakeFailed;
    };

    // Send Initial to server
    var server_addr = std.Io.net.IpAddress{
        .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = first_url.port },
    };
    socket.send(io, &server_addr, begin_result.datagram) catch {
        std.debug.print("failed to send Initial\n", .{});
        return error.SendFailed;
    };
    allocator.free(begin_result.datagram);

    // Handshake loop
    var recv_buf: [max_datagram_size]u8 = undefined;
    var handshake_done = false;
    var attempts: usize = 0;

    while (!handshake_done and attempts < 20) : (attempts += 1) {
        const received = socket.receiveTimeout(io, &recv_buf, recvTimeout()) catch {
            std.debug.print("receive timeout during handshake\n", .{});
            continue;
        };

        const result = client.receiveWithRoutePath(0, &scratch, received.data) catch {
            std.debug.print("failed to process server datagram\n", .{});
            continue;
        };

        // Send any response datagrams
        if (result.outbound_initial) |o| {
            socket.send(io, &server_addr, o.datagram) catch {};
            allocator.free(o.datagram);
        }
        if (result.outbound_handshake) |o| {
            socket.send(io, &server_addr, o.datagram) catch {};
            allocator.free(o.datagram);
        }

        if (client.handshakeConfirmed()) {
            handshake_done = true;
            std.debug.print("quicz interop client: handshake confirmed\n", .{});
        }
    }

    if (!handshake_done) {
        std.debug.print("quicz interop client: handshake failed\n", .{});
        return error.HandshakeFailed;
    }

    // Download files
    for (urls[0..url_count]) |url| {
        const parsed = parseUrl(url) catch continue;
        std.debug.print("quicz interop client: downloading {s}\n", .{parsed.path});

        // Open stream and send request
        const stream_id = client.openStream() catch continue;
        client.sendStream(stream_id, parsed.path, true) catch continue;

        // Drain and send request datagrams
        var send_out: [16]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
        const send_result = client.sendStreamWithRoutePathAndDrainDatagrams(
            stream_id,
            parsed.path,
            true,
            0,
            &send_out,
        ) catch continue;

        for (send_out[0..send_result.drain.datagrams_written]) |o| {
            socket.send(io, &server_addr, o.datagram) catch {};
            allocator.free(o.datagram);
        }

        // Receive response
        var response_buf: [1024 * 1024]u8 = undefined;
        var response_len: usize = 0;
        var recv_attempts: usize = 0;

        while (recv_attempts < 50) : (recv_attempts += 1) {
            const received = socket.receiveTimeout(io, &recv_buf, recvTimeout()) catch break;

            var recv_out: [16]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
            var due_out: [16]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
            _ = client.receiveDatagramStepWithRoutePath(
                0,
                &scratch,
                received.data,
                &recv_out,
                &due_out,
            ) catch continue;

            // Send ACKs
            for (recv_out[0..0]) |o| {
                socket.send(io, &server_addr, o.datagram) catch {};
                allocator.free(o.datagram);
            }

            // Try to read stream data
            var read_buf: [65536]u8 = undefined;
            if (client.recvStream(stream_id, &read_buf) catch null) |n| {
                if (n > 0 and response_len + n <= response_buf.len) {
                    @memcpy(response_buf[response_len .. response_len + n], read_buf[0..n]);
                    response_len += n;
                }
            }

            // Check if stream is finished
            if (client.streamFinished(stream_id) catch false) {
                break;
            }
        }

        // Save file
        if (response_len > 0) {
            saveFile(parsed.path, response_buf[0..response_len]) catch {
                std.debug.print("failed to save {s}\n", .{parsed.path});
            };
            std.debug.print("quicz interop client: saved {s} ({d} bytes)\n", .{ parsed.path, response_len });
        }
    }

    // Close connection
    var close_out: [4]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
    _ = client.closeApplicationWithRoutePathAndDrainDatagrams(0, "done", 0, &close_out) catch {};
    for (close_out[0..0]) |o| {
        socket.send(io, &server_addr, o.datagram) catch {};
        allocator.free(o.datagram);
    }

    std.debug.print("quicz interop client: complete\n", .{});
}
