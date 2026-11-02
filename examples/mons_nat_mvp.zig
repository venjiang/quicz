//! Disposable runtime probe. Never writes endpoint routes from the harness.
const std = @import("std");
const quicz = @import("quicz");
const Io = std.Io;
const Mode = enum { control, rebind, loss, blackhole, ssh_control, ssh_rebind, ssh_blackhole };

fn bind(io: Io) !Io.net.Socket {
    var address = Io.net.IpAddress{ .ip4 = .loopback(0) };
    return address.bind(io, .{ .mode = .dgram, .protocol = .udp });
}

const Proxy = struct {
    io: Io,
    host: Io.net.IpAddress,
    front: Io.net.Socket,
    old: Io.net.Socket,
    replacement: Io.net.Socket,
    mutex: std.atomic.Mutex = .unlocked,
    client: ?Io.net.IpAddress = null,
    switched: bool = false,
    blocked: bool = false,
    drop_one: bool = false,
    old_after_switch: usize = 0,
    push_started: bool = false,
    old_during_push: usize = 0,
    replacement_packets: usize = 0,
    dropped_replacement: usize = 0,
    source_cid: [20]u8 = @splat(0),
    source_cid_len: usize = 0,
    cid_checks: usize = 0,
    cid_mismatch: bool = false,

    fn init(io: Io, host: Io.net.IpAddress) !Proxy {
        const front = try bind(io);
        errdefer front.close(io);
        const old = try bind(io);
        errdefer old.close(io);
        return .{ .io = io, .host = host, .front = front, .old = old, .replacement = try bind(io) };
    }

    fn lock(self: *Proxy) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }

    fn deinit(self: *Proxy) void {
        self.front.close(self.io);
        self.old.close(self.io);
        self.replacement.close(self.io);
    }

    fn receive(self: *Proxy, socket: Io.net.Socket, buffer: []u8) !?Io.net.IncomingMessage {
        return socket.receiveTimeout(self.io, buffer, .{ .duration = .{
            .clock = .awake,
            .raw = .fromMilliseconds(50),
        } }) catch |err| switch (err) {
            error.Timeout => null,
            else => return err,
        };
    }

    fn forwardClient(self: *Proxy) !void {
        var buffer: [8192]u8 = undefined;
        while (true) {
            const message = (try self.receive(self.front, &buffer)) orelse continue;
            self.lock();
            self.client = message.from;
            const switched = self.switched;
            if (switched and message.data.len > 1 and message.data[0] & 0x80 == 0 and self.source_cid_len > 0) {
                const n = self.source_cid_len;
                self.cid_checks += 1;
                if (message.data.len < 1 + n or !std.mem.eql(u8, message.data[1 .. 1 + n], self.source_cid[0..n])) self.cid_mismatch = true;
            }
            self.mutex.unlock();
            const upstream = if (switched) self.replacement else self.old;
            try upstream.send(self.io, &self.host, message.data);
        }
    }

    fn forwardHost(self: *Proxy, replacement: bool) !void {
        const socket = if (replacement) self.replacement else self.old;
        var buffer: [8192]u8 = undefined;
        while (true) {
            const message = (try self.receive(socket, &buffer)) orelse continue;
            if (!std.meta.eql(message.from, self.host)) return error.UnexpectedSender;
            self.lock();
            const client = self.client;
            var drop = false;
            var trace_retired = false;
            var trace_bad_push = false;
            if (!replacement and !self.switched and message.data.len > 7 and message.data[0] & 0x80 != 0) {
                const destination_len: usize = message.data[5];
                const source_len_offset = 6 + destination_len;
                if (source_len_offset < message.data.len) {
                    const n: usize = message.data[source_len_offset];
                    if (n > 0 and n <= self.source_cid.len and source_len_offset + 1 + n <= message.data.len) {
                        if (self.source_cid_len != 0 and !std.mem.eql(u8, self.source_cid[0..self.source_cid_len], message.data[source_len_offset + 1 ..][0..n])) self.cid_mismatch = true;
                        self.source_cid_len = n;
                        @memcpy(self.source_cid[0..n], message.data[source_len_offset + 1 ..][0..n]);
                    }
                }
            }
            if (!replacement and self.switched) {
                self.old_after_switch += 1;
                trace_retired = self.old_after_switch == 1;
                if (self.push_started) {
                    self.old_during_push += 1;
                    trace_bad_push = self.old_during_push == 1;
                }
                drop = true;
            } else if (replacement) {
                self.replacement_packets += 1;
                if (self.blocked or self.drop_one) {
                    self.dropped_replacement += 1;
                    self.drop_one = false;
                    drop = true;
                }
            }
            self.mutex.unlock();
            if (trace_retired) std.debug.print("MVP retired_destination_observed port={d} action=drop\n", .{socket.address.ip4.port});
            if (trace_bad_push) std.debug.print("MVP retired_destination_during_push port={d} action=drop\n", .{socket.address.ip4.port});
            if (!drop) if (client) |address| try self.front.send(self.io, &address, message.data);
        }
    }

    fn switchPort(self: *Proxy, blocked: bool) void {
        self.lock();
        defer self.mutex.unlock();
        self.switched = true;
        self.blocked = blocked;
    }

    fn beginPush(self: *Proxy, drop_one: bool) void {
        self.lock();
        defer self.mutex.unlock();
        self.push_started = true;
        self.drop_one = drop_one;
    }

    fn summary(self: *Proxy) !void {
        self.lock();
        defer self.mutex.unlock();
        std.debug.print("MVP paths old_after_switch={d} old_during_push={d} replacement_packets={d} dropped_replacement={d} cid_checks={d} cid_match={any}\n", .{
            self.old_after_switch, self.old_during_push, self.replacement_packets, self.dropped_replacement, self.cid_checks, !self.cid_mismatch,
        });
        if (self.cid_mismatch or self.source_cid_len == 0) return error.ConnectionIdMismatch;
        if (self.switched and (self.cid_checks == 0 or self.replacement_packets == 0)) return error.NoReplacementTraffic;
        if (self.switched and self.old_during_push != 0) return error.AsyncUsedRetiredPath;
    }
};

fn receiveClient(client: *quicz.runtime.client.Client, stream_id: u64, expected: []const u8) !void {
    var buffer: [128]u8 = undefined;
    var received: usize = 0;
    while (received < expected.len) {
        const count = try client.receive(stream_id, buffer[received..expected.len]);
        if (count == 0) return error.UnexpectedEOF;
        received += count;
    }
    if (!std.mem.eql(u8, buffer[0..received], expected)) return error.PayloadMismatch;
}

fn receiveServer(stream: *quicz.runtime.server.Stream, expected: []const u8) !void {
    var buffer: [128]u8 = undefined;
    var received: usize = 0;
    while (received < expected.len) {
        const count = try stream.receive(buffer[received..expected.len]);
        if (count == 0) return error.UnexpectedEOF;
        received += count;
    }
    if (!std.mem.eql(u8, buffer[0..received], expected)) return error.PayloadMismatch;
}

fn stdinToClient(io: Io, client: *quicz.runtime.client.Client, stream_id: u64) !void {
    var buffer: [16384]u8 = undefined;
    while (true) {
        const count = try Io.File.stdin().readStreaming(io, &.{&buffer});
        if (count == 0) break;
        try client.sendOnStream(stream_id, buffer[0..count], false);
    }
    try client.sendOnStream(stream_id, "", true);
}

fn clientToStdout(io: Io, client: *quicz.runtime.client.Client, stream_id: u64) !void {
    var buffer: [16384]u8 = undefined;
    while (true) {
        const count = try client.receive(stream_id, &buffer);
        if (count == 0) return;
        try Io.File.stdout().writeStreamingAll(io, buffer[0..count]);
    }
}

fn streamToSsh(io: Io, stream: *quicz.runtime.server.Stream, tcp: Io.net.Stream) !void {
    var writer = tcp.writer(io, &.{});
    var buffer: [16384]u8 = undefined;
    while (true) {
        const count = try stream.receive(&buffer);
        if (count == 0) break;
        try writer.interface.writeAll(buffer[0..count]);
        try writer.interface.flush();
    }
    try tcp.shutdown(io, .send);
}

fn sshToStream(io: Io, stream: *quicz.runtime.server.Stream, tcp: Io.net.Stream) !void {
    var reader = tcp.reader(io, &.{});
    var buffer: [16384]u8 = undefined;
    var slices = [_][]u8{&buffer};
    while (true) {
        const count = reader.interface.readVec(&slices) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        try stream.send(buffer[0..count], false);
        try stream.flush();
    }
    try stream.send("", true);
    try stream.flush();
}

fn waitMarker(io: Io, path: []const u8) !void {
    while (true) {
        Io.Dir.cwd().access(io, path, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                try io.sleep(.fromMilliseconds(25), .awake);
                continue;
            },
            else => return err,
        };
        return;
    }
}

fn controlSsh(io: Io, proxy: *Proxy, mode: Mode, trigger: []const u8, verified: []const u8) !void {
    try waitMarker(io, trigger);
    if (mode != .ssh_control) proxy.switchPort(mode == .ssh_blackhole);
    std.debug.print("MVP SSH path_ready mode={s}\n", .{@tagName(mode)});
    try io.sleep(.fromMilliseconds(500), .awake);
    proxy.beginPush(false);
    std.debug.print("MVP SSH push_window_begin\n", .{});
    try waitMarker(io, verified);
    try proxy.summary();
    std.debug.print("MVP SSH transport_verified client_objects=1 connections=1 streams=1 backend_connections=1\n", .{});
}

fn runSsh(allocator: std.mem.Allocator, io: Io, client: *quicz.runtime.client.Client, stream_id: u64, server: *quicz.runtime.server.Server, proxy: *Proxy, mode: Mode, port: u16, trigger: []const u8) !void {
    const verified = try std.fmt.allocPrint(allocator, "{s}.verify", .{trigger});
    defer allocator.free(verified);
    var input = try io.concurrent(stdinToClient, .{ io, client, stream_id });
    defer input.cancel(io) catch {};
    var connection = try server.accept();
    var stream = try connection.acceptStream();
    const address = Io.net.IpAddress{ .ip4 = .loopback(port) };
    const tcp = try address.connect(io, .{ .mode = .stream });
    defer tcp.close(io);
    std.debug.print("MVP SSH begin tls=verified client_port={d} connection={d} stream={d} old_port={d} new_port={d}\n", .{
        client.localPort(), connection.id, stream_id, proxy.old.address.ip4.port, proxy.replacement.address.ip4.port,
    });
    var outgoing = try io.concurrent(streamToSsh, .{ io, &stream, tcp });
    defer outgoing.cancel(io) catch {};
    var incoming = try io.concurrent(sshToStream, .{ io, &stream, tcp });
    defer incoming.cancel(io) catch {};
    var controller = try io.concurrent(controlSsh, .{ io, proxy, mode, trigger, verified });
    defer controller.cancel(io) catch {};
    try clientToStdout(io, client, stream_id);
    try controller.await(io);
}

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.page_allocator;
    const arguments = try init.minimal.args.toSlice(allocator);
    if (arguments.len != 2 and arguments.len != 4) return error.ExpectedMode;
    const mode = std.meta.stringToEnum(Mode, arguments[1]) orelse return error.ExpectedMode;
    const ssh_mode = mode == .ssh_control or mode == .ssh_rebind or mode == .ssh_blackhole;
    if (ssh_mode != (arguments.len == 4)) return error.ExpectedMode;
    var threaded = Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const now: u64 = @intCast(Io.Clock.real.now(io).toSeconds());
    var identity = try quicz.connectivity.ephemeral_identity.generate(allocator, io, now);
    defer identity.deinit(allocator);
    var ca: std.crypto.Certificate.Bundle = .empty;
    defer ca.deinit(allocator);
    try ca.bytes.appendSlice(allocator, identity.certificate_der);
    try ca.parseCert(allocator, 0, @intCast(now));
    const alpn = [_][]const u8{"mons-nat-mvp"};
    var server = try quicz.runtime.server.Server.init(allocator, io, .{
        .port = 0,
        .bind_addr = .{ 127, 0, 0, 1 },
        .alpn = &alpn,
        .cert_der = identity.certificate_der,
        .private_key = &identity.private_key_seed,
        .private_key_algorithm = .ed25519,
        .max_connections = 1,
    });
    defer server.deinit();
    try server.start();
    var proxy = try Proxy.init(io, .{ .ip4 = .loopback(server.localPort()) });
    defer proxy.deinit();
    var from_client = try io.concurrent(Proxy.forwardClient, .{&proxy});
    defer from_client.cancel(io) catch {};
    var from_old = try io.concurrent(Proxy.forwardHost, .{ &proxy, false });
    defer from_old.cancel(io) catch {};
    var from_replacement = try io.concurrent(Proxy.forwardHost, .{ &proxy, true });
    defer from_replacement.cancel(io) catch {};
    var client = try quicz.runtime.client.Client.init(allocator, io, .{
        .server_port = proxy.front.address.ip4.port,
        .server_name = quicz.connectivity.ephemeral_identity.server_name,
        .alpn = &alpn,
        .ca_bundle = &ca,
        .active_migration_disabled = false,
        .keepalive_interval_ms = 0,
    });
    defer client.deinit();
    try client.connect();
    const stream_id = try client.openStream();
    if (ssh_mode) {
        const port = try std.fmt.parseInt(u16, arguments[2], 10);
        try runSsh(allocator, io, &client, stream_id, &server, &proxy, mode, port, arguments[3]);
        return;
    }
    const client_port = client.localPort();
    try client.sendOnStream(stream_id, "ready", false);
    var connection = try server.accept();
    const connection_id = connection.id;
    var stream = try connection.acceptStream();
    try receiveServer(&stream, "ready");
    try stream.send("control", false);
    try stream.flush();
    try receiveClient(&client, stream_id, "control");
    std.debug.print("MVP control_pass tls=verified client_port={d} connection={d} stream={d} old_port={d} new_port={d}\n", .{
        client_port, connection_id, stream_id, proxy.old.address.ip4.port, proxy.replacement.address.ip4.port,
    });
    if (mode != .control) {
        proxy.switchPort(mode == .blackhole);
        std.debug.print("MVP switch port=A_to_B blocked={any}\n", .{mode == .blackhole});
        try client.sendOnStream(stream_id, "rebind", false);
        try receiveServer(&stream, "rebind");
        try io.sleep(.fromMilliseconds(500), .awake);
    }
    proxy.beginPush(mode == .loss);
    std.debug.print("MVP host_push_begin application_client_writes=paused\n", .{});
    try stream.send("host-push-nonce-001", false);
    try stream.flush();
    try receiveClient(&client, stream_id, "host-push-nonce-001");
    if (client.localPort() != client_port or stream.id != stream_id or connection.id != connection_id) return error.ConnectionRebuilt;
    try proxy.summary();
    if (mode == .blackhole) return error.BlockedPathAccepted;
    std.debug.print("MVP PASS mode={s} accepts=1 client_objects=1 connections=1 streams=1 host_push=complete\n", .{@tagName(mode)});
}
