//! Minimal DNS HTTPS/SVCB (RFC 9460, record type 65) lookup used by
//! `quicz probe` to report whether a domain advertises HTTP/3 via SVCB alpn.
//! Best-effort by design: failures produce `query_ok=false` and never change
//! the probe verdict.

const std = @import("std");

pub const HttpsSvcInfo = struct {
    query_ok: bool = false,
    h3: bool = false,
    priority: ?u16 = null,
    target: ?[]const u8 = null,
    alpn: ?[]const u8 = null,
    port: ?u16 = null,
    ipv4hint: ?[4]u8 = null,

    pub fn deinit(self: HttpsSvcInfo, allocator: std.mem.Allocator) void {
        if (self.target) |value| allocator.free(value);
        if (self.alpn) |value| allocator.free(value);
    }
};

const svc_type_https: u16 = 65;
const dns_timeout_ms: u64 = 3000;
const max_nameservers: usize = 4;
const edns_udp_payload: u16 = 4096;

/// Query the IPv4 nameservers from `/etc/resolv.conf` for HTTPS/SVCB records
/// of `host`, trying each in order. IPv4 literals are skipped (there is no DNS
/// name to ask). A truncated UDP answer is retried over TCP.
pub fn queryHttpsSvc(allocator: std.mem.Allocator, io: std.Io, host: []const u8) HttpsSvcInfo {
    if (isIpv4Literal(host)) return .{};
    var nameservers: [max_nameservers][4]u8 = undefined;
    const count = systemNameservers(io, &nameservers);
    for (nameservers[0..count]) |nameserver| {
        if (queryHttpsSvcAt(allocator, io, host, nameserver)) |info| {
            return info;
        } else |_| {}
    }
    return .{};
}

fn isIpv4Literal(host: []const u8) bool {
    return (std.Io.net.IpAddress.parseIp4(host, 0) catch null) != null;
}

fn systemNameservers(io: std.Io, out: *[max_nameservers][4]u8) usize {
    var count: usize = 0;
    var buf: [4096]u8 = undefined;
    const file = std.Io.Dir.openFileAbsolute(io, "/etc/resolv.conf", .{}) catch return 0;
    defer file.close(io);
    const read_len = file.readPositionalAll(io, &buf, 0) catch return 0;
    var lines = std.mem.splitScalar(u8, buf[0..read_len], '\n');
    while (lines.next()) |line_raw| {
        if (count >= max_nameservers) break;
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (std.mem.startsWith(u8, line, "nameserver")) {
            const rest = std.mem.trim(u8, line["nameserver".len..], " \t");
            if (std.Io.net.IpAddress.parseIp4(rest, 53)) |addr| {
                out[count] = addr.ip4.bytes;
                count += 1;
            } else |_| {}
        }
    }
    return count;
}

fn queryHttpsSvcAt(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    nameserver: [4]u8,
) !HttpsSvcInfo {
    var id_buf: [2]u8 = undefined;
    io.random(&id_buf);
    const query_id = std.mem.readInt(u16, &id_buf, .big);

    var query_buf: [512]u8 = undefined;
    const query_len = try buildQuery(&query_buf, host, query_id);

    var local = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } };
    const dest = std.Io.net.IpAddress{ .ip4 = .{ .bytes = nameserver, .port = 53 } };
    const socket = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);

    try socket.send(io, &dest, query_buf[0..query_len]);
    var response_buf: [4096]u8 = undefined;
    const message = try socket.receiveTimeout(io, &response_buf, .{
        .duration = .{
            .raw = std.Io.Duration.fromMilliseconds(dns_timeout_ms),
            .clock = .awake,
        },
    });
    const response = response_buf[0..message.data.len];
    if (isTruncated(response)) return queryTcp(allocator, io, host, nameserver);
    return parseSvcResponse(allocator, response, query_id);
}

fn buildQuery(buf: []u8, host: []const u8, id: u16) !usize {
    if (buf.len < 12) return error.NoSpaceLeft;
    std.mem.writeInt(u16, buf[0..2], id, .big);
    std.mem.writeInt(u16, buf[2..4], 0x0100, .big); // RD
    std.mem.writeInt(u16, buf[4..6], 1, .big); // QDCOUNT
    std.mem.writeInt(u16, buf[6..8], 0, .big);
    std.mem.writeInt(u16, buf[8..10], 0, .big);
    std.mem.writeInt(u16, buf[10..12], 1, .big); // ARCOUNT (one EDNS OPT)

    var pos: usize = 12;
    var labels = std.mem.splitScalar(u8, host, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return error.BadHostName;
        if (pos + 1 + label.len > buf.len) return error.NoSpaceLeft;
        buf[pos] = @intCast(label.len);
        @memcpy(buf[pos + 1 ..][0..label.len], label);
        pos += 1 + label.len;
    }
    if (pos + 5 > buf.len) return error.NoSpaceLeft;
    buf[pos] = 0;
    pos += 1;
    std.mem.writeInt(u16, buf[pos..][0..2], svc_type_https, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 1, .big); // IN
    pos += 2;
    if (pos + 11 > buf.len) return error.NoSpaceLeft;
    buf[pos] = 0; // OPT root name
    pos += 1;
    std.mem.writeInt(u16, buf[pos..][0..2], 41, .big); // OPT type
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], edns_udp_payload, .big); // UDP payload size
    pos += 2;
    std.mem.writeInt(u32, buf[pos..][0..4], 0, .big); // extended rcode/version/flags
    pos += 4;
    std.mem.writeInt(u16, buf[pos..][0..2], 0, .big); // rdata length
    pos += 2;
    return pos;
}

fn isTruncated(packet: []const u8) bool {
    return packet.len >= 2 and (packet[2] & 0x02) != 0;
}

fn queryTcp(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    nameserver: [4]u8,
) !HttpsSvcInfo {
    var id_buf: [2]u8 = undefined;
    io.random(&id_buf);
    const query_id = std.mem.readInt(u16, &id_buf, .big);
    var query_buf: [512]u8 = undefined;
    const query_len = try buildQuery(&query_buf, host, query_id);

    const addr = std.Io.net.IpAddress{ .ip4 = .{ .bytes = nameserver, .port = 53 } };
    const timeout: std.Io.Timeout = .{ .duration = .{
        .raw = std.Io.Duration.fromMilliseconds(dns_timeout_ms),
        .clock = .awake,
    } };
    const stream = try addr.connect(io, .{ .mode = .stream, .timeout = timeout });
    defer stream.close(io);

    var wire_buf: [512 + 2]u8 = undefined;
    std.mem.writeInt(u16, wire_buf[0..2], @intCast(query_len), .big);
    @memcpy(wire_buf[2..][0..query_len], query_buf[0..query_len]);
    try stream.socket.send(io, &addr, wire_buf[0 .. 2 + query_len]);

    var len_buf: [2]u8 = undefined;
    var got: usize = 0;
    while (got < 2) {
        const message = try stream.socket.receiveTimeout(io, len_buf[got..], timeout);
        if (message.data.len == 0) return error.EndOfStream;
        got += message.data.len;
    }
    const response_len = std.mem.readInt(u16, &len_buf, .big);
    const response = try allocator.alloc(u8, response_len);
    defer allocator.free(response);
    got = 0;
    while (got < response_len) {
        const message = try stream.socket.receiveTimeout(io, response[got..], timeout);
        if (message.data.len == 0) return error.EndOfStream;
        got += message.data.len;
    }
    return parseSvcResponse(allocator, response, query_id);
}

fn parseSvcResponse(allocator: std.mem.Allocator, packet: []const u8, expected_id: u16) HttpsSvcInfo {
    if (packet.len < 12) return .{};
    if (std.mem.readInt(u16, packet[0..2], .big) != expected_id) return .{};

    var response = std.Io.net.HostName.DnsResponse.init(packet) catch return .{};
    var info = HttpsSvcInfo{ .query_ok = true };
    while (response.next() catch return info) |answer| {
        const record_type: u16 = @intFromEnum(answer.rr);
        if (record_type != svc_type_https) continue;
        const data = answer.packet[answer.data_off..][0..answer.data_len];
        const parsed = parseSvcRdata(allocator, answer.packet, answer.data_off, data) catch continue;
        if (parsed.h3) return parsed;
        if (info.target == null) {
            info.deinit(allocator);
            info = parsed;
        } else {
            parsed.deinit(allocator);
        }
    }
    return info;
}

fn parseSvcRdata(
    allocator: std.mem.Allocator,
    packet: []const u8,
    data_off: usize,
    data: []const u8,
) !HttpsSvcInfo {
    if (data.len < 3) return error.BadSvcRdata;
    var info = HttpsSvcInfo{ .query_ok = true };
    info.priority = std.mem.readInt(u16, data[0..2], .big);

    var target_buf: [256]u8 = undefined;
    // Alias-mode SVCB records use the root target (".") encoded as a single
    // zero byte. std refuses to construct the empty HostName, so handle it
    // explicitly instead of dropping the whole record.
    var consumed: usize = 1;
    if (data[2] != 0) {
        const expanded = try std.Io.net.HostName.expand(packet, data_off + 2, &target_buf);
        consumed = expanded[0];
        if (expanded[1].bytes.len > 0) {
            info.target = try allocator.dupe(u8, expanded[1].bytes);
        }
    }

    var pos: usize = 2 + consumed;
    while (pos + 4 <= data.len) {
        const key = std.mem.readInt(u16, data[pos..][0..2], .big);
        const value_len = std.mem.readInt(u16, data[pos + 2 ..][0..2], .big);
        const value = data[pos + 4 ..][0..value_len];
        pos += 4 + value_len;
        switch (key) {
            1 => try parseAlpnParam(allocator, &info, value),
            3 => {
                if (value.len >= 2) info.port = std.mem.readInt(u16, value[0..2], .big);
            },
            4 => {
                if (value.len >= 4) info.ipv4hint = value[0..4].*;
            },
            else => {},
        }
    }
    return info;
}

fn parseAlpnParam(allocator: std.mem.Allocator, info: *HttpsSvcInfo, value: []const u8) !void {
    var alpn_buf: [256]u8 = undefined;
    var out_pos: usize = 0;
    var value_pos: usize = 0;
    while (value_pos < value.len) {
        const id_len: usize = value[value_pos];
        if (value_pos + 1 + id_len > value.len) return error.BadAlpnParam;
        if (id_len == 0) {
            value_pos += 1;
            continue;
        }
        const id = value[value_pos + 1 ..][0..id_len];
        if (out_pos + id_len + 1 > alpn_buf.len) return error.NoSpaceLeft;
        @memcpy(alpn_buf[out_pos..][0..id_len], id);
        out_pos += id_len;
        alpn_buf[out_pos] = ',';
        out_pos += 1;
        value_pos += 1 + id_len;
        if (std.mem.eql(u8, id, "h3") or std.mem.startsWith(u8, id, "h3-")) info.h3 = true;
    }
    if (out_pos == 0) return;
    if (info.alpn) |old| allocator.free(old);
    info.alpn = try allocator.dupe(u8, alpn_buf[0 .. out_pos - 1]);
}

test "parses HTTPS SVCB answer advertising h3" {
    // Query: example.com HTTPS. Answer: priority 1, target example.com,
    // alpn "h3,h2,http/1.1", port 443, ipv4hint 192.0.2.1.
    var packet: [256]u8 = undefined;
    var pos: usize = 0;
    std.mem.writeInt(u16, packet[pos..][0..2], 0x1234, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 0x8180, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 1, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 1, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 0, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 0, .big);
    pos += 2;
    // Question: example.com
    for ([_][]const u8{ "example", "com" }) |label| {
        packet[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(packet[pos..][0..label.len], label);
        pos += label.len;
    }
    packet[pos] = 0;
    pos += 1;
    std.mem.writeInt(u16, packet[pos..][0..2], svc_type_https, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 1, .big);
    pos += 2;
    // Answer: name pointer 0xc00c, type HTTPS, class IN, ttl 60, rdlen below.
    std.mem.writeInt(u16, packet[pos..][0..2], 0xc00c, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], svc_type_https, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 1, .big);
    pos += 2;
    std.mem.writeInt(u32, packet[pos..][0..4], 60, .big);
    pos += 4;
    const rdata_len_pos = pos;
    pos += 2;
    // priority
    std.mem.writeInt(u16, packet[pos..][0..2], 1, .big);
    pos += 2;
    // target name: example.com
    for ([_][]const u8{ "example", "com" }) |label| {
        packet[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(packet[pos..][0..label.len], label);
        pos += label.len;
    }
    packet[pos] = 0;
    pos += 1;
    // alpn param (key=1): "h3","h2","http/1.1"
    std.mem.writeInt(u16, packet[pos..][0..2], 1, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 15, .big);
    pos += 2;
    @memcpy(packet[pos..][0..15], &[_]u8{ 2, 'h', '3', 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1' });
    pos += 15;
    // port param (key=3)
    std.mem.writeInt(u16, packet[pos..][0..2], 3, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 2, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 443, .big);
    pos += 2;
    // ipv4hint param (key=4)
    std.mem.writeInt(u16, packet[pos..][0..2], 4, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 4, .big);
    pos += 2;
    @memcpy(packet[pos..][0..4], &[_]u8{ 192, 0, 2, 1 });
    pos += 4;

    const rdata_len = pos - (rdata_len_pos + 2);
    std.mem.writeInt(u16, packet[rdata_len_pos..][0..2], @intCast(rdata_len), .big);

    const info = parseSvcResponse(std.testing.allocator, packet[0..pos], 0x1234);
    defer info.deinit(std.testing.allocator);
    try std.testing.expect(info.query_ok);
    try std.testing.expect(info.h3);
    try std.testing.expectEqual(@as(?u16, 1), info.priority);
    try std.testing.expectEqualStrings("example.com", info.target.?);
    try std.testing.expectEqualStrings("h3,h2,http/1.1", info.alpn.?);
    try std.testing.expectEqual(@as(?u16, 443), info.port);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2, 1 }, &info.ipv4hint.?);
}

test "rejects HTTPS SVCB response with mismatched id" {
    var packet: [12]u8 = undefined;
    std.mem.writeInt(u16, packet[0..2], 0x9999, .big);
    const info = parseSvcResponse(std.testing.allocator, &packet, 0x1234);
    try std.testing.expect(!info.query_ok);
}

test "parses alias-mode HTTPS SVCB with root target" {
    var packet: [128]u8 = undefined;
    var pos: usize = 0;
    std.mem.writeInt(u16, packet[pos..][0..2], 0x1234, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 0x8180, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 1, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 1, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 0, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 0, .big);
    pos += 2;
    for ([_][]const u8{ "example", "com" }) |label| {
        packet[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(packet[pos..][0..label.len], label);
        pos += label.len;
    }
    packet[pos] = 0;
    pos += 1;
    std.mem.writeInt(u16, packet[pos..][0..2], svc_type_https, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 1, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 0xc00c, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], svc_type_https, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 1, .big);
    pos += 2;
    std.mem.writeInt(u32, packet[pos..][0..4], 60, .big);
    pos += 4;
    const rdata_len_pos = pos;
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 1, .big); // priority
    pos += 2;
    packet[pos] = 0; // root target (".")
    pos += 1;
    std.mem.writeInt(u16, packet[pos..][0..2], 1, .big); // alpn key
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 3, .big);
    pos += 2;
    @memcpy(packet[pos..][0..3], &[_]u8{ 2, 'h', '2' });
    pos += 3;
    std.mem.writeInt(u16, packet[rdata_len_pos..][0..2], @intCast(pos - (rdata_len_pos + 2)), .big);

    const info = parseSvcResponse(std.testing.allocator, packet[0..pos], 0x1234);
    defer info.deinit(std.testing.allocator);
    try std.testing.expect(info.query_ok);
    try std.testing.expect(!info.h3);
    try std.testing.expect(info.target == null);
    try std.testing.expectEqualStrings("h2", info.alpn.?);
}

test "SVCB query skipped for IPv4 literal" {
    try std.testing.expect(isIpv4Literal("127.0.0.1"));
    try std.testing.expect(!isIpv4Literal("example.com"));
}

test "builds DNS query with EDNS OPT" {
    var buf: [512]u8 = undefined;
    const len = try buildQuery(&buf, "example.com", 0x1234);
    try std.testing.expectEqual(@as(u16, 0x1234), std.mem.readInt(u16, buf[0..2], .big));
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, buf[10..12], .big)); // ARCOUNT
    // Trailing OPT record: root name, type 41, UDP payload 4096.
    try std.testing.expectEqual(@as(u16, 41), std.mem.readInt(u16, buf[len - 10 ..][0..2], .big));
    try std.testing.expectEqual(edns_udp_payload, std.mem.readInt(u16, buf[len - 8 ..][0..2], .big));
}

test "detects truncated DNS response" {
    var packet: [12]u8 = undefined;
    std.mem.writeInt(u16, packet[0..2], 0x1234, .big);
    packet[2] = 0x82; // TC bit set
    packet[3] = 0x80;
    try std.testing.expect(isTruncated(&packet));
    packet[2] = 0x81;
    try std.testing.expect(!isTruncated(&packet));
}
