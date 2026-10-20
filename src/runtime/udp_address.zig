//! Lossless conversion between endpoint tuples and native UDP addresses.

const std = @import("std");
const endpoint = @import("../quic/endpoint.zig");

/// Adapt one supported endpoint tuple family to native socket addresses.
pub fn ForTuple(comptime Path: type) type {
    const is_ipv6 = Path == endpoint.Udp6Tuple;
    if (!is_ipv6 and Path != endpoint.Udp4Tuple) @compileError("unsupported UDP tuple type");
    return struct {
        pub const Address = @TypeOf(@as(Path, undefined).local);
        pub const Octets = if (is_ipv6) [16]u8 else [4]u8;

        /// Preserve the complete endpoint, or reject a different address family.
        pub fn fromIp(address: std.Io.net.IpAddress) ?Address {
            if (is_ipv6) return switch (address) {
                .ip6 => |value| .init(value.bytes, value.port, value.interface.index),
                .ip4 => null,
            };
            return switch (address) {
                .ip4 => |value| .init(value.bytes, value.port),
                .ip6 => null,
            };
        }

        /// Construct a native destination without losing IPv6 scope or bytes.
        pub fn toIp(address: Address) std.Io.net.IpAddress {
            if (is_ipv6) return .{ .ip6 = .{
                .bytes = address.octets,
                .port = address.port,
                .interface = .{ .index = address.scope_id },
            } };
            return .{ .ip4 = .{ .bytes = address.octets, .port = address.port } };
        }
    };
}

test "native IPv6 address conversion preserves every octet port and scope" {
    const Family = ForTuple(endpoint.Udp6Tuple);
    const original = endpoint.Udp6Address.init(.{ 0x20, 1, 0xdb, 8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6 }, 61234, 17);
    try std.testing.expect(original.eql(Family.fromIp(Family.toIp(original)).?));
    try std.testing.expect(Family.fromIp(.{ .ip4 = .loopback(61234) }) == null);
    try std.testing.expect(ForTuple(endpoint.Udp4Tuple).fromIp(Family.toIp(original)) == null);
}
