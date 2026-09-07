//! Stable C entry points for mobile platform adapters.
//!
//! This first boundary exposes only version and capability negotiation. Network,
//! connection, and stream handles will be added after the iOS static-library and
//! Swift import path are proven. Unsupported connectivity features are omitted
//! deliberately so callers cannot mistake QUIC transport support for NAT traversal.

const std = @import("std");

pub const abi_version: u32 = 1;

pub const Capability = enum(u6) {
    stream = 0,
    datagram = 1,
    path_validation = 2,
    migration = 3,
    multipath = 4,
};

pub fn capabilityMask() u64 {
    return bit(.stream) |
        bit(.datagram) |
        bit(.path_validation) |
        bit(.migration) |
        bit(.multipath);
}

fn bit(capability: Capability) u64 {
    return @as(u64, 1) << @intFromEnum(capability);
}

pub export fn quicz_mobile_abi_version() callconv(.c) u32 {
    return abi_version;
}

pub export fn quicz_mobile_capabilities() callconv(.c) u64 {
    return capabilityMask();
}

test "mobile ABI reports only implemented transport capabilities" {
    try std.testing.expectEqual(@as(u32, 1), quicz_mobile_abi_version());
    try std.testing.expectEqual(@as(u64, 0x1f), quicz_mobile_capabilities());
}
