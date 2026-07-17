const std = @import("std");
const connection_config = @import("connection_config.zig");
const packet = @import("packet.zig");
const transport_types = @import("transport_types.zig");

const Config = connection_config.Config;
const ConnectionSide = transport_types.ConnectionSide;
const Error = transport_types.Error;

/// Return whether a QUIC version field is the forbidden zero value.
pub fn isZeroVersion(version: packet.Version) bool {
    return @intFromEnum(version) == 0;
}

/// Return whether a version list contains the exact wire version value.
pub fn versionListContains(versions: []const packet.Version, version: packet.Version) bool {
    for (versions) |candidate| {
        if (@intFromEnum(candidate) == @intFromEnum(version)) return true;
    }
    return false;
}

/// Select the first preferred version that appears in the offered list.
pub fn selectMutualVersion(
    preferred_versions: []const packet.Version,
    offered_versions: []const packet.Version,
) ?packet.Version {
    for (preferred_versions) |preferred| {
        if (packet.isReservedVersion(preferred)) continue;
        if (versionListContains(offered_versions, preferred)) return preferred;
    }
    return null;
}

/// Select the first preferred version that appears in the offered list or matches one extra value.
pub fn selectMutualVersionWithExtra(
    preferred_versions: []const packet.Version,
    offered_versions: []const packet.Version,
    extra_version: packet.Version,
) ?packet.Version {
    for (preferred_versions) |preferred| {
        if (packet.isReservedVersion(preferred)) continue;
        if (@intFromEnum(preferred) == @intFromEnum(extra_version) or versionListContains(offered_versions, preferred)) {
            return preferred;
        }
    }
    return null;
}

/// Validate local RFC 9368 version-information configuration before connection use.
pub fn validateLocalVersionInformation(side: ConnectionSide, config: Config) Error!void {
    if (isZeroVersion(config.chosen_version)) return error.InvalidPacket;
    if (packet.isReservedVersion(config.chosen_version)) return error.InvalidPacket;
    for (config.available_versions) |available| {
        if (isZeroVersion(available)) return error.InvalidPacket;
    }
    if (side == .client) {
        if (config.available_versions.len == 0) return error.InvalidPacket;
        if (!versionListContains(config.available_versions, config.chosen_version)) return error.InvalidPacket;
    }
    if (config.version_negotiation_selected_version) |selected| {
        if (side != .client) return error.InvalidPacket;
        if (isZeroVersion(selected)) return error.InvalidPacket;
        if (packet.isReservedVersion(selected)) return error.InvalidPacket;
        if (@intFromEnum(selected) != @intFromEnum(config.chosen_version)) return error.InvalidPacket;
        if (!versionListContains(config.available_versions, selected)) return error.InvalidPacket;
    }
}

test "selectMutualVersion skips reserved preferred versions" {
    const preferred = [_]packet.Version{ @enumFromInt(0x0a0a0a0a), .v2, .v1 };
    const offered = [_]packet.Version{ .v1, .v2 };

    try std.testing.expectEqual(packet.Version.v2, selectMutualVersion(&preferred, &offered).?);
}

test "selectMutualVersionWithExtra accepts authenticated chosen version" {
    const preferred = [_]packet.Version{ .v2, .v1 };
    const offered = [_]packet.Version{.v1};

    try std.testing.expectEqual(packet.Version.v2, selectMutualVersionWithExtra(&preferred, &offered, .v2).?);
}

test "validateLocalVersionInformation rejects inconsistent client follow-up config" {
    const available = [_]packet.Version{.v1};

    try std.testing.expectError(error.InvalidPacket, validateLocalVersionInformation(.client, .{
        .chosen_version = .v2,
        .available_versions = &available,
        .version_negotiation_selected_version = .v2,
    }));
}

test "validateLocalVersionInformation rejects reserved chosen versions" {
    const reserved = [_]packet.Version{@enumFromInt(0x0a0a0a0a)};

    try std.testing.expectError(error.InvalidPacket, validateLocalVersionInformation(.client, .{
        .chosen_version = reserved[0],
        .available_versions = &reserved,
    }));
    try std.testing.expectError(error.InvalidPacket, validateLocalVersionInformation(.server, .{
        .chosen_version = reserved[0],
    }));
}
