const std = @import("std");
const buffer = @import("buffer.zig");
const packet = @import("packet.zig");
const protocol_limits = @import("protocol_limits.zig");

const max_connection_id_len = protocol_limits.max_connection_id_len;
pub const max_udp_payload_size_default = 65_527;
const max_stream_count = protocol_limits.max_stream_count;
const max_quic_varint = protocol_limits.max_quic_varint;

/// RFC 9000 transport parameter identifiers.
pub const ParameterId = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    version_information = 0x11,

    _,
};

/// Return whether a transport parameter identifier is reserved for greasing.
///
/// RFC 9000 reserves identifiers of the form `31 * N + 27` so endpoints can
/// send parameters with arbitrary values and verify that peers ignore unknown
/// transport parameters.
pub fn isReservedParameterId(id: u64) bool {
    return id % 31 == 27;
}

/// Server preferred address transport parameter value.
pub const PreferredAddress = struct {
    ipv4_address: [4]u8,
    ipv4_port: u16,
    ipv6_address: [16]u8,
    ipv6_port: u16,
    connection_id: []const u8,
    stateless_reset_token: [16]u8,
};

/// RFC 9368 version_information transport parameter value.
pub const VersionInformation = struct {
    chosen_version: packet.Version,
    available_versions: []const packet.Version,

    /// Return whether `version` is present in the Available Versions list.
    pub fn containsAvailableVersion(self: VersionInformation, version: packet.Version) bool {
        for (self.available_versions) |available| {
            if (@intFromEnum(available) == @intFromEnum(version)) return true;
        }
        return false;
    }
};

/// Typed RFC 9000 transport parameters.
///
/// Optional byte slices, the preferred-address connection ID, and
/// `version_information.available_versions` are owned by decoded values and
/// released by `deinit`. Callers that construct values for encoding retain
/// ownership of their provided slices.
pub const TransportParameters = struct {
    original_destination_connection_id: ?[]const u8 = null,
    max_idle_timeout: u64 = 0,
    stateless_reset_token: ?[16]u8 = null,
    max_udp_payload_size: u64 = max_udp_payload_size_default,
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    ack_delay_exponent: u64 = 3,
    max_ack_delay: u64 = 25,
    disable_active_migration: bool = false,
    preferred_address: ?PreferredAddress = null,
    active_connection_id_limit: u64 = 2,
    initial_source_connection_id: ?[]const u8 = null,
    retry_source_connection_id: ?[]const u8 = null,
    version_information: ?VersionInformation = null,

    /// Release buffers owned by transport parameters decoded with `parse`.
    pub fn deinit(self: *TransportParameters, allocator: std.mem.Allocator) void {
        if (self.original_destination_connection_id) |cid| allocator.free(cid);
        if (self.initial_source_connection_id) |cid| allocator.free(cid);
        if (self.retry_source_connection_id) |cid| allocator.free(cid);
        if (self.preferred_address) |preferred| allocator.free(preferred.connection_id);
        if (self.version_information) |version_information| allocator.free(version_information.available_versions);
        self.* = .{};
    }
};

fn cloneBytes(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    const owned = try allocator.alloc(u8, data.len);
    @memcpy(owned, data);
    return owned;
}

fn validateConnectionIdLen(cid: []const u8) !void {
    if (cid.len > max_connection_id_len) return error.InvalidParameterValue;
}

fn validatePreferredAddressConnectionIdLen(cid: []const u8) !void {
    if (cid.len == 0 or cid.len > max_connection_id_len) return error.InvalidParameterValue;
}

fn validateIntegerParameter(id: ParameterId, value: u64) !void {
    if (value > max_quic_varint) return error.InvalidParameterValue;
    switch (id) {
        .max_udp_payload_size => if (value < 1200 or value > max_udp_payload_size_default) return error.InvalidParameterValue,
        .initial_max_streams_bidi, .initial_max_streams_uni => if (value > max_stream_count) return error.InvalidParameterValue,
        .ack_delay_exponent => if (value > 20) return error.InvalidParameterValue,
        .max_ack_delay => if (value >= (@as(u64, 1) << 14)) return error.InvalidParameterValue,
        .active_connection_id_limit => if (value < 2) return error.InvalidParameterValue,
        else => {},
    }
}

fn parseIntegerValue(id: ParameterId, value: []const u8) !u64 {
    var reader_fbs = buffer.fixedReader(value);
    const parsed = try packet.decodeVarInt(reader_fbs.reader());
    if (parsed.len != value.len) return error.InvalidParameterLength;
    try validateIntegerParameter(id, parsed.value);
    return parsed.value;
}

fn validateParameterIdVarInt(id: u64) !void {
    if (id > max_quic_varint) return error.InvalidParameterValue;
}

fn validateParameterValueLen(value: []const u8) !u64 {
    const value_len = std.math.cast(u64, value.len) orelse return error.InvalidParameterLength;
    if (value_len > max_quic_varint) return error.InvalidParameterLength;
    return value_len;
}

fn encodeIntegerValue(writer: anytype, id: ParameterId, value: u64) !void {
    try validateIntegerParameter(id, value);
    try encodeUncheckedIntegerValue(writer, id, value);
}

fn encodeUncheckedIntegerValue(writer: anytype, id: ParameterId, value: u64) !void {
    try validateParameterIdVarInt(@intFromEnum(id));
    if (value > max_quic_varint) return error.InvalidParameterValue;

    var raw: [8]u8 = undefined;
    var value_writer = buffer.fixedWriter(&raw);
    try packet.encodeVarInt(value_writer.writer(), value);
    try encodeBytesValue(writer, id, value_writer.getWritten());
}

fn encodeBytesValue(writer: anytype, id: ParameterId, value: []const u8) !void {
    try validateParameterIdVarInt(@intFromEnum(id));
    const value_len = try validateParameterValueLen(value);
    try packet.encodeVarInt(writer, @intFromEnum(id));
    try packet.encodeVarInt(writer, value_len);
    try writer.writeAll(value);
}

/// Serialize one reserved transport parameter with arbitrary bytes.
///
/// This helper is intentionally separate from `TransportParameters` because
/// reserved parameters have no semantics and must be ignored by receivers.
pub fn encodeReservedParameter(writer: anytype, id: u64, value: []const u8) !void {
    try validateParameterIdVarInt(id);
    const value_len = try validateParameterValueLen(value);
    if (!isReservedParameterId(id)) return error.InvalidParameterValue;
    try packet.encodeVarInt(writer, id);
    try packet.encodeVarInt(writer, value_len);
    try writer.writeAll(value);
}

fn encodeConnectionIdValue(writer: anytype, id: ParameterId, cid: []const u8) !void {
    try validateConnectionIdLen(cid);
    try encodeBytesValue(writer, id, cid);
}

fn encodeZeroLengthValue(writer: anytype, id: ParameterId) !void {
    try packet.encodeVarInt(writer, @intFromEnum(id));
    try packet.encodeVarInt(writer, 0);
}

fn encodeStatelessResetToken(writer: anytype, token: [16]u8) !void {
    try encodeBytesValue(writer, .stateless_reset_token, &token);
}

fn encodePreferredAddress(writer: anytype, preferred: PreferredAddress) !void {
    try validatePreferredAddressConnectionIdLen(preferred.connection_id);

    var raw: [61]u8 = undefined;
    var value_writer = buffer.fixedWriter(&raw);
    try value_writer.writeAll(&preferred.ipv4_address);

    var port_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &port_buf, preferred.ipv4_port, .big);
    try value_writer.writeAll(&port_buf);

    try value_writer.writeAll(&preferred.ipv6_address);
    std.mem.writeInt(u16, &port_buf, preferred.ipv6_port, .big);
    try value_writer.writeAll(&port_buf);

    try value_writer.writeByte(@intCast(preferred.connection_id.len));
    try value_writer.writeAll(preferred.connection_id);
    try value_writer.writeAll(&preferred.stateless_reset_token);

    try encodeBytesValue(writer, .preferred_address, value_writer.getWritten());
}

fn validateVersion(version: packet.Version) !void {
    if (@intFromEnum(version) == 0) return error.InvalidParameterValue;
}

fn validateChosenVersion(version: packet.Version) !void {
    try validateVersion(version);
    if (packet.isReservedVersion(version)) return error.InvalidParameterValue;
}

fn versionInformationValueLen(available_count: usize) !u64 {
    const available_len = std.math.mul(usize, 4, available_count) catch return error.InvalidParameterLength;
    const value_len = std.math.add(usize, 4, available_len) catch return error.InvalidParameterLength;
    const value_len_u64 = std.math.cast(u64, value_len) orelse return error.InvalidParameterLength;
    if (value_len_u64 > max_quic_varint) return error.InvalidParameterLength;
    return value_len_u64;
}

fn encodeVersionInformation(writer: anytype, version_information: VersionInformation) !void {
    try validateChosenVersion(version_information.chosen_version);
    const value_len = try versionInformationValueLen(version_information.available_versions.len);
    for (version_information.available_versions) |available| {
        try validateVersion(available);
    }

    try packet.encodeVarInt(writer, @intFromEnum(ParameterId.version_information));
    try packet.encodeVarInt(writer, value_len);

    var version_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &version_buf, @intFromEnum(version_information.chosen_version), .big);
    try writer.writeAll(&version_buf);
    for (version_information.available_versions) |available| {
        std.mem.writeInt(u32, &version_buf, @intFromEnum(available), .big);
        try writer.writeAll(&version_buf);
    }
}

fn parsePreferredAddress(value: []const u8, allocator: std.mem.Allocator) !PreferredAddress {
    if (value.len < 41) return error.InvalidParameterLength;

    var reader_fbs = buffer.fixedReader(value);
    const reader = reader_fbs.reader();

    var ipv4_address: [4]u8 = undefined;
    try reader.readNoEof(&ipv4_address);

    var port_buf: [2]u8 = undefined;
    try reader.readNoEof(&port_buf);
    const ipv4_port = std.mem.readInt(u16, &port_buf, .big);

    var ipv6_address: [16]u8 = undefined;
    try reader.readNoEof(&ipv6_address);

    try reader.readNoEof(&port_buf);
    const ipv6_port = std.mem.readInt(u16, &port_buf, .big);

    const cid_len = try reader.readByte();
    if (cid_len == 0 or cid_len > max_connection_id_len) return error.InvalidParameterValue;
    const remaining = reader.remainingLen();
    if (remaining != @as(usize, cid_len) + 16) return error.InvalidParameterLength;

    const connection_id = try buffer.readOwnedBytes(reader, allocator, cid_len);
    errdefer allocator.free(connection_id);

    var stateless_reset_token: [16]u8 = undefined;
    try reader.readNoEof(&stateless_reset_token);

    return .{
        .ipv4_address = ipv4_address,
        .ipv4_port = ipv4_port,
        .ipv6_address = ipv6_address,
        .ipv6_port = ipv6_port,
        .connection_id = connection_id,
        .stateless_reset_token = stateless_reset_token,
    };
}

fn parseVersionInformation(value: []const u8, allocator: std.mem.Allocator) !VersionInformation {
    if (value.len < 4 or value.len % 4 != 0) return error.InvalidParameterLength;

    const chosen_version: packet.Version = @enumFromInt(std.mem.readInt(u32, value[0..4], .big));
    try validateChosenVersion(chosen_version);

    const available_count = value.len / 4 - 1;
    const available_versions = try allocator.alloc(packet.Version, available_count);
    errdefer allocator.free(available_versions);

    var offset: usize = 4;
    for (available_versions) |*available| {
        available.* = @enumFromInt(std.mem.readInt(u32, value[offset..][0..4], .big));
        try validateVersion(available.*);
        offset += 4;
    }

    return .{
        .chosen_version = chosen_version,
        .available_versions = available_versions,
    };
}

fn readValueSlice(reader: *buffer.FixedReader, value_len: u64) ![]const u8 {
    const len = std.math.cast(usize, value_len) orelse return error.InvalidParameterLength;
    if (len > reader.remainingLen()) return error.EndOfStream;
    const start = reader.pos;
    reader.pos += len;
    return reader.data[start..reader.pos];
}

fn rememberParameterId(seen: *std.ArrayList(u64), id: u64, allocator: std.mem.Allocator) !void {
    for (seen.items) |existing| {
        if (existing == id) return error.DuplicateParameter;
    }
    try seen.append(allocator, id);
}

/// Serialize typed transport parameters into RFC 9000 wire format.
pub fn encode(writer: anytype, params: TransportParameters) !void {
    if (params.original_destination_connection_id) |cid| {
        try encodeConnectionIdValue(writer, .original_destination_connection_id, cid);
    }
    if (params.max_idle_timeout != 0) {
        try encodeIntegerValue(writer, .max_idle_timeout, params.max_idle_timeout);
    }
    if (params.stateless_reset_token) |token| {
        try encodeStatelessResetToken(writer, token);
    }
    if (params.max_udp_payload_size != max_udp_payload_size_default) {
        try encodeIntegerValue(writer, .max_udp_payload_size, params.max_udp_payload_size);
    }
    if (params.initial_max_data != 0) {
        try encodeIntegerValue(writer, .initial_max_data, params.initial_max_data);
    }
    if (params.initial_max_stream_data_bidi_local != 0) {
        try encodeIntegerValue(writer, .initial_max_stream_data_bidi_local, params.initial_max_stream_data_bidi_local);
    }
    if (params.initial_max_stream_data_bidi_remote != 0) {
        try encodeIntegerValue(writer, .initial_max_stream_data_bidi_remote, params.initial_max_stream_data_bidi_remote);
    }
    if (params.initial_max_stream_data_uni != 0) {
        try encodeIntegerValue(writer, .initial_max_stream_data_uni, params.initial_max_stream_data_uni);
    }
    if (params.initial_max_streams_bidi != 0) {
        try encodeIntegerValue(writer, .initial_max_streams_bidi, params.initial_max_streams_bidi);
    }
    if (params.initial_max_streams_uni != 0) {
        try encodeIntegerValue(writer, .initial_max_streams_uni, params.initial_max_streams_uni);
    }
    if (params.ack_delay_exponent != 3) {
        try encodeIntegerValue(writer, .ack_delay_exponent, params.ack_delay_exponent);
    }
    if (params.max_ack_delay != 25) {
        try encodeIntegerValue(writer, .max_ack_delay, params.max_ack_delay);
    }
    if (params.disable_active_migration) {
        try encodeZeroLengthValue(writer, .disable_active_migration);
    }
    if (params.preferred_address) |preferred| {
        try encodePreferredAddress(writer, preferred);
    }
    if (params.active_connection_id_limit != 2) {
        try encodeIntegerValue(writer, .active_connection_id_limit, params.active_connection_id_limit);
    }
    if (params.initial_source_connection_id) |cid| {
        try encodeConnectionIdValue(writer, .initial_source_connection_id, cid);
    }
    if (params.retry_source_connection_id) |cid| {
        try encodeConnectionIdValue(writer, .retry_source_connection_id, cid);
    }
    if (params.version_information) |version_information| {
        try encodeVersionInformation(writer, version_information);
    }
}

/// Parse RFC 9000 transport parameters, ignoring unknown parameter IDs.
pub fn parse(data: []const u8, allocator: std.mem.Allocator) !TransportParameters {
    var result = TransportParameters{};
    errdefer result.deinit(allocator);

    var seen: std.ArrayList(u64) = .empty;
    defer seen.deinit(allocator);

    var reader_fbs = buffer.fixedReader(data);
    while (reader_fbs.remainingLen() != 0) {
        const id_raw = (try packet.decodeVarInt(reader_fbs.reader())).value;
        const value_len = (try packet.decodeVarInt(reader_fbs.reader())).value;
        try rememberParameterId(&seen, id_raw, allocator);
        const value = try readValueSlice(&reader_fbs, value_len);

        const id: ParameterId = @enumFromInt(id_raw);
        switch (id) {
            .original_destination_connection_id => {
                try validateConnectionIdLen(value);
                result.original_destination_connection_id = try cloneBytes(allocator, value);
            },
            .max_idle_timeout => result.max_idle_timeout = try parseIntegerValue(id, value),
            .stateless_reset_token => {
                if (value.len != 16) return error.InvalidParameterLength;
                var token: [16]u8 = undefined;
                @memcpy(&token, value);
                result.stateless_reset_token = token;
            },
            .max_udp_payload_size => result.max_udp_payload_size = try parseIntegerValue(id, value),
            .initial_max_data => result.initial_max_data = try parseIntegerValue(id, value),
            .initial_max_stream_data_bidi_local => result.initial_max_stream_data_bidi_local = try parseIntegerValue(id, value),
            .initial_max_stream_data_bidi_remote => result.initial_max_stream_data_bidi_remote = try parseIntegerValue(id, value),
            .initial_max_stream_data_uni => result.initial_max_stream_data_uni = try parseIntegerValue(id, value),
            .initial_max_streams_bidi => result.initial_max_streams_bidi = try parseIntegerValue(id, value),
            .initial_max_streams_uni => result.initial_max_streams_uni = try parseIntegerValue(id, value),
            .ack_delay_exponent => result.ack_delay_exponent = try parseIntegerValue(id, value),
            .max_ack_delay => result.max_ack_delay = try parseIntegerValue(id, value),
            .disable_active_migration => {
                if (value.len != 0) return error.InvalidParameterLength;
                result.disable_active_migration = true;
            },
            .preferred_address => result.preferred_address = try parsePreferredAddress(value, allocator),
            .active_connection_id_limit => result.active_connection_id_limit = try parseIntegerValue(id, value),
            .initial_source_connection_id => {
                try validateConnectionIdLen(value);
                result.initial_source_connection_id = try cloneBytes(allocator, value);
            },
            .retry_source_connection_id => {
                try validateConnectionIdLen(value);
                result.retry_source_connection_id = try cloneBytes(allocator, value);
            },
            .version_information => result.version_information = try parseVersionInformation(value, allocator),
            _ => {},
        }
    }

    return result;
}

test "transport parameters parse defaults from empty extension" {
    var params = try parse(&[_]u8{}, std.testing.allocator);
    defer params.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u64, 0), params.max_idle_timeout);
    try std.testing.expectEqual(@as(u64, max_udp_payload_size_default), params.max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, 3), params.ack_delay_exponent);
    try std.testing.expectEqual(@as(u64, 25), params.max_ack_delay);
    try std.testing.expectEqual(@as(u64, 2), params.active_connection_id_limit);
    try std.testing.expect(!params.disable_active_migration);
}

test "reserved transport parameter identifiers follow RFC 9000 greasing pattern" {
    try std.testing.expect(isReservedParameterId(27));
    try std.testing.expect(isReservedParameterId(58));
    try std.testing.expect(isReservedParameterId(89));
    try std.testing.expect(!isReservedParameterId(@intFromEnum(ParameterId.preferred_address)));
    try std.testing.expect(!isReservedParameterId(@intFromEnum(ParameterId.version_information)));
    try std.testing.expect(!isReservedParameterId(0));
}

test "transport parameters encode and parse typed values" {
    const reset_token = [_]u8{
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    };
    const preferred_token = [_]u8{
        0xf0, 0xf1, 0xf2, 0xf3,
        0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb,
        0xfc, 0xfd, 0xfe, 0xff,
    };
    const available_versions = [_]packet.Version{ .v2, .v1 };
    const preferred_cid = [_]u8{ 0xc1, 0xc2, 0xc3 };
    const params = TransportParameters{
        .original_destination_connection_id = &[_]u8{ 0xaa, 0xbb },
        .max_idle_timeout = 30_000,
        .stateless_reset_token = reset_token,
        .max_udp_payload_size = 1400,
        .initial_max_data = 65_536,
        .initial_max_stream_data_bidi_local = 1000,
        .initial_max_stream_data_bidi_remote = 2000,
        .initial_max_stream_data_uni = 3000,
        .initial_max_streams_bidi = 8,
        .initial_max_streams_uni = 4,
        .ack_delay_exponent = 10,
        .max_ack_delay = 50,
        .disable_active_migration = true,
        .preferred_address = .{
            .ipv4_address = .{ 127, 0, 0, 1 },
            .ipv4_port = 4433,
            .ipv6_address = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
            .ipv6_port = 4434,
            .connection_id = &preferred_cid,
            .stateless_reset_token = preferred_token,
        },
        .active_connection_id_limit = 4,
        .initial_source_connection_id = &[_]u8{0x11},
        .retry_source_connection_id = &[_]u8{0x22},
        .version_information = .{
            .chosen_version = .v1,
            .available_versions = &available_versions,
        },
    };

    var raw: [512]u8 = undefined;
    var writer = buffer.fixedWriter(&raw);
    try encode(writer.writer(), params);

    var parsed = try parse(writer.getWritten(), std.testing.allocator);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, params.original_destination_connection_id.?, parsed.original_destination_connection_id.?);
    try std.testing.expectEqual(params.max_idle_timeout, parsed.max_idle_timeout);
    try std.testing.expectEqualSlices(u8, &reset_token, &parsed.stateless_reset_token.?);
    try std.testing.expectEqual(params.max_udp_payload_size, parsed.max_udp_payload_size);
    try std.testing.expectEqual(params.initial_max_data, parsed.initial_max_data);
    try std.testing.expectEqual(params.initial_max_stream_data_bidi_local, parsed.initial_max_stream_data_bidi_local);
    try std.testing.expectEqual(params.initial_max_stream_data_bidi_remote, parsed.initial_max_stream_data_bidi_remote);
    try std.testing.expectEqual(params.initial_max_stream_data_uni, parsed.initial_max_stream_data_uni);
    try std.testing.expectEqual(params.initial_max_streams_bidi, parsed.initial_max_streams_bidi);
    try std.testing.expectEqual(params.initial_max_streams_uni, parsed.initial_max_streams_uni);
    try std.testing.expectEqual(params.ack_delay_exponent, parsed.ack_delay_exponent);
    try std.testing.expectEqual(params.max_ack_delay, parsed.max_ack_delay);
    try std.testing.expect(parsed.disable_active_migration);
    try std.testing.expectEqual(params.active_connection_id_limit, parsed.active_connection_id_limit);
    try std.testing.expectEqualSlices(u8, params.initial_source_connection_id.?, parsed.initial_source_connection_id.?);
    try std.testing.expectEqualSlices(u8, params.retry_source_connection_id.?, parsed.retry_source_connection_id.?);
    try std.testing.expectEqual(params.version_information.?.chosen_version, parsed.version_information.?.chosen_version);
    try std.testing.expectEqualSlices(packet.Version, params.version_information.?.available_versions, parsed.version_information.?.available_versions);
    try std.testing.expect(parsed.version_information.?.containsAvailableVersion(.v2));

    const preferred = parsed.preferred_address.?;
    try std.testing.expectEqualSlices(u8, &params.preferred_address.?.ipv4_address, &preferred.ipv4_address);
    try std.testing.expectEqual(params.preferred_address.?.ipv4_port, preferred.ipv4_port);
    try std.testing.expectEqualSlices(u8, &params.preferred_address.?.ipv6_address, &preferred.ipv6_address);
    try std.testing.expectEqual(params.preferred_address.?.ipv6_port, preferred.ipv6_port);
    try std.testing.expectEqualSlices(u8, params.preferred_address.?.connection_id, preferred.connection_id);
    try std.testing.expectEqualSlices(u8, &params.preferred_address.?.stateless_reset_token, &preferred.stateless_reset_token);
}

test "transport parameters reject malformed version information" {
    var raw: [64]u8 = undefined;
    var writer = buffer.fixedWriter(&raw);
    try encodeBytesValue(writer.writer(), .version_information, &[_]u8{ 0x00, 0x00, 0x00 });
    try std.testing.expectError(error.InvalidParameterLength, parse(writer.getWritten(), std.testing.allocator));

    writer = buffer.fixedWriter(&raw);
    try encodeBytesValue(writer.writer(), .version_information, &[_]u8{ 0x00, 0x00, 0x00, 0x00 });
    try std.testing.expectError(error.InvalidParameterValue, parse(writer.getWritten(), std.testing.allocator));

    writer = buffer.fixedWriter(&raw);
    try encodeBytesValue(writer.writer(), .version_information, &[_]u8{
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
    });
    try std.testing.expectError(error.InvalidParameterValue, parse(writer.getWritten(), std.testing.allocator));

    writer = buffer.fixedWriter(&raw);
    try encodeBytesValue(writer.writer(), .version_information, &[_]u8{
        0x0a, 0x0a, 0x0a, 0x0a,
        0x00, 0x00, 0x00, 0x01,
    });
    try std.testing.expectError(error.InvalidParameterValue, parse(writer.getWritten(), std.testing.allocator));

    const reserved_chosen = TransportParameters{
        .version_information = .{
            .chosen_version = @enumFromInt(0x0a0a0a0a),
            .available_versions = &[_]packet.Version{.v1},
        },
    };
    writer = buffer.fixedWriter(&raw);
    try std.testing.expectError(error.InvalidParameterValue, encode(writer.writer(), reserved_chosen));

    const reserved_available = TransportParameters{
        .version_information = .{
            .chosen_version = .v1,
            .available_versions = &[_]packet.Version{@enumFromInt(0x0a0a0a0a)},
        },
    };
    writer = buffer.fixedWriter(&raw);
    try encode(writer.writer(), reserved_available);
    var parsed_reserved_available = try parse(writer.getWritten(), std.testing.allocator);
    defer parsed_reserved_available.deinit(std.testing.allocator);
    try std.testing.expectEqual(packet.Version.v1, parsed_reserved_available.version_information.?.chosen_version);
    try std.testing.expect(parsed_reserved_available.version_information.?.containsAvailableVersion(@enumFromInt(0x0a0a0a0a)));

    const too_long = [_]packet.Version{ .v1, .v2 };
    writer = buffer.fixedWriter(raw[0..9]);
    try std.testing.expectError(error.NoSpaceLeft, encode(writer.writer(), .{
        .version_information = .{
            .chosen_version = .v1,
            .available_versions = &too_long,
        },
    }));

    const oversized_available: []const packet.Version = too_long[0..].ptr[0..std.math.maxInt(usize)];
    writer = buffer.fixedWriter(&raw);
    try std.testing.expectError(error.InvalidParameterLength, encode(writer.writer(), .{
        .version_information = .{
            .chosen_version = .v1,
            .available_versions = oversized_available,
        },
    }));
}

test "transport parameters ignore unknown parameters but reject duplicates" {
    var raw: [32]u8 = undefined;
    var writer = buffer.fixedWriter(&raw);
    try encodeReservedParameter(writer.writer(), 27, &[_]u8{ 0xaa, 0xbb });
    try encodeIntegerValue(writer.writer(), .initial_max_data, 42);

    var parsed = try parse(writer.getWritten(), std.testing.allocator);
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 42), parsed.initial_max_data);
    try std.testing.expectError(error.InvalidParameterValue, encodeReservedParameter(writer.writer(), 26, &[_]u8{}));

    var duplicate_raw: [16]u8 = undefined;
    var duplicate_writer = buffer.fixedWriter(&duplicate_raw);
    try encodeIntegerValue(duplicate_writer.writer(), .initial_max_data, 1);
    try encodeIntegerValue(duplicate_writer.writer(), .initial_max_data, 2);

    try std.testing.expectError(error.DuplicateParameter, parse(duplicate_writer.getWritten(), std.testing.allocator));
}

test "transport parameters reject invalid values and lengths" {
    var raw: [32]u8 = undefined;
    var writer = buffer.fixedWriter(&raw);
    try encodeUncheckedIntegerValue(writer.writer(), .max_udp_payload_size, 1199);
    try std.testing.expectError(error.InvalidParameterValue, parse(writer.getWritten(), std.testing.allocator));

    // RFC 9000 §18.2: max_udp_payload_size values above 65527 are invalid.
    writer = buffer.fixedWriter(&raw);
    try encodeUncheckedIntegerValue(writer.writer(), .max_udp_payload_size, max_udp_payload_size_default + 1);
    try std.testing.expectError(error.InvalidParameterValue, parse(writer.getWritten(), std.testing.allocator));

    writer = buffer.fixedWriter(&raw);
    try encodeBytesValue(writer.writer(), .stateless_reset_token, &[_]u8{0xaa});
    try std.testing.expectError(error.InvalidParameterLength, parse(writer.getWritten(), std.testing.allocator));

    writer = buffer.fixedWriter(&raw);
    try encodeUncheckedIntegerValue(writer.writer(), .ack_delay_exponent, 21);
    try std.testing.expectError(error.InvalidParameterValue, parse(writer.getWritten(), std.testing.allocator));

    writer = buffer.fixedWriter(&raw);
    try encodeUncheckedIntegerValue(writer.writer(), .max_ack_delay, 1 << 14);
    try std.testing.expectError(error.InvalidParameterValue, parse(writer.getWritten(), std.testing.allocator));

    writer = buffer.fixedWriter(&raw);
    try encodeUncheckedIntegerValue(writer.writer(), .active_connection_id_limit, 1);
    try std.testing.expectError(error.InvalidParameterValue, parse(writer.getWritten(), std.testing.allocator));
}

test "transport parameter encoders reject oversized varint fields before writing" {
    var raw: [16]u8 = undefined;
    var writer = buffer.fixedWriter(&raw);
    try std.testing.expectError(error.InvalidParameterValue, encode(writer.writer(), .{
        .max_idle_timeout = max_quic_varint + 1,
    }));
    try std.testing.expectEqual(@as(usize, 0), writer.getWritten().len);

    writer = buffer.fixedWriter(&raw);
    try std.testing.expectError(error.InvalidParameterValue, encodeReservedParameter(writer.writer(), max_quic_varint + 1, &[_]u8{}));
    try std.testing.expectEqual(@as(usize, 0), writer.getWritten().len);

    const oversized_len = std.math.cast(usize, max_quic_varint + 1) orelse return error.SkipZigTest;
    const oversized_value: []const u8 = @as([*]const u8, @ptrFromInt(1))[0..oversized_len];
    writer = buffer.fixedWriter(&raw);
    try std.testing.expectError(error.InvalidParameterLength, encodeBytesValue(writer.writer(), .stateless_reset_token, oversized_value));
    try std.testing.expectEqual(@as(usize, 0), writer.getWritten().len);
}

test "transport parameters reject malformed zero-length and preferred-address values" {
    var raw: [80]u8 = undefined;
    var writer = buffer.fixedWriter(&raw);
    try encodeBytesValue(writer.writer(), .disable_active_migration, &[_]u8{0x00});
    try std.testing.expectError(error.InvalidParameterLength, parse(writer.getWritten(), std.testing.allocator));

    writer = buffer.fixedWriter(&raw);
    const preferred = PreferredAddress{
        .ipv4_address = .{ 127, 0, 0, 1 },
        .ipv4_port = 4433,
        .ipv6_address = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .ipv6_port = 4434,
        .connection_id = &[_]u8{},
        .stateless_reset_token = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    };
    try std.testing.expectError(error.InvalidParameterValue, encodePreferredAddress(writer.writer(), preferred));

    writer = buffer.fixedWriter(&raw);
    try encodeBytesValue(writer.writer(), .preferred_address, &[_]u8{0x00});
    try std.testing.expectError(error.InvalidParameterLength, parse(writer.getWritten(), std.testing.allocator));
}

test "transport parameter parser preserves allocation failures" {
    var raw: [16]u8 = undefined;
    var writer = buffer.fixedWriter(&raw);
    try encodeConnectionIdValue(writer.writer(), .initial_source_connection_id, &[_]u8{ 0xaa, 0xbb });

    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
    try std.testing.expectError(error.OutOfMemory, parse(writer.getWritten(), failing_allocator.allocator()));
}
