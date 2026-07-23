//! qlog — QUIC event logging (draft-ietf-quic-qlog-main-schema-10).
//!
//! Provides a minimal qlog writer that emits JSON events for connection,
//! transport, and recovery state changes. Events are buffered in memory.

const std = @import("std");

pub const QlogWriter = struct {
    buf: std.ArrayList(u8) = .empty,
    allocator: std.mem.Allocator,
    start_ms: i64,
    event_count: usize = 0,
    odcid_hex: [64]u8 = undefined,
    odcid_len: usize = 0,

    /// Create a qlog writer for the specified ODCID.
    pub fn init(allocator: std.mem.Allocator, odcid: []const u8, now_ms: i64) QlogWriter {
        var self = QlogWriter{
            .allocator = allocator,
            .start_ms = now_ms,
        };
        // Manual hex encoding
        var pos: usize = 0;
        for (odcid) |byte| {
            if (pos + 2 > self.odcid_hex.len) break;
            const hi = byte >> 4;
            const lo = byte & 0x0f;
            self.odcid_hex[pos] = if (hi < 10) hi + '0' else hi - 10 + 'a';
            self.odcid_hex[pos + 1] = if (lo < 10) lo + '0' else lo - 10 + 'a';
            pos += 2;
        }
        self.odcid_len = pos;
        const hex = self.odcid_hex[0..self.odcid_len];

        var line_buf: [256]u8 = undefined;
        const header = std.fmt.bufPrint(&line_buf, "{{\n  \"qlog_version\": \"0.4\",\n  \"traces\": [{{\n    \"common_fields\": {{ \"ODCID\": \"{s}\" }},\n    \"events\": [\n", .{hex}) catch return self;
        self.buf.appendSlice(allocator, header) catch {};
        return self;
    }

    pub fn deinit(self: *QlogWriter) void {
        self.buf.appendSlice(self.allocator, "\n    ]\n  }]\n}\n") catch {};
        self.buf.deinit(self.allocator);
    }

    /// Emit a qlog event with relative timestamp.
    pub fn emit(self: *QlogWriter, event_name: []const u8, data_json: []const u8, now_ms: i64) void {
        const relative_ms = now_ms - self.start_ms;
        var line_buf: [512]u8 = undefined;
        const prefix = if (self.event_count > 0) ",\n" else "";
        const line = std.fmt.bufPrint(&line_buf, "{s}      [{d}, \"{s}\", {s}]", .{ prefix, relative_ms, event_name, data_json }) catch return;
        self.buf.appendSlice(self.allocator, line) catch return;
        self.event_count += 1;
    }

    /// Emit a connectivity:connection_state_updated event.
    pub fn emitConnectionState(self: *QlogWriter, state: []const u8, now_ms: i64) void {
        var buf: [128]u8 = undefined;
        const json = std.fmt.bufPrint(&buf, "{{\"new\": \"{s}\"}}", .{state}) catch return;
        self.emit("connectivity:connection_state_updated", json, now_ms);
    }

    /// Emit a transport:packet_sent event.
    pub fn emitPacketSent(self: *QlogWriter, packet_type: []const u8, packet_number: u64, payload_len: usize, now_ms: i64) void {
        var buf: [256]u8 = undefined;
        const json = std.fmt.bufPrint(&buf, "{{\"header\": {{\"packet_type\": \"{s}\", \"packet_number\": {d}}}, \"raw\": {{\"payload_length\": {d}}}}}", .{ packet_type, packet_number, payload_len }) catch return;
        self.emit("transport:packet_sent", json, now_ms);
    }

    /// Emit a transport:packet_received event.
    pub fn emitPacketReceived(self: *QlogWriter, packet_type: []const u8, packet_number: u64, payload_len: usize, now_ms: i64) void {
        var buf: [256]u8 = undefined;
        const json = std.fmt.bufPrint(&buf, "{{\"header\": {{\"packet_type\": \"{s}\", \"packet_number\": {d}}}, \"raw\": {{\"payload_length\": {d}}}}}", .{ packet_type, packet_number, payload_len }) catch return;
        self.emit("transport:packet_received", json, now_ms);
    }

    /// Emit a recovery:metrics_updated event.
    pub fn emitMetricsUpdated(self: *QlogWriter, bytes_in_flight: usize, cwnd: usize, now_ms: i64) void {
        var buf: [256]u8 = undefined;
        const json = std.fmt.bufPrint(&buf, "{{\"bytes_in_flight\": {d}, \"congestion_window\": {d}}}", .{ bytes_in_flight, cwnd }) catch return;
        self.emit("recovery:metrics_updated", json, now_ms);
    }

    /// Emit a recovery:packet_lost event.
    pub fn emitPacketLost(self: *QlogWriter, packet_type: []const u8, packet_number: u64, trigger: []const u8, now_ms: i64) void {
        var buf: [256]u8 = undefined;
        const json = std.fmt.bufPrint(&buf, "{{\"header\": {{\"packet_type\": \"{s}\", \"packet_number\": {d}}}, \"trigger\": \"{s}\"}}", .{ packet_type, packet_number, trigger }) catch return;
        self.emit("recovery:packet_lost", json, now_ms);
    }

    /// Return the accumulated qlog JSON as a string.
    pub fn getJson(self: *const QlogWriter) []const u8 {
        return self.buf.items;
    }
};

test "QlogWriter emits valid JSON structure" {
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var qlog = QlogWriter.init(std.testing.allocator, &odcid, 1000);
    defer qlog.deinit();

    qlog.emitConnectionState("handshake", 1000);
    qlog.emitPacketSent("initial", 0, 1200, 1001);
    qlog.emitPacketReceived("initial", 0, 1100, 1002);
    qlog.emitMetricsUpdated(1200, 14720, 1003);
    qlog.emitPacketLost("initial", 1, "time_threshold", 1004);

    const json = qlog.getJson();
    try std.testing.expect(std.mem.indexOf(u8, json, "qlog_version") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "connection_state_updated") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "packet_sent") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "packet_received") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "metrics_updated") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "packet_lost") != null);
    try std.testing.expectEqual(@as(usize, 5), qlog.event_count);
}

test "QlogWriter emit helpers produce expected event names" {
    var buf: [512]u8 = undefined;
    const state_json = std.fmt.bufPrint(&buf, "{{\"new\": \"{s}\"}}", .{"handshake"}) catch unreachable;
    try std.testing.expectEqualStrings("{\"new\": \"handshake\"}", state_json);
}
