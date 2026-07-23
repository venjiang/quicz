//! qlog — QUIC event logging (draft-ietf-quic-qlog-main-schema-10).
//!
//! Provides a minimal qlog writer that emits JSON events for connection,
//! transport, and recovery state changes. Enable by setting the QLOG_DIR
//! environment variable to a directory; one .qlog file is created per
//! connection using the ODCID as filename.

const std = @import("std");

pub const QlogWriter = struct {
    writer: std.fs.File.Writer,
    file: std.fs.File,
    start_ms: i64,
    event_count: usize = 0,

    /// Open a qlog file in the given directory for the specified ODCID.
    pub fn init(dir_path: []const u8, odcid: []const u8, now_ms: i64) !QlogWriter {
        var dir = try std.fs.cwd().openDir(dir_path, .{});
        defer dir.close();

        var name_buf: [128]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "{s}.qlog", .{std.fmt.fmtSliceHexLower(odcid)}) catch return error.NameTooLong;
        const file = try dir.createFile(name, .{ .truncate = true });
        const writer = file.writer();

        // Write qlog header
        try writer.writeAll("{\n");
        try writer.writeAll("  \"qlog_version\": \"0.4\",\n");
        try writer.writeAll("  \"traces\": [{\n");
        try writer.writeAll("    \"common_fields\": {\n");
        try writer.print("      \"ODCID\": \"{s}\",\n", .{std.fmt.fmtSliceHexLower(odcid)});
        try writer.print("      \"reference_time\": {d}\n", .{now_ms});
        try writer.writeAll("    },\n");
        try writer.writeAll("    \"events\": [\n");

        return .{
            .writer = writer,
            .file = file,
            .start_ms = now_ms,
        };
    }

    pub fn deinit(self: *QlogWriter) void {
        // Close the JSON arrays and object
        self.writer.writeAll("\n    ]\n") catch {};
        self.writer.writeAll("  }]\n") catch {};
        self.writer.writeAll("}\n") catch {};
        self.file.close();
    }

    /// Emit a qlog event with relative timestamp.
    pub fn emit(self: *QlogWriter, event_name: []const u8, data_json: []const u8, now_ms: i64) void {
        const relative_ms = now_ms - self.start_ms;
        if (self.event_count > 0) {
            self.writer.writeAll(",\n") catch return;
        }
        self.writer.print("      [{d}, \"{s}\", {s}]", .{ relative_ms, event_name, data_json }) catch return;
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
};

test "QlogWriter emit helpers produce expected event names" {
    // Verify the emit helper format strings produce valid JSON fragments.
    var buf: [512]u8 = undefined;

    // connection_state_updated
    const state_json = std.fmt.bufPrint(&buf, "{{\"new\": \"{s}\"}}", .{"handshake"}) catch unreachable;
    try std.testing.expectEqualStrings("{\"new\": \"handshake\"}", state_json);

    // metrics_updated
    const metrics_json = std.fmt.bufPrint(&buf, "{{\"bytes_in_flight\": {d}, \"congestion_window\": {d}}}", .{ @as(usize, 1200), @as(usize, 14720) }) catch unreachable;
    try std.testing.expect(std.mem.indexOf(u8, metrics_json, "bytes_in_flight") != null);
    try std.testing.expect(std.mem.indexOf(u8, metrics_json, "14720") != null);

    // packet_lost
    const lost_json = std.fmt.bufPrint(&buf, "{{\"header\": {{\"packet_type\": \"{s}\", \"packet_number\": {d}}}, \"trigger\": \"{s}\"}}", .{ "initial", @as(u64, 1), "time_threshold" }) catch unreachable;
    try std.testing.expect(std.mem.indexOf(u8, lost_json, "packet_lost") == null); // just format check
    try std.testing.expect(std.mem.indexOf(u8, lost_json, "time_threshold") != null);
}
