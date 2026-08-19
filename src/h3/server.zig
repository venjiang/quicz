//! HTTP/3 server handler (RFC 9114 §4-6).
//!
//! Processes incoming H3 requests over QUIC streams and sends responses.
//! Works with any QUIC Connection that provides stream I/O.

const std = @import("std");
const h3_frame = @import("frame.zig");
const h3_request = @import("request.zig");
const h3_connection = @import("connection.zig");
const qpack = @import("qpack.zig");
const h3_limits = @import("limits.zig");
const buffer = @import("../quic/buffer.zig");

/// H3 server request handler callback.
/// Receives a decoded request, returns a response to send.
pub const RequestHandler = *const fn (req: h3_request.DecodedRequest) h3_request.Response;

/// HTTP/3 server state machine over a QUIC connection.
pub const H3Server = struct {
    conn: *H3ServerConnection,
    handler: RequestHandler,
    allocator: std.mem.Allocator,
    control_stream_id: ?u64 = null,
    settings_sent: bool = false,
    goaway_sent: bool = false,
    goaway_last_stream_id: ?u64 = null,
    /// Advertised SETTINGS_MAX_FIELD_SECTION_SIZE: the largest field section this
    /// endpoint accepts from the peer (RFC 9114 §7.2.4.1).
    local_max_field_section_size: u64 = 8192,

    /// Server's encoder table for responses. Produces Insert/Duplicate/SetCapacity
    /// instructions sent on the QPACK encoder stream (type 0x02) to the client.
    enc_table: ?qpack.DynamicTable = null,
    /// Mirror of the client's encoder table for requests. Updated by consuming
    /// the client's encoder stream instructions via processPeerEncoderStream.
    dec_table: ?qpack.DynamicTable = null,
    /// Server's QPACK encoder stream (type 0x02).
    enc_stream_id: ?u64 = null,
    /// Server's QPACK decoder stream (type 0x03).
    dec_stream_id: ?u64 = null,
    /// Required Insert Count of each dynamic section sent on a stream, keyed by
    /// stream ID, so peer Section Acknowledgment can raise Known Received Count.
    pending_sections: ?std.AutoHashMap(u64, u64) = null,
    /// Number of peer insertions this decoder has already acknowledged via
    /// Insert Count Increment, for emitting only the outstanding delta.
    decoder_known_insert_count: u64 = 0,
    /// This decoder's advertised SETTINGS_QPACK_MAX_TABLE_CAPACITY, sent in the
    /// control-stream SETTINGS frame (RFC 9204 §3.2.3). The peer encoder must
    /// not exceed it.
    local_qpack_max_table_capacity: u64 = 0,
    /// Peer's advertised SETTINGS_QPACK_MAX_TABLE_CAPACITY. Caps this encoder's
    /// dynamic table; zero means the peer has not advertised one (capacity 0).
    peer_qpack_max_table_capacity: u64 = 0,
    /// Capacity requested via enableQpackDynamic, before peer SETTINGS capping.
    enc_capacity_requested: usize = 0,
    /// Encoded request bytes awaiting QPACK insertions (RFC 9204 §2.2.1), keyed
    /// by stream ID until the encoder stream supplies the Required Insert Count.
    blocked_requests: ?std.AutoHashMap(u64, []u8) = null,
    /// Advertised SETTINGS_QPACK_BLOCKED_STREAMS: the maximum number of streams
    /// this decoder keeps blocked at once (RFC 9204 §2.1.2).
    max_blocked_streams: u64 = 0,
    /// Per-stream request body cap (RFC 9114 §6.1). Excess is rejected with 413
    /// + H3_EXCESSIVE_LOAD on the stream.
    max_request_body_size: usize = h3_limits.max_request_body_size,

    /// In-flight request streams (headers + aggregated body), keyed by stream ID.
    requests: std.AutoHashMap(u64, RequestStream) = undefined,
    /// In-flight response streams (streamed or chunked body pending DATA frames),
    /// keyed by stream ID.
    responses: std.AutoHashMap(u64, ResponseStream) = undefined,

    /// Per-stream request/response state. `decoded` borrows `headers_wire`, so
    /// the stream entry must survive until the response fin is sent (query via
    /// `streamDone`); the runtime driver releases its buffers only then.
    const RequestStream = struct {
        phase: enum { headers, body } = .headers,
        /// Wire bytes accumulated during the headers phase. Shrunk to exactly
        /// the HEADERS frame once decoded; `decoded` borrows it as its anchor.
        wire: std.ArrayList(u8),
        /// Unparsed body-frame wire bytes accumulated across feeds (a DATA
        /// frame may span datagrams). Parsed payloads move into `body`.
        body_wire: std.ArrayList(u8),
        /// Aggregated DATA payloads (the request body).
        body: std.ArrayList(u8),
        /// Peer FIN arrived; the body is complete and the handler may run.
        body_fin: bool = false,
        /// True while the QPACK decoder awaits insertions from the peer's
        /// encoder stream (RFC 9204 §2.2.1). `wire` keeps accumulating.
        blocked: bool = false,
        /// Sink for non-pseudo request headers, kept in the stream so
        /// `decoded.headers` stays valid until the handler runs.
        request_headers: [32]qpack.HeaderField = undefined,
        decoded: ?h3_request.DecodedRequest = null,
    };

    const ResponseStream = struct {
        /// Lazy chunked body; takes precedence over `static_body`.
        body: ?h3_request.ResponseBody = null,
        /// Fixed-slice body (from `Response.body`) pumped in chunks.
        static_body: []const u8 = &.{},
        static_off: usize = 0,
    };

    pub const H3ServerConnection = struct {
        /// Open a locally-initiated unidirectional stream.
        openUniStreamFn: *const fn (ctx: *anyopaque) anyerror!u64,
        /// Send data on a stream.
        sendOnStreamFn: *const fn (ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) anyerror!void,
        /// Receive data from a stream. Returns null if no data available.
        recvOnStreamFn: *const fn (ctx: *anyopaque, stream_id: u64, buf: []u8) anyerror!?usize,
        /// Report whether the peer has sent FIN on a stream (direct-connection
        /// path; the runtime driver signals EOF via a zero-length recv instead).
        /// Optional: when null, the state machine treats the stream as finished
        /// only when the caller passes `fin=true`.
        streamRecvFinFn: ?*const fn (ctx: *anyopaque, stream_id: u64) bool = null,
        /// Opaque context pointer.
        ctx: *anyopaque,

        pub fn openUniStream(self: *H3ServerConnection) !u64 {
            return self.openUniStreamFn(self.ctx);
        }
        pub fn sendOnStream(self: *H3ServerConnection, stream_id: u64, data: []const u8, fin: bool) !void {
            return self.sendOnStreamFn(self.ctx, stream_id, data, fin);
        }
        pub fn recvOnStream(self: *H3ServerConnection, stream_id: u64, buf: []u8) !?usize {
            return self.recvOnStreamFn(self.ctx, stream_id, buf);
        }
        pub fn streamRecvFin(self: *H3ServerConnection, stream_id: u64) bool {
            if (self.streamRecvFinFn) |f| return f(self.ctx, stream_id);
            return false;
        }
    };

    /// Initialize the server and send SETTINGS on the control stream.
    pub fn init(
        conn: *H3ServerConnection,
        handler: RequestHandler,
        allocator: std.mem.Allocator,
        qpack_max_table_capacity: u64,
        qpack_blocked_streams: u64,
    ) !H3Server {
        var server = H3Server{
            .conn = conn,
            .handler = handler,
            .allocator = allocator,
            .local_qpack_max_table_capacity = qpack_max_table_capacity,
            .max_blocked_streams = qpack_blocked_streams,
            .requests = std.AutoHashMap(u64, RequestStream).init(allocator),
            .responses = std.AutoHashMap(u64, ResponseStream).init(allocator),
        };
        try server.sendSettings();
        return server;
    }

    /// Release QPACK dynamic table resources.
    pub fn deinit(self: *H3Server) void {
        if (self.enc_table) |*t| t.deinit();
        if (self.dec_table) |*t| t.deinit();
        if (self.pending_sections) |*m| m.deinit();
        if (self.blocked_requests) |*m| {
            var it = m.iterator();
            while (it.next()) |entry| self.allocator.free(entry.value_ptr.*);
            m.deinit();
        }
        var rit = self.requests.valueIterator();
        while (rit.next()) |rs| {
            rs.wire.deinit(self.allocator);
            rs.body_wire.deinit(self.allocator);
            rs.body.deinit(self.allocator);
        }
        self.requests.deinit();
        var sit = self.responses.valueIterator();
        while (sit.next()) |rs| {
            if (rs.body) |b| b.deinit();
        }
        self.responses.deinit();
    }

    /// Enable QPACK dynamic table compression (RFC 9204).
    /// Opens QPACK encoder (0x02) and decoder (0x03) unidirectional streams,
    /// initializes both tables, and advertises capacity to the peer via a
    /// Set Capacity instruction on the encoder stream. The encoder capacity is
    /// capped by the peer's advertised SETTINGS_QPACK_MAX_TABLE_CAPACITY; when
    /// the peer has not advertised one, the encoder must stay at capacity zero
    /// and send no encoder instructions (RFC 9204 §3.2.3).
    pub fn enableQpackDynamic(self: *H3Server, capacity: usize) !void {
        self.enc_capacity_requested = capacity;
        const enc_capacity: usize = @intCast(@min(capacity, self.peer_qpack_max_table_capacity));
        self.enc_table = qpack.DynamicTable.init(self.allocator);
        self.dec_table = qpack.DynamicTable.init(self.allocator);
        self.pending_sections = std.AutoHashMap(u64, u64).init(self.allocator);
        self.blocked_requests = std.AutoHashMap(u64, []u8).init(self.allocator);
        self.enc_table.?.setCapacity(enc_capacity);
        self.dec_table.?.setCapacity(@intCast(self.local_qpack_max_table_capacity));

        // Open encoder stream (type 0x02) and send Set Capacity.
        self.enc_stream_id = try self.conn.openUniStream();
        var enc_buf: [32]u8 = undefined;
        var pos: usize = 0;
        enc_buf[pos] = 0x02;
        pos += 1;
        if (enc_capacity > 0) {
            pos += try qpack.encodeEncoderInstruction(enc_buf[pos..], .{ .set_capacity = enc_capacity });
        }
        try self.conn.sendOnStream(self.enc_stream_id.?, enc_buf[0..pos], false);

        // Open decoder stream (type 0x03).
        self.dec_stream_id = try self.conn.openUniStream();
        var dec_buf: [4]u8 = undefined;
        dec_buf[0] = 0x03;
        try self.conn.sendOnStream(self.dec_stream_id.?, dec_buf[0..1], false);
    }

    /// Record the peer's advertised SETTINGS_QPACK_MAX_TABLE_CAPACITY. If the
    /// dynamic table is already enabled and the new limit is lower, reduce the
    /// encoder capacity and re-issue Set Capacity (RFC 9204 §3.2.3).
    pub fn setPeerMaxTableCapacity(self: *H3Server, capacity: u64) !void {
        self.peer_qpack_max_table_capacity = capacity;
        if (self.enc_table) |*et| {
            const effective: usize = @intCast(@min(self.enc_capacity_requested, capacity));
            if (effective != et.max_capacity) {
                et.setCapacity(effective);
                if (effective > 0) {
                    var buf: [16]u8 = undefined;
                    const len = try qpack.encodeEncoderInstruction(&buf, .{ .set_capacity = effective });
                    try self.conn.sendOnStream(self.enc_stream_id.?, buf[0..len], false);
                }
            }
        }
    }

    /// Feed peer (client) encoder stream data into the decoder-side dynamic
    /// table so subsequent request header blocks with dynamic references
    /// resolve correctly (RFC 9204 §4.3).
    pub fn processPeerEncoderStream(self: *H3Server, data: []const u8) !void {
        if (self.dec_table) |*dt| {
            _ = try qpack.decodeEncoderStreamInstructions(data, dt);
            if (dt.max_capacity > self.local_qpack_max_table_capacity) {
                return error.QpackCapacityExceedsSettings;
            }
        }
        try self.unblockBlockedRequests();
        try self.pumpResponses();
    }

    /// Process the peer's control stream: parse SETTINGS and apply the
    /// advertised QPACK table capacity (RFC 9114 §6.2.1 / RFC 9204 §3.2.3).
    pub fn processPeerControlStream(self: *H3Server, data: []const u8) !void {
        var pos: usize = 0;
        if (pos < data.len and data[pos] == 0x00) pos += 1; // stream type
        while (pos < data.len) {
            const frame = try h3_frame.decodeFrame(data[pos..]);
            if (frame.frame.frame_type == @intFromEnum(h3_frame.FrameType.settings)) {
                const settings = try h3_connection.Settings.decodePayload(frame.frame.payload);
                if (settings.qpack_max_table_capacity != 0) {
                    try self.setPeerMaxTableCapacity(settings.qpack_max_table_capacity);
                }
            }
            if (frame.consumed == 0) break;
            pos += frame.consumed;
        }
    }

    /// Feed peer (client) decoder stream data into the encoder-side table so
    /// Section Acknowledgment / Insert Count Increment advance the Known
    /// Received Count (RFC 9204 §4.4).
    pub fn processPeerDecoderStream(self: *H3Server, data: []const u8) !void {
        if (self.enc_table) |*et| {
            if (self.pending_sections) |*ps| {
                _ = try qpack.decodeDecoderStreamInstructions(data, et, ps);
            }
        }
    }

    /// Emit Section Acknowledgment (when the decoded section used dynamic
    /// references) and any outstanding Insert Count Increment on the QPACK
    /// decoder stream (RFC 9204 §4.4).
    fn sendSectionAcknowledgement(self: *H3Server, stream_id: u64, required_insert_count: u64) !void {
        const dec_stream_id = self.dec_stream_id orelse return;
        var buf: [32]u8 = undefined;
        var pos: usize = 0;
        if (required_insert_count > 0) {
            pos += try qpack.encodeDecoderInstruction(buf[pos..], .{ .section_ack = stream_id });
        }
        if (self.dec_table) |*dt| {
            if (dt.insert_count > self.decoder_known_insert_count) {
                const increment = dt.insert_count - self.decoder_known_insert_count;
                pos += try qpack.encodeDecoderInstruction(buf[pos..], .{ .insert_count_increment = increment });
                self.decoder_known_insert_count = dt.insert_count;
            }
        }
        if (pos > 0) try self.conn.sendOnStream(dec_stream_id, buf[0..pos], false);
    }

    /// Open the server control stream and send SETTINGS.
    fn sendSettings(self: *H3Server) !void {
        const stream_id = try self.conn.openUniStream();
        self.control_stream_id = stream_id;

        // Control stream: stream type (0x00) + SETTINGS frame
        var buf: [128]u8 = undefined;
        var pos: usize = 0;

        // Stream type: control (0x00)
        buf[pos] = 0x00;
        pos += 1;

        // SETTINGS frame: max_field_section_size + advertised QPACK capacity.
        var settings_payload: [32]u8 = undefined;
        const settings = h3_connection.Settings{
            .max_field_section_size = self.local_max_field_section_size,
            .qpack_max_table_capacity = self.local_qpack_max_table_capacity,
            .qpack_blocked_streams = self.max_blocked_streams,
        };
        const sp_len = try settings.encodePayload(&settings_payload);

        // Frame type (0x04) + length + payload
        buf[pos] = 0x04; // SETTINGS frame type
        pos += 1;
        buf[pos] = @intCast(sp_len);
        pos += 1;
        @memcpy(buf[pos .. pos + sp_len], settings_payload[0..sp_len]);
        pos += sp_len;

        try self.conn.sendOnStream(stream_id, buf[0..pos], false);
        self.settings_sent = true;
    }

    /// Process an incoming request on a bidi stream.
    /// Reads the request, calls the handler, and sends the response. When the
    /// QPACK decoder lacks the required insertions, the request bytes are
    /// buffered until the peer's encoder stream supplies them (RFC 9204 §2.2.1).
    pub fn handleRequestStream(self: *H3Server, stream_id: u64) !void {
        // Read request data
        var req_buf: [8192]u8 = undefined;
        var total_read: usize = 0;

        // Poll for data
        while (total_read < req_buf.len) {
            const n = try self.conn.recvOnStream(stream_id, req_buf[total_read..]) orelse break;
            total_read += n;
            // Check if we have a complete HEADERS frame
            if (total_read > 0) {
                _ = h3_frame.decodeFrame(req_buf[0..total_read]) catch continue;
                break;
            }
        }

        if (total_read == 0) return;
        const request_frame = try h3_frame.decodeFrame(req_buf[0..total_read]);
        if (request_frame.frame.payload.len > self.local_max_field_section_size) {
            return error.FieldSectionTooLarge;
        }
        if (try self.tryProcessRequest(stream_id, req_buf[0..total_read])) {
            try self.pumpResponses();
            return;
        }

        // Blocked: retain the request and retry after encoder stream progress.
        try self.bufferBlockedRequest(stream_id, req_buf[0..total_read]);
    }

    /// Feed already-buffered request bytes (a complete HEADERS frame) into the
    /// server. The runtime driver reads the wire itself and hands the frame
    /// here so it can interleave QPACK control streams instead of blocking on
    /// one request stream. Returns `processed` when a response was sent, or
    /// `blocked` when the request waits for QPACK insertions (the state machine
    /// keeps its own copy and retries on encoder-stream progress).
    pub const FeedResult = enum { processed, blocked, need_more };

    /// Result of feeding request bytes: `processed` (handler ran, response
    /// started), `blocked` (QPACK pending insertions), `need_more` (partial
    /// frame, buffer more). `consumed` is the number of input bytes the state
    /// machine owns (the driver may shrink its buffer by that amount).
    pub const FeedDataResult = struct { result: FeedResult, consumed: usize };

    /// Whether an HTTP method is HEAD; such responses send headers only.
    fn isHeadMethod(method: []const u8) bool {
        return std.mem.eql(u8, method, "HEAD");
    }

    pub fn feedRequestBytes(self: *H3Server, stream_id: u64, data: []const u8) !FeedResult {
        const frame = try h3_frame.decodeFrame(data);
        if (frame.frame.frame_type != @intFromEnum(h3_frame.FrameType.headers)) {
            return error.ExpectedHeadersFrame;
        }
        if (frame.frame.payload.len > self.local_max_field_section_size) {
            return error.FieldSectionTooLarge;
        }
        if (try self.tryProcessRequest(stream_id, data)) return .processed;
        try self.bufferBlockedRequest(stream_id, data);
        return .blocked;
    }

    /// Streaming request entry point. Feed wire bytes (and EOF via `fin`) for a
    /// bidi request stream; the state machine buffers the HEADERS frame, then
    /// aggregates DATA payloads up to `max_request_body_size`, and runs the
    /// handler once the body has fully arrived. `consumed` lets the driver
    /// shrink its own buffer (the state machine owns a copy).
    pub fn feedRequestData(self: *H3Server, stream_id: u64, data: []const u8, fin: bool) !FeedDataResult {
        const gop = try self.requests.getOrPut(stream_id);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .wire = std.ArrayList(u8).empty,
                .body_wire = std.ArrayList(u8).empty,
                .body = std.ArrayList(u8).empty,
            };
        }
        const rs = gop.value_ptr;

        if (rs.phase == .headers) {
            try rs.wire.appendSlice(self.allocator, data);
            // Clients may send GREASE / unknown extension frames before the
            // initial HEADERS frame (RFC 9114 §7.2.8, §9); quiche greases the
            // request stream in production. Skip and scan for the first
            // HEADERS frame.
            var frame = h3_frame.decodeFrame(rs.wire.items) catch |e| switch (e) {
                error.IncompleteFrame => return .{ .result = .need_more, .consumed = data.len },
                else => return e,
            };
            while (h3_frame.isIgnorableHeaderPrefixFrame(frame.frame.frame_type)) {
                if (frame.consumed == rs.wire.items.len) {
                    rs.wire.clearRetainingCapacity();
                } else {
                    std.mem.copyForwards(u8, rs.wire.items[0 .. rs.wire.items.len - frame.consumed], rs.wire.items[frame.consumed..]);
                    rs.wire.shrinkRetainingCapacity(rs.wire.items.len - frame.consumed);
                }
                frame = h3_frame.decodeFrame(rs.wire.items) catch |e| switch (e) {
                    error.IncompleteFrame => return .{ .result = .need_more, .consumed = data.len },
                    else => return e,
                };
            }
            if (frame.frame.frame_type != @intFromEnum(h3_frame.FrameType.headers)) {
                return error.ExpectedHeadersFrame;
            }
            if (frame.frame.payload.len > self.local_max_field_section_size) {
                return error.FieldSectionTooLarge;
            }

            var ric: u64 = 0;
            // decodeRequest expects the full HEADERS frame (type + length +
            // QPACK block), not just its payload.
            const headers_wire = rs.wire.items[0..frame.consumed];
            const decoded = if (self.dec_table) |*dt| blk: {
                const r = h3_request.decodeRequestWithDynamicWithHeaders(headers_wire, dt, &rs.request_headers) catch |e| {
                    if (e == error.BlockedByQpack) {
                        rs.blocked = true;
                        return .{ .result = .blocked, .consumed = data.len };
                    }
                    return e;
                };
                ric = r.required_insert_count;
                break :blk r.request;
            } else (try h3_request.decodeRequestWithHeaders(headers_wire, &rs.request_headers)).request;
            try self.sendSectionAcknowledgement(stream_id, ric);

            // Retain only the HEADERS frame in `wire` (the decoded request
            // borrows it); any trailing DATA bytes go to `body_wire`.
            if (frame.consumed < rs.wire.items.len) {
                try rs.body_wire.appendSlice(self.allocator, rs.wire.items[frame.consumed..]);
            }
            rs.wire.shrinkRetainingCapacity(frame.consumed);
            rs.decoded = decoded;
            rs.phase = .body;
        } else {
            try rs.body_wire.appendSlice(self.allocator, data);
        }

        try self.parseBody(stream_id, rs);

        if (fin) rs.body_fin = true;
        if (rs.body_fin) {
            // Body is now stable; expose it to the handler and start the response.
            if (rs.decoded) |*d| d.body = if (rs.body.items.len > 0) rs.body.items else null;
            const resp = self.handler(rs.decoded.?);
            try self.startResponse(stream_id, resp, isHeadMethod(rs.decoded.?.method));
            return .{ .result = .processed, .consumed = data.len };
        }
        return .{ .result = .need_more, .consumed = data.len };
    }

    /// Parse complete DATA frames out of `body_wire`, aggregating their
    /// payloads into `body`, bounded by `max_request_body_size`. A trailing
    /// partial frame stays buffered for the next feed.
    fn parseBody(self: *H3Server, stream_id: u64, rs: *RequestStream) !void {
        var off: usize = 0;
        while (off < rs.body_wire.items.len) {
            const frame = h3_request.takeDataFrame(rs.body_wire.items[off..]) catch |e| switch (e) {
                error.IncompleteFrame => break,
                else => return e,
            };
            if (rs.body.items.len + frame.payload.len > self.max_request_body_size) {
                return error.RequestBodyTooLarge;
            }
            try rs.body.appendSlice(self.allocator, frame.payload);
            off += frame.consumed;
        }
        if (off > 0) {
            std.mem.copyForwards(u8, rs.body_wire.items[0 .. rs.body_wire.items.len - off], rs.body_wire.items[off..]);
            rs.body_wire.shrinkRetainingCapacity(rs.body_wire.items.len - off);
        }
        _ = stream_id;
    }

    fn bufferBlockedRequest(self: *H3Server, stream_id: u64, data: []const u8) !void {
        if (self.blocked_requests) |*blocked| {
            if (!blocked.contains(stream_id) and blocked.count() >= self.max_blocked_streams) {
                return error.BlockedStreamLimitExceeded;
            }
            const copy = try self.allocator.dupe(u8, data);
            errdefer self.allocator.free(copy);
            if (blocked.get(stream_id)) |old| self.allocator.free(old);
            try blocked.put(stream_id, copy);
        }
    }

    /// Abandon a request stream: drop any buffered blocked data and tell the
    /// peer encoder that its references on this stream are no longer
    /// outstanding (RFC 9204 §4.4.2).
    pub fn cancelStream(self: *H3Server, stream_id: u64) !void {
        if (self.blocked_requests) |*blocked| {
            if (blocked.fetchRemove(stream_id)) |removed| {
                self.allocator.free(removed.value);
            }
        }
        self.releaseRequest(stream_id);
        if (self.responses.fetchRemove(stream_id)) |kv| {
            if (kv.value.body) |b| b.deinit();
        }
        const dec_stream_id = self.dec_stream_id orelse return;
        var buf: [16]u8 = undefined;
        const len = try qpack.encodeDecoderInstruction(&buf, .{ .stream_cancellation = stream_id });
        try self.conn.sendOnStream(dec_stream_id, buf[0..len], false);
    }

    /// Decode and serve a request. Returns false when the QPACK decoder still
    /// needs insertions from the peer's encoder stream (blocked stream).
    fn tryProcessRequest(self: *H3Server, stream_id: u64, request_data: []const u8) !bool {
        var request_required_insert_count: u64 = 0;
        var stack_headers: [32]qpack.HeaderField = undefined;
        const decoded = if (self.dec_table) |*dt| blk: {
            const result = h3_request.decodeRequestWithDynamicWithHeaders(request_data, dt, &stack_headers) catch |err| {
                if (err == error.BlockedByQpack) return false;
                return err;
            };
            request_required_insert_count = result.required_insert_count;
            break :blk result.request;
        } else (try h3_request.decodeRequestWithHeaders(request_data, &stack_headers)).request;

        try self.sendSectionAcknowledgement(stream_id, request_required_insert_count);

        // Call handler
        const response = self.handler(decoded);

        try self.startResponse(stream_id, response, isHeadMethod(decoded.method));
        return true;
    }

    /// Encode and initiate a response. A bodyless response is sent in one
    /// HEADERS frame with fin; any body (static slice or streamed) is sent as
    /// HEADERS (fin=false) plus a `ResponseStream` entry, drained by
    /// `pumpResponses` in max-response-chunk-payload DATA frames.
    fn startResponse(self: *H3Server, stream_id: u64, response: h3_request.Response, is_head: bool) !void {
        var resp_buf: [8192]u8 = undefined;
        var enc_instr: [4096]u8 = undefined;

        // HEAD responses carry HEADERS (and no DATA), like curl/HTTP semantics.
        const has_body = !is_head and ((response.body_stream != null) or (response.body != null and response.body.?.len > 0));

        if (self.enc_table) |*et| {
            const enc = try h3_request.encodeResponseHeadersWithDynamic(&resp_buf, response, et, &enc_instr);
            if (self.pending_sections) |*ps| {
                if (enc.required_insert_count > 0) {
                    try ps.put(stream_id, enc.required_insert_count);
                    et.protectUpTo(enc.required_insert_count);
                }
            }
            // Send encoder stream instructions before the response so dynamic
            // references in the header block resolve on the peer's decoder.
            if (enc.encoder_stream_len > 0) {
                try self.conn.sendOnStream(self.enc_stream_id.?, enc_instr[0..enc.encoder_stream_len], false);
            }
            try self.conn.sendOnStream(stream_id, resp_buf[0..enc.len], !has_body);
        } else {
            const resp_len = try h3_request.encodeResponseHeaders(&resp_buf, response);
            try self.conn.sendOnStream(stream_id, resp_buf[0..resp_len], !has_body);
        }

        if (has_body) {
            try self.responses.put(stream_id, .{
                .body = response.body_stream,
                .static_body = if (response.body_stream == null) (response.body orelse &.{}) else &.{},
            });
        } else {
            // HEAD responses never send DATA; release any body resources the
            // handler attached so they do not leak.
            if (response.body_stream) |bs| bs.deinit();
            // Bodyless response fully sent (fin on HEADERS); the request entry
            // is no longer needed and may be released.
            self.releaseRequest(stream_id);
        }
    }

    /// Drain pending response bodies, emitting DATA frames bounded per stream
    /// per call so a large response cannot starve the QPACK control/encoder/
    /// decoder streams. Flow-control-blocked chunks are retried next call.
    pub fn pumpResponses(self: *H3Server) !void {
        if (self.responses.count() == 0) return;
        var finished = std.ArrayList(u64).empty;
        defer finished.deinit(self.allocator);

        var it = self.responses.iterator();
        while (it.next()) |entry| {
            const sid = entry.key_ptr.*;
            const rs = entry.value_ptr;
            var chunks: usize = 0;
            while (chunks < h3_limits.max_chunks_per_pump) {
                var chunk: [h3_limits.max_response_chunk_payload]u8 = undefined;
                // static slice: advance the offset only after a successful send
                // so a flow-control-blocked chunk is retried, not dropped.
                if (rs.static_off < rs.static_body.len) {
                    const take = @min(rs.static_body.len - rs.static_off, chunk.len);
                    @memcpy(chunk[0..take], rs.static_body[rs.static_off .. rs.static_off + take]);
                    var dframe: [h3_limits.max_response_chunk_payload + 8]u8 = undefined;
                    const dlen = try h3_request.encodeDataFrame(&dframe, chunk[0..take]);
                    self.conn.sendOnStream(sid, dframe[0..dlen], false) catch |e| {
                        if (e == error.FlowControlBlocked) break;
                        return e;
                    };
                    rs.static_off += take;
                    chunks += 1;
                    continue;
                }
                // streamed body: pull one chunk and send it.
                if (rs.body) |bs| {
                    const n = bs.next(&chunk) catch |e| return e;
                    if (n) |len| {
                        var dframe: [h3_limits.max_response_chunk_payload + 8]u8 = undefined;
                        const dlen = try h3_request.encodeDataFrame(&dframe, chunk[0..len]);
                        self.conn.sendOnStream(sid, dframe[0..dlen], false) catch |e| {
                            if (e == error.FlowControlBlocked) break;
                            return e;
                        };
                        chunks += 1;
                        continue;
                    }
                }

                // Body exhausted: send the terminating empty frame with fin and
                // retire the stream (Connection.sendOnStream supports empty+fin).
                try self.conn.sendOnStream(sid, &.{}, true);
                if (rs.body) |b| b.deinit();
                try finished.append(self.allocator, sid);
                break;
            }
        }
        for (finished.items) |sid| {
            _ = self.responses.remove(sid);
            self.releaseRequest(sid);
        }
    }

    /// Release a request stream entry once its response has been fully sent.
    fn releaseRequest(self: *H3Server, stream_id: u64) void {
        if (self.requests.fetchRemove(stream_id)) |kv| {
            var rs = kv.value;
            rs.wire.deinit(self.allocator);
            rs.body_wire.deinit(self.allocator);
            rs.body.deinit(self.allocator);
        }
    }

    /// True once the stream has no pending request or response state (its
    /// response fin has been sent and the request entry released). The runtime
    /// driver uses this to release its per-stream buffers.
    pub fn streamDone(self: *H3Server, stream_id: u64) bool {
        return !self.requests.contains(stream_id) and !self.responses.contains(stream_id);
    }

    /// Send a minimal bodyless error response (e.g. 413) and retire the stream.
    pub fn sendSimpleError(self: *H3Server, stream_id: u64, status: u16) !void {
        try self.startResponse(stream_id, .{ .status = status }, false);
    }

    /// Retry all buffered blocked requests once the decoder table has advanced.
    fn unblockBlockedRequests(self: *H3Server) !void {
        if (self.blocked_requests) |*blocked| {
            if (blocked.count() == 0) return;

            var ids = std.ArrayList(u64).empty;
            defer ids.deinit(self.allocator);
            var it = blocked.iterator();
            while (it.next()) |entry| try ids.append(self.allocator, entry.key_ptr.*);

            for (ids.items) |stream_id| {
                const data = blocked.get(stream_id) orelse continue;
                if (try self.tryProcessRequest(stream_id, data)) {
                    self.allocator.free(data);
                    _ = blocked.remove(stream_id);
                }
            }
        }

        // Also unblock in-flight streams buffered via feedRequestData: their
        // wire bytes kept accumulating while blocked, so retry the QPACK decode
        // and migrate to the body phase once insertions arrive.
        if (self.dec_table == null or self.requests.count() == 0) return;
        var it = self.requests.iterator();
        while (it.next()) |entry| {
            const sid = entry.key_ptr.*;
            const rs = entry.value_ptr;
            if (rs.phase != .headers or !rs.blocked) continue;
            const frame = h3_frame.decodeFrame(rs.wire.items) catch continue;
            if (frame.frame.frame_type != @intFromEnum(h3_frame.FrameType.headers)) continue;
            const headers_wire = rs.wire.items[0..frame.consumed];
            const r = h3_request.decodeRequestWithDynamicWithHeaders(headers_wire, &self.dec_table.?, &rs.request_headers) catch |e| switch (e) {
                error.BlockedByQpack => continue,
                else => return e,
            };
            rs.blocked = false;
            try self.sendSectionAcknowledgement(sid, r.required_insert_count);
            if (frame.consumed < rs.wire.items.len) {
                try rs.body_wire.appendSlice(self.allocator, rs.wire.items[frame.consumed..]);
            }
            rs.wire.shrinkRetainingCapacity(frame.consumed);
            rs.decoded = r.request;
            rs.phase = .body;
            try self.parseBody(sid, rs);
            if (rs.body_fin) {
                if (rs.decoded) |*d| d.body = if (rs.body.items.len > 0) rs.body.items else null;
                const resp = self.handler(rs.decoded.?);
                try self.startResponse(sid, resp, isHeadMethod(rs.decoded.?.method));
            }
        }
    }

    /// Send GOAWAY to initiate graceful shutdown.
    pub fn sendGoaway(self: *H3Server, last_stream_id: u64) !void {
        if (self.goaway_sent) return;
        const control_id = self.control_stream_id orelse return;

        var buf: [16]u8 = undefined;
        var pos: usize = 0;

        // GOAWAY frame: type(0x07) + len + stream_id varint
        buf[pos] = 0x07;
        pos += 1;
        // Encode stream_id as varint
        if (last_stream_id <= 63) {
            buf[pos] = @intCast(last_stream_id);
            pos += 1;
            buf[1] = @intCast(pos - 2); // fix length
        } else {
            buf[pos] = @intCast(0x40 | (last_stream_id >> 8));
            buf[pos + 1] = @intCast(last_stream_id & 0xff);
            pos += 2;
            buf[1] = @intCast(pos - 2);
        }

        try self.conn.sendOnStream(control_id, buf[0..pos], false);
        self.goaway_sent = true;
        self.goaway_last_stream_id = last_stream_id;
    }
};

test "H3Server sends SETTINGS on control stream" {
    // Mock connection that captures sent data
    const MockCtx = struct {
        sent_data: std.ArrayList(u8) = .empty,
        sent_stream_id: ?u64 = null,
        next_uni_id: u64 = 3, // server-initiated uni

        fn openUni(ctx: *anyopaque) !u64 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            const id = self.next_uni_id;
            self.next_uni_id += 4;
            return id;
        }
        fn send(ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = fin;
            self.sent_stream_id = stream_id;
            try self.sent_data.appendSlice(std.testing.allocator, data);
        }
        fn recv(ctx: *anyopaque, stream_id: u64, buf: []u8) !?usize {
            _ = ctx;
            _ = stream_id;
            _ = buf;
            return null;
        }
    };

    var mock = MockCtx{};
    defer mock.sent_data.deinit(std.testing.allocator);

    var conn = H3Server.H3ServerConnection{
        .openUniStreamFn = MockCtx.openUni,
        .sendOnStreamFn = MockCtx.send,
        .recvOnStreamFn = MockCtx.recv,
        .ctx = &mock,
    };

    const handler = struct {
        fn handle(decoded_req: h3_request.DecodedRequest) h3_request.Response {
            _ = decoded_req;
            return .{ .status = 200, .body = "OK" };
        }
    }.handle;

    var server = try H3Server.init(&conn, handler, std.testing.allocator, 4096, 8);
    defer server.deinit();
    try std.testing.expect(server.settings_sent);
    try std.testing.expectEqual(@as(?u64, 3), server.control_stream_id);
    // Control stream should have: stream_type(1) + SETTINGS frame
    try std.testing.expect(mock.sent_data.items.len > 2);
    try std.testing.expectEqual(@as(u8, 0x00), mock.sent_data.items[0]); // control stream type
    try std.testing.expectEqual(@as(u8, 0x04), mock.sent_data.items[1]); // SETTINGS frame type
}

test "H3Server handles request and sends response" {
    // Encode a GET request
    var req_buf: [4096]u8 = undefined;
    const req = h3_request.Request{
        .method = "GET",
        .path = "/hello",
        .authority = "test.com",
    };
    const req_len = try h3_request.encodeRequest(&req_buf, req);

    const MockCtx = struct {
        request_data: []const u8,
        request_pos: usize = 0,
        response_data: std.ArrayList(u8) = .empty,
        response_stream_id: ?u64 = null,

        fn openUni(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 3;
        }
        fn send(ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = fin;
            if (stream_id != 3) { // not control stream
                self.response_stream_id = stream_id;
                try self.response_data.appendSlice(std.testing.allocator, data);
            }
        }
        fn recv(ctx: *anyopaque, stream_id: u64, buf: []u8) !?usize {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = stream_id;
            if (self.request_pos >= self.request_data.len) return null;
            const available = self.request_data[self.request_pos..];
            const n = @min(buf.len, available.len);
            @memcpy(buf[0..n], available[0..n]);
            self.request_pos += n;
            return n;
        }
    };

    var mock = MockCtx{ .request_data = req_buf[0..req_len] };
    defer mock.response_data.deinit(std.testing.allocator);

    var conn = H3Server.H3ServerConnection{
        .openUniStreamFn = MockCtx.openUni,
        .sendOnStreamFn = MockCtx.send,
        .recvOnStreamFn = MockCtx.recv,
        .ctx = &mock,
    };

    const handler = struct {
        fn handle(decoded_req: h3_request.DecodedRequest) h3_request.Response {
            if (std.mem.eql(u8, decoded_req.path, "/hello")) {
                return .{ .status = 200, .body = "Hello, World!" };
            }
            return .{ .status = 404, .body = "Not Found" };
        }
    }.handle;

    var server = try H3Server.init(&conn, handler, std.testing.allocator, 4096, 8);
    defer server.deinit();
    try server.handleRequestStream(0); // client bidi stream 0

    // Verify response
    try std.testing.expectEqual(@as(?u64, 0), mock.response_stream_id);
    const resp_result = try h3_request.decodeResponse(mock.response_data.items);
    try std.testing.expectEqual(@as(u16, 200), resp_result.response.status);
    try std.testing.expectEqualStrings("Hello, World!", resp_result.response.body.?);
}

test "H3Server GOAWAY" {
    const MockCtx = struct {
        sent_data: std.ArrayList(u8) = .empty,

        fn openUni(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 3;
        }
        fn send(ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = fin;
            _ = stream_id;
            try self.sent_data.appendSlice(std.testing.allocator, data);
        }
        fn recv(ctx: *anyopaque, stream_id: u64, buf: []u8) !?usize {
            _ = ctx;
            _ = stream_id;
            _ = buf;
            return null;
        }
    };

    var mock = MockCtx{};
    defer mock.sent_data.deinit(std.testing.allocator);

    var conn = H3Server.H3ServerConnection{
        .openUniStreamFn = MockCtx.openUni,
        .sendOnStreamFn = MockCtx.send,
        .recvOnStreamFn = MockCtx.recv,
        .ctx = &mock,
    };

    const handler = struct {
        fn handle(decoded_req: h3_request.DecodedRequest) h3_request.Response {
            _ = decoded_req;
            return .{ .status = 200 };
        }
    }.handle;

    var server = try H3Server.init(&conn, handler, std.testing.allocator, 4096, 8);
    defer server.deinit();
    try std.testing.expect(!server.goaway_sent);

    try server.sendGoaway(4);
    try std.testing.expect(server.goaway_sent);
    try std.testing.expectEqual(@as(?u64, 4), server.goaway_last_stream_id);
}

test "H3Server applies peer QPACK capacity from control stream" {
    const MockCtx = struct {
        next_uni_id: u64 = 3,

        fn openUni(ctx: *anyopaque) !u64 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            const id = self.next_uni_id;
            self.next_uni_id += 4;
            return id;
        }
        fn send(ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) !void {
            _ = ctx;
            _ = stream_id;
            _ = data;
            _ = fin;
        }
        fn recv(ctx: *anyopaque, stream_id: u64, buf: []u8) !?usize {
            _ = ctx;
            _ = stream_id;
            _ = buf;
            return null;
        }
    };

    var mock = MockCtx{};
    var conn = H3Server.H3ServerConnection{
        .openUniStreamFn = MockCtx.openUni,
        .sendOnStreamFn = MockCtx.send,
        .recvOnStreamFn = MockCtx.recv,
        .ctx = &mock,
    };
    const handler = struct {
        fn handle(decoded_req: h3_request.DecodedRequest) h3_request.Response {
            _ = decoded_req;
            return .{ .status = 200 };
        }
    }.handle;

    var server = try H3Server.init(&conn, handler, std.testing.allocator, 4096, 8);
    defer server.deinit();

    // Control stream: type + SETTINGS with qpack_max_table_capacity=2048.
    var settings_payload: [32]u8 = undefined;
    const settings = h3_connection.Settings{ .qpack_max_table_capacity = 2048 };
    const sp_len = try settings.encodePayload(&settings_payload);
    var control: [64]u8 = undefined;
    control[0] = 0x00;
    control[1] = 0x04; // SETTINGS
    control[2] = @intCast(sp_len);
    @memcpy(control[3 .. 3 + sp_len], settings_payload[0..sp_len]);

    try server.processPeerControlStream(control[0 .. 3 + sp_len]);
    try std.testing.expectEqual(@as(u64, 2048), server.peer_qpack_max_table_capacity);

    // enableQpackDynamic caps the encoder capacity at the peer's value.
    try server.enableQpackDynamic(4096);
    try std.testing.expectEqual(@as(usize, 2048), server.enc_table.?.max_capacity);
}

// ---------------------------------------------------------------------------
// Streaming request body / chunked response tests
// ---------------------------------------------------------------------------

test "H3Server streams request body across feeds and echoes it" {
    // POST with a body, encoded as HEADERS + DATA.
    const req_body = "the-quick-brown-fox-jumps-over-the-lazy-dog";
    var req_buf: [4096]u8 = undefined;
    const req = h3_request.Request{
        .method = "POST",
        .path = "/echo",
        .authority = "example.com",
        .body = req_body,
    };
    const req_len = try h3_request.encodeRequest(&req_buf, req);
    const headers_len = (try h3_frame.decodeFrame(req_buf[0..req_len])).consumed;

    const MockCtx = struct {
        response_data: std.ArrayList(u8) = .empty,
        fn openUni(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 3;
        }
        fn send(ctx: *anyopaque, sid: u64, data: []const u8, fin: bool) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = fin;
            if (sid != 3) try self.response_data.appendSlice(std.testing.allocator, data);
        }
        fn recv(ctx: *anyopaque, sid: u64, buf: []u8) !?usize {
            _ = ctx;
            _ = sid;
            _ = buf;
            return null;
        }
    };
    var mock = MockCtx{};
    defer mock.response_data.deinit(std.testing.allocator);
    var conn = H3Server.H3ServerConnection{
        .openUniStreamFn = MockCtx.openUni,
        .sendOnStreamFn = MockCtx.send,
        .recvOnStreamFn = MockCtx.recv,
        .ctx = &mock,
    };
    const handler = struct {
        fn handle(decoded_req: h3_request.DecodedRequest) h3_request.Response {
            return .{ .status = 200, .body = decoded_req.body orelse "NOBODY" };
        }
    }.handle;
    var server = try H3Server.init(&conn, handler, std.testing.allocator, 4096, 8);
    defer server.deinit();

    // HEADERS frame split across two feeds, then DATA + fin.
    _ = try server.feedRequestData(0, req_buf[0..4], false);
    _ = try server.feedRequestData(0, req_buf[4..headers_len], false);
    _ = try server.feedRequestData(0, req_buf[headers_len..req_len], true);
    try server.pumpResponses();

    const decoded = try h3_request.decodeResponse(mock.response_data.items);
    try std.testing.expectEqual(@as(u16, 200), decoded.response.status);
    try std.testing.expectEqualStrings(req_body, decoded.response.body.?);
}

test "H3Server skips GREASE frames before request HEADERS" {
    // POST /echo with a body, prefixed by two GREASE frames as quiche clients
    // emit before the request HEADERS frame (RFC 9114 §7.2.8).
    const req_body = "greased-request";
    var req_buf: [4096]u8 = undefined;
    const req = h3_request.Request{
        .method = "POST",
        .path = "/echo",
        .authority = "example.com",
        .body = req_body,
    };
    const req_len = try h3_request.encodeRequest(&req_buf, req);

    const grease_type: u64 = 31 * 100_000_000_000_000_000 + 33;
    var grease_a: [128]u8 = undefined;
    var ga = buffer.fixedWriter(&grease_a);
    try h3_frame.encodeFrame(ga.writer(), .{ .frame_type = grease_type, .payload = "GREASE is the word" });
    const grease_a_len = ga.getWritten().len;
    var grease_b: [64]u8 = undefined;
    var gb = buffer.fixedWriter(&grease_b);
    try h3_frame.encodeFrame(gb.writer(), .{ .frame_type = grease_type + 0x1f, .payload = "" });
    const grease_b_len = gb.getWritten().len;

    var wire: [4096]u8 = undefined;
    var pos: usize = 0;
    @memcpy(wire[pos .. pos + grease_a_len], grease_a[0..grease_a_len]);
    pos += grease_a_len;
    @memcpy(wire[pos .. pos + grease_b_len], grease_b[0..grease_b_len]);
    pos += grease_b_len;
    @memcpy(wire[pos .. pos + req_len], req_buf[0..req_len]);
    pos += req_len;

    const MockCtx = struct {
        response_data: std.ArrayList(u8) = .empty,
        fn openUni(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 3;
        }
        fn send(ctx: *anyopaque, sid: u64, data: []const u8, fin: bool) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = fin;
            if (sid != 3) try self.response_data.appendSlice(std.testing.allocator, data);
        }
        fn recv(ctx: *anyopaque, sid: u64, buf: []u8) !?usize {
            _ = ctx;
            _ = sid;
            _ = buf;
            return null;
        }
    };
    var mock = MockCtx{};
    defer mock.response_data.deinit(std.testing.allocator);
    var conn = H3Server.H3ServerConnection{
        .openUniStreamFn = MockCtx.openUni,
        .sendOnStreamFn = MockCtx.send,
        .recvOnStreamFn = MockCtx.recv,
        .ctx = &mock,
    };
    const handler = struct {
        fn handle(decoded_req: h3_request.DecodedRequest) h3_request.Response {
            return .{ .status = 200, .body = decoded_req.body orelse "NOBODY" };
        }
    }.handle;
    var server = try H3Server.init(&conn, handler, std.testing.allocator, 4096, 8);
    defer server.deinit();

    // Feed in two chunks so the skip loop buffers a partial GREASE frame.
    const r1 = try server.feedRequestData(0, wire[0..1], false);
    try std.testing.expect(r1.result == .need_more);
    const r2 = try server.feedRequestData(0, wire[1..pos], true);
    try std.testing.expect(r2.result == .processed);
    try server.pumpResponses();

    const decoded = try h3_request.decodeResponse(mock.response_data.items);
    try std.testing.expectEqual(@as(u16, 200), decoded.response.status);
    try std.testing.expectEqualStrings(req_body, decoded.response.body.?);
}

test "H3Server sends HEAD responses without a body" {
    var req_buf: [128]u8 = undefined;
    const req = h3_request.Request{ .method = "HEAD", .path = "/", .authority = "example.com" };
    const req_len = try h3_request.encodeRequest(&req_buf, req);

    const MockCtx = struct {
        response_data: std.ArrayList(u8) = .empty,
        fins: std.ArrayList(bool) = .empty,
        fn openUni(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 3;
        }
        fn send(ctx: *anyopaque, sid: u64, data: []const u8, fin: bool) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (sid != 3) {
                try self.response_data.appendSlice(std.testing.allocator, data);
                try self.fins.append(std.testing.allocator, fin);
            }
        }
        fn recv(ctx: *anyopaque, sid: u64, buf: []u8) !?usize {
            _ = ctx;
            _ = sid;
            _ = buf;
            return null;
        }
    };
    var mock = MockCtx{};
    defer {
        mock.response_data.deinit(std.testing.allocator);
        mock.fins.deinit(std.testing.allocator);
    }
    var conn = H3Server.H3ServerConnection{
        .openUniStreamFn = MockCtx.openUni,
        .sendOnStreamFn = MockCtx.send,
        .recvOnStreamFn = MockCtx.recv,
        .ctx = &mock,
    };
    const handler = struct {
        fn handle(decoded_req: h3_request.DecodedRequest) h3_request.Response {
            _ = decoded_req;
            // The body must be discarded for HEAD; leaking it (deinit never
            // called) fails the test via the testing allocator.
            return .{ .status = 200, .body_stream = h3_request.ResponseBody.fromRepeating(std.testing.allocator, '*', 20_000) catch unreachable };
        }
    }.handle;
    var server = try H3Server.init(&conn, handler, std.testing.allocator, 4096, 8);
    defer server.deinit();

    _ = try server.feedRequestData(0, req_buf[0..req_len], true);
    try server.pumpResponses();

    // Only the HEADERS frame is on the wire, finished in a single send.
    try std.testing.expectEqual(@as(usize, 1), mock.fins.items.len);
    try std.testing.expect(mock.fins.items[0]);
    const frame = try h3_frame.decodeFrame(mock.response_data.items);
    try std.testing.expectEqual(@as(u64, 0x01), frame.frame.frame_type);
    try std.testing.expectEqual(frame.consumed, mock.response_data.items.len);
}

test "H3Server pumps a streamed response as multiple DATA frames with fin last" {
    const req_wire: [32]u8 = undefined;
    _ = req_wire;
    // Minimal GET request: HEADERS frame with empty QPACK block.
    var req_buf: [64]u8 = undefined;
    const req = h3_request.Request{ .method = "GET", .path = "/stream", .authority = "example.com" };
    const req_len = try h3_request.encodeRequest(&req_buf, req);

    const MockCtx = struct {
        response_data: std.ArrayList(u8) = .empty,
        fins: std.ArrayList(bool) = .empty,
        fn openUni(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 3;
        }
        fn send(ctx: *anyopaque, sid: u64, data: []const u8, fin: bool) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (sid != 3) {
                try self.response_data.appendSlice(std.testing.allocator, data);
                try self.fins.append(std.testing.allocator, fin);
            }
        }
        fn recv(ctx: *anyopaque, sid: u64, buf: []u8) !?usize {
            _ = ctx;
            _ = sid;
            _ = buf;
            return null;
        }
    };
    var mock = MockCtx{};
    defer {
        mock.response_data.deinit(std.testing.allocator);
        mock.fins.deinit(std.testing.allocator);
    }
    var conn = H3Server.H3ServerConnection{
        .openUniStreamFn = MockCtx.openUni,
        .sendOnStreamFn = MockCtx.send,
        .recvOnStreamFn = MockCtx.recv,
        .ctx = &mock,
    };
    const handler = struct {
        fn handle(decoded_req: h3_request.DecodedRequest) h3_request.Response {
            if (std.mem.eql(u8, decoded_req.path, "/stream")) {
                return .{
                    .status = 200,
                    .body_stream = h3_request.ResponseBody.fromRepeating(std.heap.c_allocator, '*', 20_000) catch unreachable,
                };
            }
            return .{ .status = 404 };
        }
    }.handle;
    var server = try H3Server.init(&conn, handler, std.testing.allocator, 4096, 8);
    defer server.deinit();

    _ = try server.feedRequestData(0, req_buf[0..req_len], true);
    try server.pumpResponses();

    // Multiple DATA frames were sent; fin only on the last.
    try std.testing.expect(mock.fins.items.len > 2);
    for (mock.fins.items[0 .. mock.fins.items.len - 1]) |f| try std.testing.expect(!f);
    try std.testing.expect(mock.fins.items[mock.fins.items.len - 1]);

    // Concatenated DATA payloads reconstruct the full body.
    var pos: usize = 0;
    var total: usize = 0;
    var body_ok = true;
    while (true) {
        const frame = h3_frame.decodeFrame(mock.response_data.items[pos..]) catch break;
        if (frame.frame.frame_type == @intFromEnum(h3_frame.FrameType.data)) {
            total += frame.frame.payload.len;
            var i: usize = 0;
            while (i < frame.frame.payload.len) : (i += 1) {
                if (frame.frame.payload[i] != '*') body_ok = false;
            }
        }
        pos += frame.consumed;
    }
    try std.testing.expect(body_ok);
    try std.testing.expectEqual(@as(usize, 20_000), total);
}

test "H3Server rejects an oversized request body" {
    var req_buf: [4096]u8 = undefined;
    const req = h3_request.Request{
        .method = "POST",
        .path = "/upload",
        .authority = "example.com",
        .body = "x-large-body",
    };
    const req_len = try h3_request.encodeRequest(&req_buf, req);
    const headers_len = (try h3_frame.decodeFrame(req_buf[0..req_len])).consumed;

    const MockCtx = struct {
        fn openUni(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 3;
        }
        fn send(ctx: *anyopaque, sid: u64, data: []const u8, fin: bool) !void {
            _ = ctx;
            _ = sid;
            _ = data;
            _ = fin;
        }
        fn recv(ctx: *anyopaque, sid: u64, buf: []u8) !?usize {
            _ = ctx;
            _ = sid;
            _ = buf;
            return null;
        }
    };
    var mock = MockCtx{};
    var conn = H3Server.H3ServerConnection{
        .openUniStreamFn = MockCtx.openUni,
        .sendOnStreamFn = MockCtx.send,
        .recvOnStreamFn = MockCtx.recv,
        .ctx = &mock,
    };
    const handler = struct {
        fn handle(decoded_req: h3_request.DecodedRequest) h3_request.Response {
            _ = decoded_req;
            return .{ .status = 200 };
        }
    }.handle;
    var server = try H3Server.init(&conn, handler, std.testing.allocator, 4096, 8);
    defer server.deinit();
    server.max_request_body_size = 4; // tiny cap

    _ = try server.feedRequestData(0, req_buf[0..headers_len], false);
    try std.testing.expectError(error.RequestBodyTooLarge, server.feedRequestData(0, req_buf[headers_len..req_len], true));
}

test "H3Server retries a flow-control-blocked response chunk" {
    var req_buf: [64]u8 = undefined;
    const req = h3_request.Request{ .method = "GET", .path = "/", .authority = "example.com" };
    const req_len = try h3_request.encodeRequest(&req_buf, req);

    const MockCtx = struct {
        response_data: std.ArrayList(u8) = .empty,
        block_next_data: bool = true,
        fn openUni(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 3;
        }
        fn send(ctx: *anyopaque, sid: u64, data: []const u8, fin: bool) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = fin;
            if (sid == 3) return; // control stream
            if (data.len > 0 and data[0] == @intFromEnum(h3_frame.FrameType.data)) {
                if (self.block_next_data) {
                    self.block_next_data = false;
                    return error.FlowControlBlocked;
                }
            }
            try self.response_data.appendSlice(std.testing.allocator, data);
        }
        fn recv(ctx: *anyopaque, sid: u64, buf: []u8) !?usize {
            _ = ctx;
            _ = sid;
            _ = buf;
            return null;
        }
    };
    var mock = MockCtx{};
    defer mock.response_data.deinit(std.testing.allocator);
    var conn = H3Server.H3ServerConnection{
        .openUniStreamFn = MockCtx.openUni,
        .sendOnStreamFn = MockCtx.send,
        .recvOnStreamFn = MockCtx.recv,
        .ctx = &mock,
    };
    const handler = struct {
        fn handle(decoded_req: h3_request.DecodedRequest) h3_request.Response {
            _ = decoded_req;
            return .{ .status = 200, .body = "retried-body" };
        }
    }.handle;
    var server = try H3Server.init(&conn, handler, std.testing.allocator, 4096, 8);
    defer server.deinit();

    _ = try server.feedRequestData(0, req_buf[0..req_len], true);
    // First pump hits FlowControlBlocked on the DATA chunk; the response is
    // not lost and the stream is not retired.
    try server.pumpResponses();
    try std.testing.expect(!server.streamDone(0));

    // Second pump completes the transfer.
    try server.pumpResponses();
    try std.testing.expect(server.streamDone(0));
    const decoded = try h3_request.decodeResponse(mock.response_data.items);
    try std.testing.expectEqualStrings("retried-body", decoded.response.body.?);
}

test "H3Server serves a bodyless request with fin" {
    var req_buf: [64]u8 = undefined;
    const req = h3_request.Request{ .method = "GET", .path = "/", .authority = "example.com" };
    const req_len = try h3_request.encodeRequest(&req_buf, req);

    const MockCtx = struct {
        response_data: std.ArrayList(u8) = .empty,
        fn openUni(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 3;
        }
        fn send(ctx: *anyopaque, sid: u64, data: []const u8, fin: bool) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = fin;
            if (sid != 3) try self.response_data.appendSlice(std.testing.allocator, data);
        }
        fn recv(ctx: *anyopaque, sid: u64, buf: []u8) !?usize {
            _ = ctx;
            _ = sid;
            _ = buf;
            return null;
        }
    };
    var mock = MockCtx{};
    defer mock.response_data.deinit(std.testing.allocator);
    var conn = H3Server.H3ServerConnection{
        .openUniStreamFn = MockCtx.openUni,
        .sendOnStreamFn = MockCtx.send,
        .recvOnStreamFn = MockCtx.recv,
        .ctx = &mock,
    };
    const handler = struct {
        fn handle(decoded_req: h3_request.DecodedRequest) h3_request.Response {
            _ = decoded_req;
            return .{ .status = 204 };
        }
    }.handle;
    var server = try H3Server.init(&conn, handler, std.testing.allocator, 4096, 8);
    defer server.deinit();

    _ = try server.feedRequestData(0, req_buf[0..req_len], true);
    try server.pumpResponses();
    try std.testing.expect(server.streamDone(0));

    const decoded = try h3_request.decodeResponse(mock.response_data.items);
    try std.testing.expectEqual(@as(u16, 204), decoded.response.status);
}
