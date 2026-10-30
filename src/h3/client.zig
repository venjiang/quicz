//! HTTP/3 client handler (RFC 9114 §4-6).
//!
//! Sends H3 requests over QUIC streams and receives responses.
//! Works with any QUIC Connection that provides stream I/O.

const std = @import("std");
const h3_frame = @import("frame.zig");
const buffer = @import("../quic/buffer.zig");
const h3_request = @import("request.zig");
const h3_connection = @import("connection.zig");
const qpack = @import("qpack.zig");
const h3_limits = @import("limits.zig");

/// HTTP/3 client state machine over a QUIC connection.
pub const H3Client = struct {
    conn: *H3ClientConnection,
    allocator: std.mem.Allocator,
    control_stream_id: ?u64 = null,
    settings_sent: bool = false,
    settings_received: bool = false,
    next_request_stream_id: u64 = 0,
    goaway_received: bool = false,
    goaway_last_stream_id: u64 = 0,
    /// Advertised SETTINGS_MAX_FIELD_SECTION_SIZE: the largest field section this
    /// endpoint accepts from the peer (RFC 9114 §7.2.4.1).
    local_max_field_section_size: u64 = 8192,

    /// Client's encoder table for requests. Produces Insert/Duplicate/SetCapacity
    /// instructions sent on the QPACK encoder stream (type 0x02) to the server.
    enc_table: ?qpack.DynamicTable = null,
    /// Mirror of the server's encoder table for responses. Updated by consuming
    /// the server's encoder stream instructions via processPeerEncoderStream.
    dec_table: ?qpack.DynamicTable = null,
    /// Client's QPACK encoder stream (type 0x02).
    enc_stream_id: ?u64 = null,
    /// Client's QPACK decoder stream (type 0x03).
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
    /// Encoded response bytes awaiting QPACK insertions (RFC 9204 §2.2.1),
    /// keyed by stream ID until the peer's encoder stream supplies the
    /// Required Insert Count.
    blocked_responses: ?std.AutoHashMap(u64, []u8) = null,
    /// Advertised SETTINGS_QPACK_BLOCKED_STREAMS: the maximum number of streams
    /// this decoder keeps blocked at once (RFC 9204 §2.1.2).
    max_blocked_streams: u64 = 0,
    /// Per-stream response body cap, mirroring the server's request cap.
    max_response_body_size: usize = h3_limits.max_request_body_size,

    /// Request bodies awaiting flow-control credit, keyed by stream ID. A
    /// streamed request body that cannot be fully sent in one call continues
    /// here until `pumpSends` drains it (mirror of the server's response pump).
    pending_sends: ?std.AutoHashMap(u64, PendingSend) = null,

    /// In-flight response streams (headers + aggregated DATA body), keyed by
    /// stream ID. `decoded` borrows `wire` and `body`, so the entry survives
    /// until the response is fully consumed (kept as backing storage).
    response_streams: std.AutoHashMap(u64, ResponseStream) = undefined,

    const ResponseStream = struct {
        phase: enum { headers, body } = .headers,
        /// HEADERS-frame wire bytes; the decoded response borrows them.
        wire: std.ArrayList(u8),
        /// Unparsed DATA-frame wire bytes accumulated across feeds.
        body_wire: std.ArrayList(u8),
        /// Aggregated DATA payloads (the response body).
        body: std.ArrayList(u8),
        /// Decoded response header fields; names/values borrow `wire` or the
        /// QPACK static table, and the array itself lives here.
        headers_buf: [32]qpack.HeaderField = undefined,
        header_count: usize = 0,
        /// Peer FIN arrived; the response is complete.
        fin: bool = false,
        /// True while the QPACK decoder awaits inserts (RFC 9204 §2.2.1).
        blocked: bool = false,
        decoded: ?h3_request.DecodedResponse = null,
    };

    const PendingSend = struct {
        /// Lazy chunked body; takes precedence over `static_body`.
        body: ?h3_request.ResponseBody = null,
        /// Fixed-slice body (from a `ResponseBody.fromChunks`-style source).
        static_body: []const u8 = &.{},
        static_off: usize = 0,
    };

    pub const H3ClientConnection = struct {
        /// Open a locally-initiated bidirectional stream.
        openBidiStreamFn: *const fn (ctx: *anyopaque) anyerror!u64,
        /// Open a locally-initiated unidirectional stream.
        openUniStreamFn: *const fn (ctx: *anyopaque) anyerror!u64,
        /// Send data on a stream.
        sendOnStreamFn: *const fn (ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) anyerror!void,
        /// Receive data from a stream. Returns null if no data available.
        recvOnStreamFn: *const fn (ctx: *anyopaque, stream_id: u64, buf: []u8) anyerror!?usize,
        /// Opaque context pointer.
        ctx: *anyopaque,

        pub fn openBidiStream(self: *H3ClientConnection) !u64 {
            return self.openBidiStreamFn(self.ctx);
        }
        pub fn openUniStream(self: *H3ClientConnection) !u64 {
            return self.openUniStreamFn(self.ctx);
        }
        pub fn sendOnStream(self: *H3ClientConnection, stream_id: u64, data: []const u8, fin: bool) !void {
            return self.sendOnStreamFn(self.ctx, stream_id, data, fin);
        }
        pub fn recvOnStream(self: *H3ClientConnection, stream_id: u64, buf: []u8) !?usize {
            return self.recvOnStreamFn(self.ctx, stream_id, buf);
        }
    };

    /// Initialize the client and send SETTINGS on the control stream.
    pub fn init(
        conn: *H3ClientConnection,
        allocator: std.mem.Allocator,
        qpack_max_table_capacity: u64,
        qpack_blocked_streams: u64,
    ) !H3Client {
        var client = H3Client{
            .conn = conn,
            .allocator = allocator,
            .local_qpack_max_table_capacity = qpack_max_table_capacity,
            .max_blocked_streams = qpack_blocked_streams,
            .response_streams = std.AutoHashMap(u64, ResponseStream).init(allocator),
        };
        try client.sendSettings();
        return client;
    }

    /// Release QPACK dynamic table resources.
    pub fn deinit(self: *H3Client) void {
        if (self.enc_table) |*t| t.deinit();
        if (self.dec_table) |*t| t.deinit();
        if (self.pending_sections) |*m| m.deinit();
        if (self.blocked_responses) |*m| {
            var it = m.iterator();
            while (it.next()) |entry| self.allocator.free(entry.value_ptr.*);
            m.deinit();
        }
        if (self.pending_sends) |*ps| {
            var it = ps.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.body) |b| b.deinit();
            }
            ps.deinit();
        }
        var rit = self.response_streams.valueIterator();
        while (rit.next()) |rs| {
            rs.wire.deinit(self.allocator);
            rs.body_wire.deinit(self.allocator);
            rs.body.deinit(self.allocator);
        }
        self.response_streams.deinit();
    }

    /// Enable QPACK dynamic table compression (RFC 9204).
    /// Opens QPACK encoder (0x02) and decoder (0x03) unidirectional streams,
    /// initializes both tables, and advertises capacity to the peer via a
    /// Set Capacity instruction on the encoder stream. The encoder capacity is
    /// capped by the peer's advertised SETTINGS_QPACK_MAX_TABLE_CAPACITY; when
    /// the peer has not advertised one, the encoder must stay at capacity zero
    /// and send no encoder instructions (RFC 9204 §3.2.3).
    pub fn enableQpackDynamic(self: *H3Client, capacity: usize) !void {
        self.enc_capacity_requested = capacity;
        const enc_capacity: usize = @intCast(@min(capacity, self.peer_qpack_max_table_capacity));
        self.enc_table = qpack.DynamicTable.init(self.allocator);
        self.dec_table = qpack.DynamicTable.init(self.allocator);
        self.pending_sections = std.AutoHashMap(u64, u64).init(self.allocator);
        self.blocked_responses = std.AutoHashMap(u64, []u8).init(self.allocator);
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
    pub fn setPeerMaxTableCapacity(self: *H3Client, capacity: u64) !void {
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

    /// Feed peer (server) encoder stream data into the decoder-side dynamic
    /// table so subsequent response header blocks with dynamic references
    /// resolve correctly (RFC 9204 §4.3).
    pub fn processPeerEncoderStream(self: *H3Client, data: []const u8) !void {
        if (self.dec_table) |*dt| {
            _ = try qpack.decodeEncoderStreamInstructions(data, dt);
            if (dt.max_capacity > self.local_qpack_max_table_capacity) {
                return error.QpackCapacityExceedsSettings;
            }
        }
    }

    /// Process the peer's control stream: parse SETTINGS (apply the advertised
    /// QPACK table capacity) and GOAWAY (graceful shutdown) frames (RFC 9114
    /// §6.2.1).
    pub fn processPeerControlStream(self: *H3Client, data: []const u8) !void {
        var pos: usize = 0;
        if (pos < data.len and data[pos] == 0x00) pos += 1; // stream type
        while (pos < data.len) {
            const frame = try h3_frame.decodeFrame(data[pos..]);
            switch (frame.frame.frame_type) {
                @backingInt(h3_frame.FrameType.settings) => {
                    const settings = try h3_connection.Settings.decodePayload(frame.frame.payload);
                    self.settings_received = true;
                    if (settings.qpack_max_table_capacity != 0) {
                        try self.setPeerMaxTableCapacity(settings.qpack_max_table_capacity);
                    }
                },
                @backingInt(h3_frame.FrameType.goaway) => {
                    const last_stream_id = try h3_connection.H3Connection.decodeGoawayPayload(frame.frame.payload);
                    try self.processGoaway(last_stream_id);
                },
                else => {},
            }
            if (frame.consumed == 0) break;
            pos += frame.consumed;
        }
    }

    /// Feed peer (server) decoder stream data into the encoder-side table so
    /// Section Acknowledgment / Insert Count Increment advance the Known
    /// Received Count (RFC 9204 §4.4).
    pub fn processPeerDecoderStream(self: *H3Client, data: []const u8) !void {
        if (self.enc_table) |*et| {
            if (self.pending_sections) |*ps| {
                _ = try qpack.decodeDecoderStreamInstructions(data, et, ps);
            }
        }
    }

    /// Emit Section Acknowledgment (when the decoded section used dynamic
    /// references) and any outstanding Insert Count Increment on the QPACK
    /// decoder stream (RFC 9204 §4.4).
    fn sendSectionAcknowledgement(self: *H3Client, stream_id: u64, required_insert_count: u64) !void {
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

    /// Open the client control stream and send SETTINGS.
    fn sendSettings(self: *H3Client) !void {
        const stream_id = try self.conn.openUniStream();
        self.control_stream_id = stream_id;

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

        buf[pos] = 0x04; // SETTINGS frame type
        pos += 1;
        buf[pos] = @intCast(sp_len);
        pos += 1;
        @memcpy(buf[pos .. pos + sp_len], settings_payload[0..sp_len]);
        pos += sp_len;

        try self.conn.sendOnStream(stream_id, buf[0..pos], false);
        self.settings_sent = true;
    }

    /// Send an HTTP request and receive the response.
    /// Opens a new bidi stream, sends the request, and reads the response.
    pub fn sendRequest(self: *H3Client, request: h3_request.Request) !h3_request.DecodedResponse {
        if (self.goaway_received and self.next_request_stream_id > self.goaway_last_stream_id) {
            return error.GoawayExceeded;
        }
        // Open bidi stream for request
        const stream_id = try self.conn.openBidiStream();
        self.next_request_stream_id = stream_id + 4;

        // Encode and send request
        var req_buf: [8192]u8 = undefined;
        const req_len = try h3_request.encodeRequest(&req_buf, request);
        try self.conn.sendOnStream(stream_id, req_buf[0..req_len], true);

        // Read response
        var resp_buf: [8192]u8 = undefined;
        var total_read: usize = 0;

        while (total_read < resp_buf.len) {
            const n = try self.conn.recvOnStream(stream_id, resp_buf[total_read..]) orelse break;
            total_read += n;
            // Try to decode - if successful, we have a complete response
            if (total_read > 0) {
                try self.checkFieldSectionSize(resp_buf[0..total_read]);
                const result = h3_request.decodeResponse(resp_buf[0..total_read]) catch continue;
                return result.response;
            }
        }

        if (total_read == 0) return error.NoResponse;

        try self.checkFieldSectionSize(resp_buf[0..total_read]);
        const result = try h3_request.decodeResponse(resp_buf[0..total_read]);
        return result.response;
    }

    /// Send an HTTP request using QPACK dynamic table compression (RFC 9204).
    /// Encodes the request with dynamic insertions, sends encoder stream
    /// instructions on the QPACK encoder stream, then sends the request on
    /// a new bidi stream. Returns the stream ID for later response retrieval
    /// via receiveResponseDynamic.
    ///
    /// The caller must ensure the peer receives and processes the encoder
    /// stream instructions before decoding the request. Likewise, before
    /// calling receiveResponseDynamic, the caller must feed any peer encoder
    /// stream data via processPeerEncoderStream.
    pub fn sendRequestDynamic(self: *H3Client, request: h3_request.Request) !u64 {
        if (self.goaway_received and self.next_request_stream_id > self.goaway_last_stream_id) {
            return error.GoawayExceeded;
        }
        const stream_id = try self.conn.openBidiStream();
        self.next_request_stream_id = stream_id + 4;

        var req_buf: [8192]u8 = undefined;
        var enc_instr: [4096]u8 = undefined;
        const enc = try h3_request.encodeRequestWithDynamic(&req_buf, request, &self.enc_table.?, &enc_instr);
        if (self.pending_sections) |*ps| {
            if (enc.required_insert_count > 0) {
                try ps.put(stream_id, enc.required_insert_count);
                self.enc_table.?.protectUpTo(enc.required_insert_count);
            }
        }

        // Send encoder stream instructions before the request so the peer's
        // decoder table is synchronized when it decodes the header block.
        if (enc.encoder_stream_len > 0) {
            try self.conn.sendOnStream(self.enc_stream_id.?, enc_instr[0..enc.encoder_stream_len], false);
        }
        try self.conn.sendOnStream(stream_id, req_buf[0..enc.len], true);
        return stream_id;
    }

    /// Send an HTTP request with a streamed (chunked) body (RFC 9114 §6.1).
    /// Emits HEADERS (fin=false), then sends the body as bounded DATA frames,
    /// parking any flow-control-blocked remainder in `pending_sends` for
    /// `pumpSends` to drain once fresh MAX_STREAM_DATA credit arrives. Returns
    /// the stream ID for `receiveResponseDynamic`.
    pub fn sendRequestStreamed(self: *H3Client, request: h3_request.Request, body: h3_request.ResponseBody) !u64 {
        if (self.goaway_received and self.next_request_stream_id > self.goaway_last_stream_id) {
            return error.GoawayExceeded;
        }
        const stream_id = try self.conn.openBidiStream();
        self.next_request_stream_id = stream_id + 4;

        var req_buf: [8192]u8 = undefined;
        var enc_instr: [4096]u8 = undefined;
        const enc = try h3_request.encodeRequestHeadersWithDynamic(&req_buf, request, &self.enc_table.?, &enc_instr);
        if (self.pending_sections) |*ps| {
            if (enc.required_insert_count > 0) {
                try ps.put(stream_id, enc.required_insert_count);
                self.enc_table.?.protectUpTo(enc.required_insert_count);
            }
        }
        if (enc.encoder_stream_len > 0) {
            try self.conn.sendOnStream(self.enc_stream_id.?, enc_instr[0..enc.encoder_stream_len], false);
        }
        try self.conn.sendOnStream(stream_id, req_buf[0..enc.len], false);

        if (self.pending_sends == null) self.pending_sends = std.AutoHashMap(u64, PendingSend).init(self.allocator);
        try self.pending_sends.?.put(stream_id, .{ .body = body });
        try self.pumpSends();
        return stream_id;
    }

    /// Drain pending streamed request bodies, emitting bounded DATA frames.
    /// Flow-control-blocked chunks retry on the next call (the peer's
    /// MAX_STREAM_DATA credit arrives as an inbound datagram).
    pub fn pumpSends(self: *H3Client) !void {
        const ps = self.pending_sends orelse return;
        if (ps.count() == 0) return;
        var finished = std.ArrayList(u64).empty;
        defer finished.deinit(self.allocator);

        var it = ps.iterator();
        while (it.next()) |entry| {
            const sid = entry.key_ptr.*;
            const st = entry.value_ptr;
            var chunks: usize = 0;
            while (chunks < h3_limits.max_chunks_per_pump) {
                var chunk: [h3_limits.max_response_chunk_payload]u8 = undefined;
                if (st.static_off < st.static_body.len) {
                    const take = @min(st.static_body.len - st.static_off, chunk.len);
                    @memcpy(chunk[0..take], st.static_body[st.static_off .. st.static_off + take]);
                    var dframe: [h3_limits.max_response_chunk_payload + 8]u8 = undefined;
                    const dlen = try h3_request.encodeDataFrame(&dframe, chunk[0..take]);
                    self.conn.sendOnStream(sid, dframe[0..dlen], false) catch |e| {
                        if (e == error.FlowControlBlocked) break;
                        return e;
                    };
                    st.static_off += take;
                    chunks += 1;
                    continue;
                }
                if (st.body) |b| {
                    const n = try b.next(&chunk);
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
                // Body exhausted: terminate with an empty fin frame.
                try self.conn.sendOnStream(sid, &.{}, true);
                if (st.body) |b| b.deinit();
                try finished.append(self.allocator, sid);
                break;
            }
        }
        for (finished.items) |sid| _ = self.pending_sends.?.remove(sid);
    }

    /// Read and decode a response using QPACK dynamic table.
    /// When the decoder needs insertions the peer's encoder stream has not
    /// delivered yet, the response bytes are buffered and `error.BlockedByQpack`
    /// is returned; the caller feeds peer encoder stream data via
    /// processPeerEncoderStream and calls this again to finish decoding.
    pub fn receiveResponseDynamic(self: *H3Client, stream_id: u64) !h3_request.DecodedResponse {
        // Retry a previously blocked response before reading the connection.
        if (self.blocked_responses) |*blocked| {
            if (blocked.get(stream_id)) |data| {
                if (try self.tryDecodeBufferedResponse(stream_id, data)) |response| {
                    // The returned response borrows the buffered bytes, so the
                    // entry is retained as backing storage until deinit.
                    return response;
                }
                return error.BlockedByQpack;
            }
        }

        var resp_buf: [8192]u8 = undefined;
        var total_read: usize = 0;

        while (total_read < resp_buf.len) {
            const n = try self.conn.recvOnStream(stream_id, resp_buf[total_read..]) orelse break;
            total_read += n;
            if (total_read > 0) {
                try self.checkFieldSectionSize(resp_buf[0..total_read]);
                if (h3_request.decodeResponseWithDynamic(resp_buf[0..total_read], &self.dec_table.?)) |result| {
                    try self.sendSectionAcknowledgement(stream_id, result.required_insert_count);
                    return result.response;
                } else |err| {
                    if (err == error.BlockedByQpack) {
                        try self.bufferBlockedResponse(stream_id, resp_buf[0..total_read]);
                        return error.BlockedByQpack;
                    }
                    // Incomplete: keep reading the response.
                }
            }
        }

        if (total_read == 0) return error.NoResponse;
        try self.checkFieldSectionSize(resp_buf[0..total_read]);
        const result = h3_request.decodeResponseWithDynamic(resp_buf[0..total_read], &self.dec_table.?) catch |err| {
            if (err == error.BlockedByQpack) {
                try self.bufferBlockedResponse(stream_id, resp_buf[0..total_read]);
                return error.BlockedByQpack;
            }
            return err;
        };
        try self.sendSectionAcknowledgement(stream_id, result.required_insert_count);
        return result.response;
    }

    /// Streaming response entry point (mirror of `H3Server.feedRequestData`).
    /// Feed wire bytes (and EOF via `fin`) for a response stream; the state
    /// machine buffers the HEADERS frame and aggregates DATA payloads up to
    /// `max_response_body_size`, returning the decoded response once the body
    /// has fully arrived, or `null` while incomplete/blocked. The returned
    /// response borrows the stream entry, which is kept as backing storage.
    pub fn feedResponseData(self: *H3Client, stream_id: u64, data: []const u8, fin: bool) !?h3_request.DecodedResponse {
        const gop = try self.response_streams.getOrPut(stream_id);
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
            // Servers may send GREASE / unknown extension frames before the
            // initial HEADERS frame (RFC 9114 §7.2.8, §9); Cloudflare's quiche
            // greases the response stream in production. Skip and scan for the
            // first HEADERS frame.
            var frame = h3_frame.decodeFrame(rs.wire.items) catch |e| switch (e) {
                error.IncompleteFrame => return null,
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
                    error.IncompleteFrame => return null,
                    else => return e,
                };
            }
            if (frame.frame.frame_type != @backingInt(h3_frame.FrameType.headers)) {
                return error.ExpectedHeadersFrame;
            }
            if (frame.frame.payload.len > self.local_max_field_section_size) {
                return error.FieldSectionTooLarge;
            }

            var ric: u64 = 0;
            const headers_wire = rs.wire.items[0..frame.consumed];
            const decoded = if (self.dec_table) |*dt| blk: {
                const r = h3_request.decodeResponseWithDynamicAndHeaders(headers_wire, dt, &rs.headers_buf) catch |e| {
                    if (e == error.BlockedByQpack) {
                        rs.blocked = true;
                        return null;
                    }
                    return e;
                };
                ric = r.required_insert_count;
                rs.header_count = r.header_count;
                break :blk r.response;
            } else blk: {
                const r = try h3_request.decodeResponseWithHeaders(headers_wire, &rs.headers_buf);
                rs.header_count = r.header_count;
                break :blk r.response;
            };
            try self.sendSectionAcknowledgement(stream_id, ric);

            if (frame.consumed < rs.wire.items.len) {
                try rs.body_wire.appendSlice(self.allocator, rs.wire.items[frame.consumed..]);
            }
            rs.wire.shrinkRetainingCapacity(frame.consumed);
            rs.decoded = decoded;
            if (rs.decoded) |*d| d.headers = rs.headers_buf[0..rs.header_count];
            rs.phase = .body;
        } else {
            try rs.body_wire.appendSlice(self.allocator, data);
        }

        try self.parseResponseBody(rs);

        if (fin) rs.fin = true;
        if (rs.fin) {
            if (rs.decoded) |*d| d.body = if (rs.body.items.len > 0) rs.body.items else null;
            return rs.decoded;
        }
        return null;
    }

    /// Parse complete DATA frames out of `body_wire`, aggregating payloads
    /// into `body`, bounded by `max_response_body_size`.
    fn parseResponseBody(self: *H3Client, rs: *ResponseStream) !void {
        var off: usize = 0;
        while (off < rs.body_wire.items.len) {
            const frame = h3_request.takeDataFrame(rs.body_wire.items[off..]) catch |e| switch (e) {
                error.IncompleteFrame => break,
                else => return e,
            };
            if (rs.body.items.len + frame.payload.len > self.max_response_body_size) {
                return error.ResponseBodyTooLarge;
            }
            try rs.body.appendSlice(self.allocator, frame.payload);
            off += frame.consumed;
        }
        if (off > 0) {
            std.mem.copyForwards(u8, rs.body_wire.items[0 .. rs.body_wire.items.len - off], rs.body_wire.items[off..]);
            rs.body_wire.shrinkRetainingCapacity(rs.body_wire.items.len - off);
        }
    }

    /// Release a response stream entry once fully consumed.
    pub fn releaseResponse(self: *H3Client, stream_id: u64) void {
        if (self.response_streams.fetchRemove(stream_id)) |kv| {
            var rs = kv.value;
            rs.wire.deinit(self.allocator);
            rs.body_wire.deinit(self.allocator);
            rs.body.deinit(self.allocator);
        }
    }

    /// Decode a buffered response. Returns null while still blocked.
    pub fn tryDecodeBufferedResponse(
        self: *H3Client,
        stream_id: u64,
        data: []const u8,
    ) !?h3_request.DecodedResponse {
        try self.checkFieldSectionSize(data);
        const result = h3_request.decodeResponseWithDynamic(data, &self.dec_table.?) catch |err| {
            if (err == error.BlockedByQpack) return null;
            return err;
        };
        try self.sendSectionAcknowledgement(stream_id, result.required_insert_count);
        return result.response;
    }

    /// Feed already-buffered response bytes (a complete HEADERS frame plus any
    /// DATA) into the client. The runtime driver reads the wire itself so it
    /// can interleave the server's control / QPACK streams. Returns the decoded
    /// response, or `null` while the response is incomplete or blocked (the
    /// state machine keeps its own copy of a blocked response and retries on
    /// encoder-stream progress).
    pub fn feedResponseBytes(self: *H3Client, stream_id: u64, data: []const u8) !?h3_request.DecodedResponse {
        const frame = try h3_frame.decodeFrame(data);
        if (frame.frame.frame_type != @backingInt(h3_frame.FrameType.headers)) {
            return error.ExpectedHeadersFrame;
        }
        try self.checkFieldSectionSize(data);
        const result = h3_request.decodeResponseWithDynamic(data, &self.dec_table.?) catch |err| {
            if (err == error.BlockedByQpack) {
                try self.bufferBlockedResponse(stream_id, data);
                return null;
            }
            return err;
        };
        try self.sendSectionAcknowledgement(stream_id, result.required_insert_count);
        return result.response;
    }

    /// Reject a complete HEADERS frame whose payload exceeds the advertised
    /// SETTINGS_MAX_FIELD_SECTION_SIZE; incomplete frames are left for the
    /// decode path to keep reading.
    fn checkFieldSectionSize(self: *const H3Client, data: []const u8) !void {
        const frame = h3_frame.decodeFrame(data) catch return;
        if (frame.frame.payload.len > self.local_max_field_section_size) {
            return error.FieldSectionTooLarge;
        }
    }

    /// Record a peer GOAWAY. A second GOAWAY with a lower last stream ID is an
    /// H3_ID_ERROR; no further streams above the limit may be opened (RFC 9114
    /// §5.2).
    pub fn processGoaway(self: *H3Client, last_stream_id: u64) !void {
        if (self.goaway_received and last_stream_id < self.goaway_last_stream_id) {
            return error.InvalidGoaway;
        }
        self.goaway_received = true;
        self.goaway_last_stream_id = last_stream_id;
    }

    fn bufferBlockedResponse(self: *H3Client, stream_id: u64, data: []const u8) !void {
        if (self.blocked_responses) |*blocked| {
            if (!blocked.contains(stream_id) and blocked.count() >= self.max_blocked_streams) {
                return error.BlockedStreamLimitExceeded;
            }
            const copy = try self.allocator.dupe(u8, data);
            errdefer self.allocator.free(copy);
            if (blocked.get(stream_id)) |old| self.allocator.free(old);
            try blocked.put(stream_id, copy);
        }
    }

    /// Abandon a response stream: drop any buffered blocked data and tell the
    /// peer encoder that its references on this stream are no longer
    /// outstanding (RFC 9204 §4.4.2).
    pub fn cancelStream(self: *H3Client, stream_id: u64) !void {
        if (self.blocked_responses) |*blocked| {
            if (blocked.fetchRemove(stream_id)) |removed| {
                self.allocator.free(removed.value);
            }
        }
        const dec_stream_id = self.dec_stream_id orelse return;
        var buf: [16]u8 = undefined;
        const len = try qpack.encodeDecoderInstruction(&buf, .{ .stream_cancellation = stream_id });
        try self.conn.sendOnStream(dec_stream_id, buf[0..len], false);
    }

    /// Whether the client is ready to send requests.
    pub fn isReady(self: *const H3Client) bool {
        return self.settings_sent;
    }
};

test "H3Client sends SETTINGS on control stream" {
    const MockCtx = struct {
        sent_data: std.ArrayList(u8) = .empty,
        sent_stream_id: ?u64 = null,
        next_uni_id: u64 = 2, // client-initiated uni

        fn openBidi(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 0;
        }
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

    var conn = H3Client.H3ClientConnection{
        .openBidiStreamFn = MockCtx.openBidi,
        .openUniStreamFn = MockCtx.openUni,
        .sendOnStreamFn = MockCtx.send,
        .recvOnStreamFn = MockCtx.recv,
        .ctx = &mock,
    };

    var client = try H3Client.init(&conn, std.testing.allocator, 4096, 8);
    defer client.deinit();
    try std.testing.expect(client.settings_sent);
    try std.testing.expect(client.isReady());
    try std.testing.expectEqual(@as(?u64, 2), client.control_stream_id);
    // Control stream: stream_type(0x00) + SETTINGS frame(0x04)
    try std.testing.expect(mock.sent_data.items.len > 2);
    try std.testing.expectEqual(@as(u8, 0x00), mock.sent_data.items[0]);
    try std.testing.expectEqual(@as(u8, 0x04), mock.sent_data.items[1]);
}

test "H3Client sends request and receives response" {
    // Pre-encode a response that the mock will return
    var resp_wire: [4096]u8 = undefined;
    const resp = h3_request.Response{
        .status = 200,
        .body = "Hello from server!",
    };
    const resp_len = try h3_request.encodeResponse(&resp_wire, resp);

    const MockCtx = struct {
        response_wire: []const u8,
        response_pos: usize = 0,
        request_data: std.ArrayList(u8) = .empty,
        request_stream_id: ?u64 = null,
        next_bidi_id: u64 = 0,

        fn openBidi(ctx: *anyopaque) !u64 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            const id = self.next_bidi_id;
            self.next_bidi_id += 4;
            return id;
        }
        fn openUni(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 2;
        }
        fn send(ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = fin;
            if (stream_id != 2) { // not control stream
                self.request_stream_id = stream_id;
                try self.request_data.appendSlice(std.testing.allocator, data);
            }
        }
        fn recv(ctx: *anyopaque, stream_id: u64, buf: []u8) !?usize {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = stream_id;
            if (self.response_pos >= self.response_wire.len) return null;
            const available = self.response_wire[self.response_pos..];
            const n = @min(buf.len, available.len);
            @memcpy(buf[0..n], available[0..n]);
            self.response_pos += n;
            return n;
        }
    };

    var mock = MockCtx{ .response_wire = resp_wire[0..resp_len] };
    defer mock.request_data.deinit(std.testing.allocator);

    var conn = H3Client.H3ClientConnection{
        .openBidiStreamFn = MockCtx.openBidi,
        .openUniStreamFn = MockCtx.openUni,
        .sendOnStreamFn = MockCtx.send,
        .recvOnStreamFn = MockCtx.recv,
        .ctx = &mock,
    };

    var client = try H3Client.init(&conn, std.testing.allocator, 4096, 8);
    defer client.deinit();

    const request = h3_request.Request{
        .method = "GET",
        .path = "/test",
        .authority = "example.com",
    };

    const response = try client.sendRequest(request);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expect(response.isSuccess());
    try std.testing.expectEqualStrings("Hello from server!", response.body.?);

    // Verify the request was sent on stream 0
    try std.testing.expectEqual(@as(?u64, 0), mock.request_stream_id);
    // Verify request can be decoded
    const decoded_req = try h3_request.decodeRequest(mock.request_data.items);
    try std.testing.expectEqualStrings("GET", decoded_req.request.method);
    try std.testing.expectEqualStrings("/test", decoded_req.request.path);
}

test "H3Client applies SETTINGS and GOAWAY from control stream" {
    const MockCtx = struct {
        fn openBidi(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 0;
        }
        fn openUni(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 2;
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
    var conn = H3Client.H3ClientConnection{
        .openBidiStreamFn = MockCtx.openBidi,
        .openUniStreamFn = MockCtx.openUni,
        .sendOnStreamFn = MockCtx.send,
        .recvOnStreamFn = MockCtx.recv,
        .ctx = &mock,
    };

    var client = try H3Client.init(&conn, std.testing.allocator, 4096, 8);
    defer client.deinit();

    // Control stream: type + SETTINGS(2048) + GOAWAY(4).
    var settings_payload: [32]u8 = undefined;
    const settings = h3_connection.Settings{ .qpack_max_table_capacity = 2048 };
    const sp_len = try settings.encodePayload(&settings_payload);
    var goaway_payload: [8]u8 = undefined;
    const gp_len = try h3_connection.H3Connection.encodeGoawayPayload(&goaway_payload, 4);

    var control: [128]u8 = undefined;
    var pos: usize = 0;
    control[pos] = 0x00; // control stream type
    pos += 1;
    control[pos] = 0x04; // SETTINGS
    pos += 1;
    control[pos] = @intCast(sp_len);
    pos += 1;
    @memcpy(control[pos .. pos + sp_len], settings_payload[0..sp_len]);
    pos += sp_len;
    control[pos] = 0x07; // GOAWAY
    pos += 1;
    control[pos] = @intCast(gp_len);
    pos += 1;
    @memcpy(control[pos .. pos + gp_len], goaway_payload[0..gp_len]);
    pos += gp_len;

    try client.processPeerControlStream(control[0..pos]);
    try std.testing.expectEqual(@as(u64, 2048), client.peer_qpack_max_table_capacity);
    try std.testing.expect(client.goaway_received);
    try std.testing.expectEqual(@as(u64, 4), client.goaway_last_stream_id);
}

test "H3Client aggregates a chunked response via feedResponseData" {
    // Build a response wire: HEADERS frame + two DATA frames.
    const response = h3_request.Response{ .status = 200 };
    var headers_buf: [512]u8 = undefined;
    const headers_len = try h3_request.encodeResponseHeaders(&headers_buf, response);
    var d1: [128]u8 = undefined;
    const d1_len = try h3_request.encodeDataFrame(&d1, "chunk-one-");
    var d2: [128]u8 = undefined;
    const d2_len = try h3_request.encodeDataFrame(&d2, "chunk-two");

    const MockCtx = struct {
        sent: std.ArrayList(u8) = .empty,
        fn openBidi(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 0;
        }
        fn openUni(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 3;
        }
        fn send(ctx: *anyopaque, sid: u64, data: []const u8, fin: bool) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = fin;
            if (sid != 3) try self.sent.appendSlice(std.testing.allocator, data);
        }
        fn recv(ctx: *anyopaque, sid: u64, buf: []u8) !?usize {
            _ = ctx;
            _ = sid;
            _ = buf;
            return null;
        }
    };
    var mock = MockCtx{};
    defer mock.sent.deinit(std.testing.allocator);
    var conn = H3Client.H3ClientConnection{
        .openBidiStreamFn = MockCtx.openBidi,
        .openUniStreamFn = MockCtx.openUni,
        .sendOnStreamFn = MockCtx.send,
        .recvOnStreamFn = MockCtx.recv,
        .ctx = &mock,
    };
    var client = try H3Client.init(&conn, std.testing.allocator, 4096, 8);
    defer client.deinit();

    // Feed HEADERS + first DATA, then second DATA + fin.
    try std.testing.expect((try client.feedResponseData(0, headers_buf[0..headers_len], false)) == null);
    try std.testing.expect((try client.feedResponseData(0, d1[0..d1_len], false)) == null);
    const resp = (try client.feedResponseData(0, d2[0..d2_len], true)).?;
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("chunk-one-chunk-two", resp.body.?);
    client.releaseResponse(0);
}

test "H3Client skips GREASE frames before response HEADERS" {
    const response = h3_request.Response{ .status = 200 };
    var headers_buf: [512]u8 = undefined;
    const headers_len = try h3_request.encodeResponseHeaders(&headers_buf, response);
    var data_buf: [64]u8 = undefined;
    const data_len = try h3_request.encodeDataFrame(&data_buf, "greased-body");

    // Reserved GREASE type (RFC 9114 §7.2.8); real quiche / Cloudflare servers
    // emit one or more of these before the response HEADERS frame.
    const grease_type: u64 = 31 * 100_000_000_000_000_000 + 33;
    var grease_a: [128]u8 = undefined;
    var ga = buffer.fixedWriter(&grease_a);
    try h3_frame.encodeFrame(ga.writer(), .{ .frame_type = grease_type, .payload = "GREASE is the word" });
    const grease_a_len = ga.getWritten().len;
    var grease_b: [64]u8 = undefined;
    var gb = buffer.fixedWriter(&grease_b);
    try h3_frame.encodeFrame(gb.writer(), .{ .frame_type = grease_type + 0x1f, .payload = "" });
    const grease_b_len = gb.getWritten().len;

    const MockCtx = struct {
        sent: std.ArrayList(u8) = .empty,
        fn openBidi(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 0;
        }
        fn openUni(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 3;
        }
        fn send(ctx: *anyopaque, sid: u64, data: []const u8, fin: bool) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = fin;
            if (sid != 3) try self.sent.appendSlice(std.testing.allocator, data);
        }
        fn recv(ctx: *anyopaque, sid: u64, buf: []u8) !?usize {
            _ = ctx;
            _ = sid;
            _ = buf;
            return null;
        }
    };
    var mock = MockCtx{};
    defer mock.sent.deinit(std.testing.allocator);
    var conn = H3Client.H3ClientConnection{
        .openBidiStreamFn = MockCtx.openBidi,
        .openUniStreamFn = MockCtx.openUni,
        .sendOnStreamFn = MockCtx.send,
        .recvOnStreamFn = MockCtx.recv,
        .ctx = &mock,
    };
    var client = try H3Client.init(&conn, std.testing.allocator, 4096, 8);
    defer client.deinit();

    var wire: [2048]u8 = undefined;
    var pos: usize = 0;
    @memcpy(wire[pos .. pos + grease_a_len], grease_a[0..grease_a_len]);
    pos += grease_a_len;
    @memcpy(wire[pos .. pos + grease_b_len], grease_b[0..grease_b_len]);
    pos += grease_b_len;
    @memcpy(wire[pos .. pos + headers_len], headers_buf[0..headers_len]);
    pos += headers_len;
    @memcpy(wire[pos .. pos + data_len], data_buf[0..data_len]);
    pos += data_len;

    // Feed in two chunks so the skip loop buffers a partial GREASE frame.
    try std.testing.expect((try client.feedResponseData(0, wire[0..1], false)) == null);
    const resp = (try client.feedResponseData(0, wire[1..pos], true)).?;
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expectEqualStrings("greased-body", resp.body.?);
    client.releaseResponse(0);
}

test "H3Client streams a request body via sendRequestStreamed" {
    const MockCtx = struct {
        sent: std.ArrayList(u8) = .empty,
        fins: std.ArrayList(bool) = .empty,
        next_uni: u64 = 3,
        block_data: bool = false,
        fn openBidi(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 0;
        }
        fn openUni(ctx: *anyopaque) !u64 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            const id = self.next_uni;
            self.next_uni += 4;
            return id;
        }
        fn send(ctx: *anyopaque, sid: u64, data: []const u8, fin: bool) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (sid == 3) return; // client encoder/decoder streams (3, 7)
            if (data.len > 0 and data[0] == @backingInt(h3_frame.FrameType.data)) {
                if (self.block_data) {
                    self.block_data = false;
                    return error.FlowControlBlocked;
                }
            }
            try self.sent.appendSlice(std.testing.allocator, data);
            try self.fins.append(std.testing.allocator, fin);
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
        mock.sent.deinit(std.testing.allocator);
        mock.fins.deinit(std.testing.allocator);
    }
    var conn = H3Client.H3ClientConnection{
        .openBidiStreamFn = MockCtx.openBidi,
        .openUniStreamFn = MockCtx.openUni,
        .sendOnStreamFn = MockCtx.send,
        .recvOnStreamFn = MockCtx.recv,
        .ctx = &mock,
    };
    var client = try H3Client.init(&conn, std.testing.allocator, 4096, 8);
    defer client.deinit();
    try client.setPeerMaxTableCapacity(4096);
    try client.enableQpackDynamic(4096);

    const req = h3_request.Request{ .method = "POST", .path = "/upload", .authority = "example.com" };
    const chunks = [_][]const u8{ "aaaa", "bbbb", "cccc" };
    const body = try h3_request.ResponseBody.fromChunks(std.testing.allocator, &chunks);
    const sid = try client.sendRequestStreamed(req, body);

    // Headers (fin=false) + 3 DATA frames + terminating fin frame.
    try std.testing.expectEqual(@as(u64, 0), sid);
    try std.testing.expect(mock.fins.items.len >= 4);
    for (mock.fins.items[0 .. mock.fins.items.len - 1]) |f| try std.testing.expect(!f);
    try std.testing.expect(mock.fins.items[mock.fins.items.len - 1]);
    try std.testing.expect(client.pending_sends.?.count() == 0);
}

test "H3Client sendRequestStreamed retries a flow-control-blocked chunk" {
    const MockCtx = struct {
        sent: std.ArrayList(u8) = .empty,
        next_uni: u64 = 3,
        block_data: bool = true,
        fn openBidi(ctx: *anyopaque) !u64 {
            _ = ctx;
            return 0;
        }
        fn openUni(ctx: *anyopaque) !u64 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            const id = self.next_uni;
            self.next_uni += 4;
            return id;
        }
        fn send(ctx: *anyopaque, sid: u64, data: []const u8, fin: bool) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = fin;
            if (sid == 3) return;
            if (data.len > 0 and data[0] == @backingInt(h3_frame.FrameType.data)) {
                if (self.block_data) {
                    self.block_data = false;
                    return error.FlowControlBlocked;
                }
            }
            try self.sent.appendSlice(std.testing.allocator, data);
        }
        fn recv(ctx: *anyopaque, sid: u64, buf: []u8) !?usize {
            _ = ctx;
            _ = sid;
            _ = buf;
            return null;
        }
    };
    var mock = MockCtx{};
    defer mock.sent.deinit(std.testing.allocator);
    var conn = H3Client.H3ClientConnection{
        .openBidiStreamFn = MockCtx.openBidi,
        .openUniStreamFn = MockCtx.openUni,
        .sendOnStreamFn = MockCtx.send,
        .recvOnStreamFn = MockCtx.recv,
        .ctx = &mock,
    };
    var client = try H3Client.init(&conn, std.testing.allocator, 4096, 8);
    defer client.deinit();
    try client.setPeerMaxTableCapacity(4096);
    try client.enableQpackDynamic(4096);

    const req = h3_request.Request{ .method = "POST", .path = "/upload", .authority = "example.com" };
    const chunks = [_][]const u8{"longbody-chunk"};
    const body = try h3_request.ResponseBody.fromChunks(std.testing.allocator, &chunks);
    _ = try client.sendRequestStreamed(req, body);
    // First DATA chunk was blocked; the stream is still pending until pumped.
    try std.testing.expect(client.pending_sends.?.count() == 1);
    try client.pumpSends();
    try std.testing.expect(client.pending_sends.?.count() == 0);
}
