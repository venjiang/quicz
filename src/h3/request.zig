//! HTTP/3 request/response (RFC 9114 §4).
//!
//! Implements HTTP/3 request and response encoding/decoding
//! over QUIC streams using QPACK header compression.

const std = @import("std");
const h3_frame = @import("frame.zig");
const qpack = @import("qpack.zig");
const h3_limits = @import("limits.zig");
const buffer = @import("../quic/buffer.zig");

/// An HTTP request.
pub const Request = struct {
    method: []const u8,
    path: []const u8,
    scheme: []const u8 = "https",
    authority: ?[]const u8 = null,
    /// Additional headers.
    extra_headers: []const qpack.HeaderField = &.{},
    /// Request body (for POST/PUT).
    body: ?[]const u8 = null,

    /// Encode the request as QPACK header block + optional DATA frame.
    pub fn encodeHeaders(self: *const Request, out: []u8) !usize {
        // Build pseudo-header fields
        var fields_buf: [32]qpack.HeaderField = undefined;
        var count: usize = 0;

        fields_buf[count] = .{ .name = ":method", .value = self.method };
        count += 1;
        fields_buf[count] = .{ .name = ":path", .value = self.path };
        count += 1;
        fields_buf[count] = .{ .name = ":scheme", .value = self.scheme };
        count += 1;
        if (self.authority) |auth| {
            fields_buf[count] = .{ .name = ":authority", .value = auth };
            count += 1;
        }
        for (self.extra_headers) |h| {
            if (count >= fields_buf.len) break;
            fields_buf[count] = h;
            count += 1;
        }

        return qpack.encodeHeaderBlock(out, fields_buf[0..count]);
    }
};

/// An HTTP response.
pub const Response = struct {
    status: u16,
    /// Additional headers.
    extra_headers: []const qpack.HeaderField = &.{},
    /// Response body (single contiguous slice, encoded as one DATA frame).
    body: ?[]const u8 = null,
    /// Streamed response body. When set, takes precedence over `body` and is
    /// emitted as multiple DATA frames by the response pump.
    body_stream: ?ResponseBody = null,

    /// Encode the response as QPACK header block.
    pub fn encodeHeaders(self: *const Response, out: []u8) !usize {
        var status_buf: [8]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{self.status}) catch "500";

        var fields_buf: [32]qpack.HeaderField = undefined;
        var count: usize = 0;

        fields_buf[count] = .{ .name = ":status", .value = status_str };
        count += 1;
        for (self.extra_headers) |h| {
            if (count >= fields_buf.len) break;
            fields_buf[count] = h;
            count += 1;
        }

        return qpack.encodeHeaderBlock(out, fields_buf[0..count]);
    }

    /// Whether the response indicates success (2xx).
    pub fn isSuccess(self: *const Response) bool {
        return self.status >= 200 and self.status < 300;
    }
};

/// A chunked response body produced lazily by the server handler.
///
/// Modelled as a non-blocking pull iterator: the response pump calls `next_fn`
/// with a caller-owned buffer, fills it with the next chunk of body bytes, and
/// returns the number of bytes written (or `null` when the body is exhausted).
/// Must never block — it returns whatever data is currently available, matching
/// quic-zig's `recvBody` and quiche's `send_body` pull model.
///
/// `deinit_fn` (optional) is invoked by the H3 server when the body is fully
/// sent or the stream is cancelled. This vtable seam lets a future async
/// (producer-task) body implementation swap in without changing the send path.
pub const ResponseBody = struct {
    ctx: *anyopaque,
    /// Fill `buf` with the next chunk; `null` reports end-of-body.
    next_fn: *const fn (ctx: *anyopaque, buf: []u8) anyerror!?usize,
    /// Release resources owned by the body producer, if any.
    deinit_fn: ?*const fn (ctx: *anyopaque) void = null,

    pub fn next(self: ResponseBody, buf: []u8) anyerror!?usize {
        return self.next_fn(self.ctx, buf);
    }
    pub fn deinit(self: ResponseBody) void {
        if (self.deinit_fn) |f| f(self.ctx);
    }

    /// Build a body that streams a fixed list of chunks in order.
    pub fn fromChunks(allocator: std.mem.Allocator, chunks: []const []const u8) !ResponseBody {
        const owned = try allocator.dupe([]const u8, chunks);
        errdefer allocator.free(owned);
        const state = try allocator.create(ChunksState);
        state.* = .{ .allocator = allocator, .chunks = owned, .index = 0 };
        return .{
            .ctx = state,
            .next_fn = chunksNext,
            .deinit_fn = chunksDeinit,
        };
    }

    /// Build a body that repeats a single byte `total` times in chunks of
    /// `max_response_chunk_payload`. A cheap generator for `/stream` demos.
    pub fn fromRepeating(allocator: std.mem.Allocator, byte: u8, total: u64) !ResponseBody {
        const state = try allocator.create(RepeatingState);
        state.* = .{ .allocator = allocator, .byte = byte, .remaining = total };
        return .{
            .ctx = state,
            .next_fn = repeatingNext,
            .deinit_fn = repeatingDeinit,
        };
    }

    const ChunksState = struct {
        allocator: std.mem.Allocator,
        chunks: []const []const u8,
        index: usize = 0,
    };
    const RepeatingState = struct {
        allocator: std.mem.Allocator,
        byte: u8,
        remaining: u64,
    };

    fn chunksNext(ctx: *anyopaque, buf: []u8) anyerror!?usize {
        const state: *ChunksState = @ptrCast(@alignCast(ctx));
        if (state.index >= state.chunks.len) return null;
        const chunk = state.chunks[state.index];
        state.index += 1;
        @memcpy(buf[0..chunk.len], chunk);
        return chunk.len;
    }
    fn chunksDeinit(ctx: *anyopaque) void {
        const state: *ChunksState = @ptrCast(@alignCast(ctx));
        const allocator = state.allocator;
        allocator.free(state.chunks);
        allocator.destroy(state);
    }

    fn repeatingNext(ctx: *anyopaque, buf: []u8) anyerror!?usize {
        const state: *RepeatingState = @ptrCast(@alignCast(ctx));
        if (state.remaining == 0) return null;
        const n: usize = @intCast(@min(state.remaining, buf.len));
        @memset(buf[0..n], state.byte);
        state.remaining -= n;
        return n;
    }
    fn repeatingDeinit(ctx: *anyopaque) void {
        const state: *RepeatingState = @ptrCast(@alignCast(ctx));
        state.allocator.destroy(state);
    }
};

/// Encode a complete HTTP/3 request as HEADERS + optional DATA frames.
pub fn encodeRequest(out: []u8, request: Request) !usize {
    var pos: usize = 0;

    // Encode HEADERS frame
    var header_buf: [4096]u8 = undefined;
    const header_len = try request.encodeHeaders(&header_buf);

    // Write HEADERS frame
    const fbs_out = out[pos..];
    pos += try writeFrame(fbs_out, @intFromEnum(h3_frame.FrameType.headers), header_buf[0..header_len]);

    // Write DATA frame if body present
    if (request.body) |body| {
        if (body.len > 0) {
            pos += try writeFrame(out[pos..], @intFromEnum(h3_frame.FrameType.data), body);
        }
    }

    return pos;
}

/// Encode only the HEADERS frame of a request, without any body. Used by the
/// streaming send path, which emits HEADERS first and body DATA frames later.
pub fn encodeRequestHeaders(out: []u8, request: Request) !usize {
    var header_buf: [4096]u8 = undefined;
    const header_len = try request.encodeHeaders(&header_buf);
    return writeFrame(out, @intFromEnum(h3_frame.FrameType.headers), header_buf[0..header_len]);
}

/// Encode a complete HTTP/3 response as HEADERS + optional DATA frames.
pub fn encodeResponse(out: []u8, response: Response) !usize {
    var pos: usize = 0;

    var header_buf: [4096]u8 = undefined;
    const header_len = try response.encodeHeaders(&header_buf);

    pos += try writeFrame(out[pos..], @intFromEnum(h3_frame.FrameType.headers), header_buf[0..header_len]);

    if (response.body) |body| {
        if (body.len > 0) {
            pos += try writeFrame(out[pos..], @intFromEnum(h3_frame.FrameType.data), body);
        }
    }

    return pos;
}

/// Encode only the HEADERS frame of a response, without any body. Used by the
/// streaming send path, which emits HEADERS first and body DATA frames later.
pub fn encodeResponseHeaders(out: []u8, response: Response) !usize {
    var header_buf: [4096]u8 = undefined;
    const header_len = try response.encodeHeaders(&header_buf);
    return writeFrame(out, @intFromEnum(h3_frame.FrameType.headers), header_buf[0..header_len]);
}

/// Encode only the HEADERS frame of a response using QPACK dynamic references.
/// Returns the encode result (encoder-stream instruction length + RIC) so the
/// caller can emit encoder instructions before the frame on the wire.
pub fn encodeResponseHeadersWithDynamic(
    out: []u8,
    response: Response,
    dynamic_table: *qpack.DynamicTable,
    encoder_stream_out: []u8,
) !DynamicEncodeResult {
    var status_buf: [8]u8 = undefined;
    const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{response.status}) catch "500";

    var fields_buf: [32]qpack.HeaderField = undefined;
    var count: usize = 0;
    fields_buf[count] = .{ .name = ":status", .value = status_str };
    count += 1;
    for (response.extra_headers) |h| {
        if (count >= fields_buf.len) break;
        fields_buf[count] = h;
        count += 1;
    }

    var header_buf: [4096]u8 = undefined;
    const enc = try qpack.encodeHeaderBlockWithDynamicInserting(&header_buf, encoder_stream_out, fields_buf[0..count], dynamic_table);
    const pos = try writeFrame(out, @intFromEnum(h3_frame.FrameType.headers), header_buf[0..enc.header_block_len]);
    return .{
        .len = pos,
        .encoder_stream_len = enc.encoder_stream_len,
        .required_insert_count = enc.required_insert_count,
    };
}

/// Encode a DATA frame with the given payload.
pub fn encodeDataFrame(out: []u8, payload: []const u8) !usize {
    return writeFrame(out, @intFromEnum(h3_frame.FrameType.data), payload);
}

/// Parse a single DATA frame from the front of `data`. Returns the payload
/// slice (borrowed from `data`) and the bytes consumed. `IncompleteFrame` is
/// propagated when the frame is split across buffer boundaries; a non-DATA
/// frame yields `ExpectedDataFrame`.
pub fn takeDataFrame(data: []const u8) !struct { payload: []const u8, consumed: usize } {
    const result = try h3_frame.decodeFrame(data);
    if (result.frame.frame_type != @intFromEnum(h3_frame.FrameType.data)) {
        return error.ExpectedDataFrame;
    }
    return .{ .payload = result.frame.payload, .consumed = result.consumed };
}

/// Write a single H3 frame to a buffer. Returns bytes written.
fn writeFrame(out: []u8, frame_type: u64, payload: []const u8) !usize {
    var pos: usize = 0;
    // Frame type varint
    pos += writeVarInt(out[pos..], frame_type);
    // Payload length varint
    pos += writeVarInt(out[pos..], payload.len);
    // Payload
    @memcpy(out[pos .. pos + payload.len], payload);
    pos += payload.len;
    return pos;
}

fn writeVarInt(out: []u8, value: u64) usize {
    if (value <= 63) {
        out[0] = @intCast(value);
        return 1;
    } else if (value <= 16383) {
        out[0] = @intCast(0x40 | (value >> 8));
        out[1] = @intCast(value & 0xff);
        return 2;
    } else if (value <= 1073741823) {
        out[0] = @intCast(0x80 | (value >> 24));
        out[1] = @intCast((value >> 16) & 0xff);
        out[2] = @intCast((value >> 8) & 0xff);
        out[3] = @intCast(value & 0xff);
        return 4;
    }
    out[0] = 0;
    return 1;
}

test "HTTP/3 request encode" {
    const req = Request{
        .method = "GET",
        .path = "/index.html",
        .scheme = "https",
        .authority = "example.com",
    };

    var buf: [4096]u8 = undefined;
    const len = try encodeRequest(&buf, req);
    try std.testing.expect(len > 0);

    // First frame should be HEADERS (type 0x01)
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);
}

test "HTTP/3 response encode" {
    const resp = Response{
        .status = 200,
        .body = "Hello, World!",
    };

    var buf: [4096]u8 = undefined;
    const len = try encodeResponse(&buf, resp);
    try std.testing.expect(len > 0);

    // First frame should be HEADERS (type 0x01)
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);
    try std.testing.expect(resp.isSuccess());
}

test "HTTP/3 request with body" {
    const req = Request{
        .method = "POST",
        .path = "/api/data",
        .body = "{\"key\": \"value\"}",
    };

    var buf: [4096]u8 = undefined;
    const len = try encodeRequest(&buf, req);
    try std.testing.expect(len > 0);

    // Should have HEADERS + DATA frames
    // First: HEADERS (0x01)
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);
}

test "HTTP/3 response status codes" {
    const ok = Response{ .status = 200 };
    try std.testing.expect(ok.isSuccess());

    const not_found = Response{ .status = 404 };
    try std.testing.expect(!not_found.isSuccess());

    const server_error = Response{ .status = 500 };
    try std.testing.expect(!server_error.isSuccess());
}

test "HTTP/3 request encodeHeaders" {
    const req = Request{
        .method = "GET",
        .path = "/",
        .authority = "test.com",
    };

    var buf: [256]u8 = undefined;
    const len = try req.encodeHeaders(&buf);
    try std.testing.expect(len > 0);
    // QPACK prefix: RIC=0, DB=0, then :method GET (RFC 9204 static index 17)
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]); // RIC
    try std.testing.expectEqual(@as(u8, 0x00), buf[1]); // DB
    try std.testing.expectEqual(@as(u8, 0xd1), buf[2]); // :method GET
}

/// Decode an HTTP/3 request from a byte buffer containing HEADERS + optional DATA frames.
/// Returns the decoded request and the number of bytes consumed.
pub const DecodeRequestInfo = struct {
    request: DecodedRequest,
    consumed: usize,
};

pub fn decodeRequest(data: []const u8) !DecodeRequestInfo {
    // Legacy behavior: non-pseudo request headers are discarded, so pass an
    // empty sink to avoid exposing a dangling stack-backed slice.
    return decodeRequestWithHeaders(data, &.{});
}

/// Like `decodeRequest`, but also copies non-pseudo request headers into
/// `headers_out` (up to its capacity) and links them from
/// `request.headers`. Header slices borrow the input buffer, so `data` must
/// outlive the returned request. Callers that don't need the headers should
/// keep using `decodeRequest`.
pub fn decodeRequestWithHeaders(data: []const u8, headers_out: []qpack.HeaderField) !DecodeRequestInfo {
    var pos: usize = 0;
    var method: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var scheme: ?[]const u8 = null;
    var authority: ?[]const u8 = null;
    var body: ?[]const u8 = null;
    var header_count: usize = 0;

    // Skip GREASE / unknown extension frames that may precede the initial
    // HEADERS frame (RFC 9114 §7.2.8, §9), then require HEADERS.
    var headers_result = try h3_frame.decodeFrame(data[pos..]);
    while (headers_result.frame.frame_type != @intFromEnum(h3_frame.FrameType.headers)) {
        if (!h3_frame.isIgnorableHeaderPrefixFrame(headers_result.frame.frame_type)) {
            return error.ExpectedHeadersFrame;
        }
        pos += headers_result.consumed;
        headers_result = try h3_frame.decodeFrame(data[pos..]);
    }
    pos += headers_result.consumed;

    // Decode QPACK header block
    var fields: [32]qpack.HeaderField = undefined;
    const field_count = try qpack.decodeHeaderBlock(headers_result.frame.payload, &fields);

    for (fields[0..field_count]) |field| {
        // Enforce per-field length + casing limits before use (RFC 9204 §3.1).
        try h3_limits.validateHeaderField(field.name, field.value);
        if (std.mem.eql(u8, field.name, ":method")) {
            method = field.value;
        } else if (std.mem.eql(u8, field.name, ":path")) {
            path = field.value;
        } else if (std.mem.eql(u8, field.name, ":scheme")) {
            scheme = field.value;
        } else if (std.mem.eql(u8, field.name, ":authority")) {
            authority = field.value;
        } else if (header_count < headers_out.len) {
            headers_out[header_count] = field;
            header_count += 1;
        }
    }

    if (method == null) return error.MissingMethod;
    if (path == null) return error.MissingPath;

    // Parse optional DATA frame
    if (pos < data.len) {
        const data_result = h3_frame.decodeFrame(data[pos..]) catch null;
        if (data_result) |dr| {
            if (dr.frame.frame_type == @intFromEnum(h3_frame.FrameType.data)) {
                body = dr.frame.payload;
                pos += dr.consumed;
            }
        }
    }

    return .{
        .request = .{
            .method = method.?,
            .path = path.?,
            .scheme = scheme orelse "https",
            .authority = authority,
            .body = body,
            .headers = headers_out[0..header_count],
        },
        .consumed = pos,
    };
}

/// Decode an HTTP/3 response from a byte buffer containing HEADERS + optional DATA frames.
const DecodeResponseInfo = struct {
    status: u16,
    body: ?[]const u8,
    required_insert_count: u64,
    consumed: usize,
    header_count: usize,
};

fn decodeResponseImpl(
    data: []const u8,
    dynamic_table: ?*const qpack.DynamicTable,
    headers_out: ?[]qpack.HeaderField,
) !DecodeResponseInfo {
    var pos: usize = 0;
    var status: ?u16 = null;
    var body: ?[]const u8 = null;
    var required_insert_count: u64 = 0;
    var header_count: usize = 0;

    // Skip GREASE / unknown extension frames that may precede the initial
    // HEADERS frame (RFC 9114 §7.2.8, §9), then require HEADERS.
    var headers_result = try h3_frame.decodeFrame(data[pos..]);
    while (headers_result.frame.frame_type != @intFromEnum(h3_frame.FrameType.headers)) {
        if (!h3_frame.isIgnorableHeaderPrefixFrame(headers_result.frame.frame_type)) {
            return error.ExpectedHeadersFrame;
        }
        pos += headers_result.consumed;
        headers_result = try h3_frame.decodeFrame(data[pos..]);
    }
    pos += headers_result.consumed;

    // Decode QPACK header block
    var fields: [32]qpack.HeaderField = undefined;
    var field_count: usize = undefined;
    if (dynamic_table) |dt| {
        const decoded_block = try qpack.decodeHeaderBlockWithDynamicInfo(headers_result.frame.payload, &fields, dt);
        field_count = decoded_block.field_count;
        required_insert_count = decoded_block.required_insert_count;
    } else {
        field_count = try qpack.decodeHeaderBlock(headers_result.frame.payload, &fields);
    }
    if (headers_out) |out| {
        const copied = @min(field_count, out.len);
        @memcpy(out[0..copied], fields[0..copied]);
        header_count = copied;
    }

    for (fields[0..field_count]) |field| {
        if (std.mem.eql(u8, field.name, ":status")) {
            status = std.fmt.parseInt(u16, field.value, 10) catch return error.InvalidStatusCode;
        }
    }

    if (status == null) return error.MissingStatus;

    // Parse optional DATA frame
    if (pos < data.len) {
        const data_result = h3_frame.decodeFrame(data[pos..]) catch null;
        if (data_result) |dr| {
            if (dr.frame.frame_type == @intFromEnum(h3_frame.FrameType.data)) {
                body = dr.frame.payload;
                pos += dr.consumed;
            }
        }
    }

    return .{
        .status = status.?,
        .body = body,
        .required_insert_count = required_insert_count,
        .consumed = pos,
        .header_count = header_count,
    };
}

/// Decode an HTTP/3 response without retaining the header fields.
pub fn decodeResponse(data: []const u8) !struct { response: DecodedResponse, consumed: usize } {
    const info = try decodeResponseImpl(data, null, null);
    return .{
        .response = .{ .status = info.status, .body = info.body },
        .consumed = info.consumed,
    };
}

/// Decode an HTTP/3 response and copy the decoded header fields into
/// `headers_out`. Name/value slices borrow from `data` (or the QPACK static
/// table), so the caller must keep the HEADERS frame alive while using them.
pub fn decodeResponseWithHeaders(
    data: []const u8,
    headers_out: []qpack.HeaderField,
) !struct { response: DecodedResponse, consumed: usize, header_count: usize } {
    const info = try decodeResponseImpl(data, null, headers_out);
    return .{
        .response = .{
            .status = info.status,
            .body = info.body,
            .headers = headers_out[0..info.header_count],
        },
        .consumed = info.consumed,
        .header_count = info.header_count,
    };
}

/// Encode only the HEADERS frame of a request using QPACK dynamic references.
/// Returns the encode result (encoder-stream instruction length + RIC) so the
/// caller can emit encoder instructions before the frame on the wire.
pub fn encodeRequestHeadersWithDynamic(
    out: []u8,
    request: Request,
    dynamic_table: *qpack.DynamicTable,
    encoder_stream_out: []u8,
) !DynamicEncodeResult {
    var fields_buf: [32]qpack.HeaderField = undefined;
    var count: usize = 0;
    fields_buf[count] = .{ .name = ":method", .value = request.method };
    count += 1;
    fields_buf[count] = .{ .name = ":path", .value = request.path };
    count += 1;
    fields_buf[count] = .{ .name = ":scheme", .value = request.scheme };
    count += 1;
    if (request.authority) |auth| {
        fields_buf[count] = .{ .name = ":authority", .value = auth };
        count += 1;
    }
    for (request.extra_headers) |h| {
        if (count >= fields_buf.len) break;
        fields_buf[count] = h;
        count += 1;
    }

    var header_buf: [4096]u8 = undefined;
    const enc = try qpack.encodeHeaderBlockWithDynamicInserting(&header_buf, encoder_stream_out, fields_buf[0..count], dynamic_table);
    const pos = try writeFrame(out, @intFromEnum(h3_frame.FrameType.headers), header_buf[0..enc.header_block_len]);
    return .{
        .len = pos,
        .encoder_stream_len = enc.encoder_stream_len,
        .required_insert_count = enc.required_insert_count,
    };
}

/// A decoded HTTP request (borrows from the input buffer).
pub const DecodedRequest = struct {
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    body: ?[]const u8,
    /// Non-pseudo request headers, in receive order. Empty when the caller
    /// used `decodeRequest` (which discards them); populated only by
    /// `decodeRequestWithHeaders`. Field slices borrow the input buffer.
    headers: []const qpack.HeaderField = &.{},
};

/// A decoded HTTP response (borrows from the input buffer).
pub const DecodedResponse = struct {
    status: u16,
    body: ?[]const u8,
    /// Decoded response header fields. The `[]HeaderField` array is
    /// caller-provided; name/value slices borrow from the response wire or the
    /// QPACK static table, so the backing HEADERS frame must outlive them.
    headers: []const qpack.HeaderField = &.{},

    pub fn isSuccess(self: *const DecodedResponse) bool {
        return self.status >= 200 and self.status < 300;
    }
};

test "HTTP/3 request encode/decode roundtrip" {
    const req = Request{
        .method = "GET",
        .path = "/index.html",
        .scheme = "https",
        .authority = "example.com",
    };

    var buf: [4096]u8 = undefined;
    const len = try encodeRequest(&buf, req);

    const result = try decodeRequest(buf[0..len]);
    try std.testing.expectEqualStrings("GET", result.request.method);
    try std.testing.expectEqualStrings("/index.html", result.request.path);
    try std.testing.expectEqualStrings("https", result.request.scheme);
    try std.testing.expectEqualStrings("example.com", result.request.authority.?);
    try std.testing.expect(result.request.body == null);
}

test "HTTP/3 request rejects uppercase header name" {
    // Build a QPACK header block with a literal field whose name contains an
    // uppercase byte (RFC 9114 §4.2 forbids). wrap it in a HEADERS frame and
    // assert decodeRequest enforces the casing limit via validateHeaderField.
    var block: [64]u8 = undefined;
    block[0] = 0x00; // Required Insert Count = 0
    block[1] = 0x00; // Delta Base = 0
    block[2] = 0x25; // Literal without Name Reference: 001N + H=0 + name len 5
    @memcpy(block[3..8], "X-Big"); // uppercase name
    block[8] = 1; // value length (8-bit prefix)
    block[9] = 'v';

    const block_len = 10;
    var buf: [64]u8 = undefined;
    buf[0] = @intFromEnum(h3_frame.FrameType.headers); // HEADERS
    buf[1] = @intCast(block_len); // 1-byte length
    @memcpy(buf[2 .. 2 + block_len], block[0..block_len]);
    try std.testing.expectError(error.UppercaseHeaderName, decodeRequest(buf[0 .. 2 + block_len]));
}

test "HTTP/3 response encode/decode roundtrip" {
    const resp = Response{
        .status = 200,
        .body = "Hello, HTTP/3!",
    };

    var buf: [4096]u8 = undefined;
    const len = try encodeResponse(&buf, resp);

    const result = try decodeResponse(buf[0..len]);
    try std.testing.expectEqual(@as(u16, 200), result.response.status);
    try std.testing.expect(result.response.isSuccess());
    try std.testing.expectEqualStrings("Hello, HTTP/3!", result.response.body.?);
}

test "HTTP/3 POST request with body roundtrip" {
    const req = Request{
        .method = "POST",
        .path = "/api/submit",
        .body = "{\"key\":\"value\"}",
    };

    var buf: [4096]u8 = undefined;
    const len = try encodeRequest(&buf, req);

    const result = try decodeRequest(buf[0..len]);
    try std.testing.expectEqualStrings("POST", result.request.method);
    try std.testing.expectEqualStrings("/api/submit", result.request.path);
    try std.testing.expectEqualStrings("{\"key\":\"value\"}", result.request.body.?);
}

test "HTTP/3 404 response roundtrip" {
    const resp = Response{
        .status = 404,
        .body = "Not Found",
    };

    var buf: [4096]u8 = undefined;
    const len = try encodeResponse(&buf, resp);

    const result = try decodeResponse(buf[0..len]);
    try std.testing.expectEqual(@as(u16, 404), result.response.status);
    try std.testing.expect(!result.response.isSuccess());
    try std.testing.expectEqualStrings("Not Found", result.response.body.?);
}

// ---------------------------------------------------------------------------
// Dynamic table variants (RFC 9204 integration)
// ---------------------------------------------------------------------------

/// Encode a complete HTTP/3 request using QPACK dynamic table references.
/// Result of a dynamic-table-encoding call: the encoded request/response bytes
/// and the length of the QPACK encoder-stream Insert instructions produced.
pub const DynamicEncodeResult = struct {
    len: usize,
    encoder_stream_len: usize,
    required_insert_count: u64,
};

pub fn encodeRequestWithDynamic(
    out: []u8,
    request: Request,
    dynamic_table: *qpack.DynamicTable,
    encoder_stream_out: []u8,
) !DynamicEncodeResult {
    var pos: usize = 0;

    // Build header fields
    var fields_buf: [32]qpack.HeaderField = undefined;
    var count: usize = 0;
    fields_buf[count] = .{ .name = ":method", .value = request.method };
    count += 1;
    fields_buf[count] = .{ .name = ":path", .value = request.path };
    count += 1;
    fields_buf[count] = .{ .name = ":scheme", .value = request.scheme };
    count += 1;
    if (request.authority) |auth| {
        fields_buf[count] = .{ .name = ":authority", .value = auth };
        count += 1;
    }
    for (request.extra_headers) |h| {
        if (count >= fields_buf.len) break;
        fields_buf[count] = h;
        count += 1;
    }

    // Encode header block with dynamic table (inserts new fields + emits
    // encoder-stream Insert instructions).
    var header_buf: [4096]u8 = undefined;
    const enc = try qpack.encodeHeaderBlockWithDynamicInserting(&header_buf, encoder_stream_out, fields_buf[0..count], dynamic_table);

    // Write HEADERS frame
    pos += try writeFrame(out[pos..], @intFromEnum(h3_frame.FrameType.headers), header_buf[0..enc.header_block_len]);

    // Write DATA frame if body present
    if (request.body) |body| {
        if (body.len > 0) {
            pos += try writeFrame(out[pos..], @intFromEnum(h3_frame.FrameType.data), body);
        }
    }

    return .{
        .len = pos,
        .encoder_stream_len = enc.encoder_stream_len,
        .required_insert_count = enc.required_insert_count,
    };
}

/// Decode an HTTP/3 request using QPACK dynamic table references.
pub const DynamicDecodeRequestInfo = struct {
    request: DecodedRequest,
    consumed: usize,
    required_insert_count: u64,
};

/// Decode an HTTP/3 request using QPACK dynamic table references, discarding
/// non-pseudo request headers (legacy behavior).
pub fn decodeRequestWithDynamic(
    data: []const u8,
    dynamic_table: *const qpack.DynamicTable,
) !DynamicDecodeRequestInfo {
    return decodeRequestWithDynamicWithHeaders(data, dynamic_table, &.{});
}

/// Like `decodeRequestWithDynamic`, but also copies non-pseudo request
/// headers into `headers_out` (up to its capacity) and links them from
/// `request.headers` (which borrows `headers_out`).
pub fn decodeRequestWithDynamicWithHeaders(
    data: []const u8,
    dynamic_table: *const qpack.DynamicTable,
    headers_out: []qpack.HeaderField,
) !DynamicDecodeRequestInfo {
    var pos: usize = 0;
    var method: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var scheme: ?[]const u8 = null;
    var authority: ?[]const u8 = null;
    var body: ?[]const u8 = null;

    // Skip GREASE / unknown extension frames that may precede the initial
    // HEADERS frame (RFC 9114 §7.2.8, §9), then require HEADERS.
    var headers_result = try h3_frame.decodeFrame(data[pos..]);
    while (headers_result.frame.frame_type != @intFromEnum(h3_frame.FrameType.headers)) {
        if (!h3_frame.isIgnorableHeaderPrefixFrame(headers_result.frame.frame_type)) {
            return error.ExpectedHeadersFrame;
        }
        pos += headers_result.consumed;
        headers_result = try h3_frame.decodeFrame(data[pos..]);
    }
    pos += headers_result.consumed;

    // Decode QPACK header block with dynamic table
    var fields: [32]qpack.HeaderField = undefined;
    const decoded_block = try qpack.decodeHeaderBlockWithDynamicInfo(headers_result.frame.payload, &fields, dynamic_table);
    const field_count = decoded_block.field_count;

    var header_count: usize = 0;
    for (fields[0..field_count]) |field| {
        // Enforce per-field length + casing limits before use (RFC 9204 §3.1).
        try h3_limits.validateHeaderField(field.name, field.value);
        if (std.mem.eql(u8, field.name, ":method")) {
            method = field.value;
        } else if (std.mem.eql(u8, field.name, ":path")) {
            path = field.value;
        } else if (std.mem.eql(u8, field.name, ":scheme")) {
            scheme = field.value;
        } else if (std.mem.eql(u8, field.name, ":authority")) {
            authority = field.value;
        } else if (header_count < headers_out.len) {
            headers_out[header_count] = field;
            header_count += 1;
        }
    }

    if (method == null) return error.MissingMethod;
    if (path == null) return error.MissingPath;

    // Parse optional DATA frame
    if (pos < data.len) {
        const data_result = h3_frame.decodeFrame(data[pos..]) catch null;
        if (data_result) |dr| {
            if (dr.frame.frame_type == @intFromEnum(h3_frame.FrameType.data)) {
                body = dr.frame.payload;
                pos += dr.consumed;
            }
        }
    }

    return .{
        .request = .{
            .method = method.?,
            .path = path.?,
            .scheme = scheme orelse "https",
            .authority = authority,
            .body = body,
            .headers = headers_out[0..header_count],
        },
        .consumed = pos,
        .required_insert_count = decoded_block.required_insert_count,
    };
}

/// Encode a complete HTTP/3 response using QPACK dynamic table references.
pub fn encodeResponseWithDynamic(
    out: []u8,
    response: Response,
    dynamic_table: *qpack.DynamicTable,
    encoder_stream_out: []u8,
) !DynamicEncodeResult {
    var pos: usize = 0;

    var status_buf: [8]u8 = undefined;
    const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{response.status}) catch "500";

    var fields_buf: [32]qpack.HeaderField = undefined;
    var count: usize = 0;
    fields_buf[count] = .{ .name = ":status", .value = status_str };
    count += 1;
    for (response.extra_headers) |h| {
        if (count >= fields_buf.len) break;
        fields_buf[count] = h;
        count += 1;
    }

    var header_buf: [4096]u8 = undefined;
    const enc = try qpack.encodeHeaderBlockWithDynamicInserting(&header_buf, encoder_stream_out, fields_buf[0..count], dynamic_table);

    pos += try writeFrame(out[pos..], @intFromEnum(h3_frame.FrameType.headers), header_buf[0..enc.header_block_len]);

    if (response.body) |body| {
        if (body.len > 0) {
            pos += try writeFrame(out[pos..], @intFromEnum(h3_frame.FrameType.data), body);
        }
    }

    return .{
        .len = pos,
        .encoder_stream_len = enc.encoder_stream_len,
        .required_insert_count = enc.required_insert_count,
    };
}

/// Decode an HTTP/3 response using QPACK dynamic table references.
pub fn decodeResponseWithDynamic(
    data: []const u8,
    dynamic_table: *const qpack.DynamicTable,
) !struct { response: DecodedResponse, consumed: usize, required_insert_count: u64 } {
    const info = try decodeResponseImpl(data, dynamic_table, null);
    return .{
        .response = .{ .status = info.status, .body = info.body },
        .consumed = info.consumed,
        .required_insert_count = info.required_insert_count,
    };
}

/// Decode an HTTP/3 response with dynamic QPACK and copy the decoded header
/// fields into `headers_out`. Name/value slices borrow from `data` (or the
/// QPACK static table), so the caller must keep the HEADERS frame alive.
pub fn decodeResponseWithDynamicAndHeaders(
    data: []const u8,
    dynamic_table: *const qpack.DynamicTable,
    headers_out: []qpack.HeaderField,
) !struct { response: DecodedResponse, consumed: usize, required_insert_count: u64, header_count: usize } {
    const info = try decodeResponseImpl(data, dynamic_table, headers_out);
    return .{
        .response = .{
            .status = info.status,
            .body = info.body,
            .headers = headers_out[0..info.header_count],
        },
        .consumed = info.consumed,
        .required_insert_count = info.required_insert_count,
        .header_count = info.header_count,
    };
}

// ---------------------------------------------------------------------------
// Dynamic table request/response tests
// ---------------------------------------------------------------------------

test "HTTP/3 request with dynamic table roundtrip" {
    var dt = qpack.DynamicTable.init(std.testing.allocator);
    defer dt.deinit();
    dt.setCapacity(4096);
    try dt.insert("x-request-id", "req-abc-123");
    try dt.insert("x-api-key", "secret-key-456");

    const extra = [_]qpack.HeaderField{
        .{ .name = "x-request-id", .value = "req-abc-123" },
        .{ .name = "x-api-key", .value = "secret-key-456" },
    };

    const req = Request{
        .method = "GET",
        .path = "/api/data",
        .authority = "api.example.com",
        .extra_headers = &extra,
    };

    var buf: [4096]u8 = undefined;
    var instr_buf: [4096]u8 = undefined;
    const len = (try encodeRequestWithDynamic(&buf, req, &dt, &instr_buf)).len;

    const result = try decodeRequestWithDynamic(buf[0..len], &dt);
    try std.testing.expectEqualStrings("GET", result.request.method);
    try std.testing.expectEqualStrings("/api/data", result.request.path);
    try std.testing.expectEqualStrings("api.example.com", result.request.authority.?);
}

test "HTTP/3 response with dynamic table roundtrip" {
    var dt = qpack.DynamicTable.init(std.testing.allocator);
    defer dt.deinit();
    dt.setCapacity(4096);
    try dt.insert("content-type", "application/json");
    try dt.insert("x-cache", "HIT");

    const extra = [_]qpack.HeaderField{
        .{ .name = "content-type", .value = "application/json" },
        .{ .name = "x-cache", .value = "HIT" },
    };

    const resp = Response{
        .status = 200,
        .extra_headers = &extra,
        .body = "{\"result\":\"ok\"}",
    };

    var buf: [4096]u8 = undefined;
    var instr_buf: [4096]u8 = undefined;
    const len = (try encodeResponseWithDynamic(&buf, resp, &dt, &instr_buf)).len;

    const result = try decodeResponseWithDynamic(buf[0..len], &dt);
    try std.testing.expectEqual(@as(u16, 200), result.response.status);
    try std.testing.expect(result.response.isSuccess());
    try std.testing.expectEqualStrings("{\"result\":\"ok\"}", result.response.body.?);
}

test "HTTP/3 non-streaming decode skips GREASE before HEADERS" {
    const response = Response{ .status = 200 };
    var headers_buf: [512]u8 = undefined;
    const headers_len = try encodeResponseHeaders(&headers_buf, response);
    var data_buf: [64]u8 = undefined;
    const data_len = try encodeDataFrame(&data_buf, "greased");

    // Reserved GREASE frame (RFC 9114 §7.2.8) before the response HEADERS.
    const grease_type: u64 = 31 * 100_000_000_000_000_000 + 33;
    var grease_buf: [64]u8 = undefined;
    var gw = buffer.fixedWriter(&grease_buf);
    try h3_frame.encodeFrame(gw.writer(), .{ .frame_type = grease_type, .payload = "GREASE is the word" });
    const grease_len = gw.getWritten().len;

    var wire: [1024]u8 = undefined;
    @memcpy(wire[0..grease_len], grease_buf[0..grease_len]);
    @memcpy(wire[grease_len .. grease_len + headers_len], headers_buf[0..headers_len]);
    @memcpy(wire[grease_len + headers_len .. grease_len + headers_len + data_len], data_buf[0..data_len]);

    const result = try decodeResponse(wire[0 .. grease_len + headers_len + data_len]);
    try std.testing.expectEqual(@as(u16, 200), result.response.status);
    try std.testing.expectEqualStrings("greased", result.response.body.?);
}

test "HTTP/3 dynamic response headers are retained via decodeResponseWithDynamicAndHeaders" {
    var dt = qpack.DynamicTable.init(std.testing.allocator);
    defer dt.deinit();
    dt.setCapacity(4096);
    try dt.insert("location", "/redirect-target");

    const extra = [_]qpack.HeaderField{
        .{ .name = "location", .value = "/redirect-target" },
    };
    const resp = Response{
        .status = 302,
        .extra_headers = &extra,
    };

    var buf: [4096]u8 = undefined;
    var instr_buf: [4096]u8 = undefined;
    const len = (try encodeResponseWithDynamic(&buf, resp, &dt, &instr_buf)).len;

    var headers: [32]qpack.HeaderField = undefined;
    const result = try decodeResponseWithDynamicAndHeaders(buf[0..len], &dt, &headers);
    try std.testing.expectEqual(@as(u16, 302), result.response.status);
    try std.testing.expectEqual(@as(usize, 2), result.header_count);
    var found = false;
    for (result.response.headers) |h| {
        if (std.mem.eql(u8, h.name, "location")) {
            try std.testing.expectEqualStrings("/redirect-target", h.value);
            found = true;
        }
    }
    try std.testing.expect(found);
}

test "HTTP/3 dynamic table reduces wire size after acknowledgment" {
    var dt = qpack.DynamicTable.init(std.testing.allocator);
    defer dt.deinit();
    dt.setCapacity(4096);

    const extra = [_]qpack.HeaderField{
        .{ .name = "x-long-header-name", .value = "x-long-header-value-that-is-repeated" },
    };

    const req = Request{
        .method = "GET",
        .path = "/",
        .extra_headers = &extra,
    };

    // First request: the long header is inserted on the encoder stream, but the
    // peer has not acknowledged it, so the block itself still uses literals.
    var buf_first: [4096]u8 = undefined;
    var instr_first: [4096]u8 = undefined;
    const enc_first = try encodeRequestWithDynamic(&buf_first, req, &dt, &instr_first);
    try std.testing.expectEqual(@as(u64, 0), enc_first.required_insert_count);
    try std.testing.expect(enc_first.encoder_stream_len > 0);

    // Peer acknowledges the insertion; now dynamic indexing shrinks the block.
    try dt.acknowledgeReceived(1);
    var buf_acked: [4096]u8 = undefined;
    var instr_acked: [4096]u8 = undefined;
    const enc_acked = try encodeRequestWithDynamic(&buf_acked, req, &dt, &instr_acked);
    try std.testing.expectEqual(@as(u64, 1), enc_acked.required_insert_count);
    try std.testing.expect(enc_acked.len < enc_first.len);

    // Baseline: literal-only encoding writes the long header in full.
    var buf_static: [4096]u8 = undefined;
    const len_static = try encodeRequest(&buf_static, req);
    try std.testing.expect(enc_acked.len < len_static);
}

test "HTTP/3 POST with dynamic table and body" {
    var dt = qpack.DynamicTable.init(std.testing.allocator);
    defer dt.deinit();
    dt.setCapacity(4096);
    try dt.insert("content-type", "application/json");

    const extra = [_]qpack.HeaderField{
        .{ .name = "content-type", .value = "application/json" },
    };

    const req = Request{
        .method = "POST",
        .path = "/api/submit",
        .authority = "example.com",
        .extra_headers = &extra,
        .body = "{\"data\":\"payload\"}",
    };

    var buf: [4096]u8 = undefined;
    var instr_buf: [4096]u8 = undefined;
    const len = (try encodeRequestWithDynamic(&buf, req, &dt, &instr_buf)).len;

    const result = try decodeRequestWithDynamic(buf[0..len], &dt);
    try std.testing.expectEqualStrings("POST", result.request.method);
    try std.testing.expectEqualStrings("/api/submit", result.request.path);
    try std.testing.expectEqualStrings("{\"data\":\"payload\"}", result.request.body.?);
}

// ---------------------------------------------------------------------------
// Streaming body / headers-only / DATA frame tests
// ---------------------------------------------------------------------------

test "encodeResponseHeaders emits only the HEADERS frame" {
    const resp = Response{
        .status = 200,
        .extra_headers = &.{.{ .name = "content-type", .value = "text/plain" }},
        .body = "should not be encoded",
    };
    var buf: [512]u8 = undefined;
    const len = try encodeResponseHeaders(&buf, resp);

    // Wire must be exactly one HEADERS frame with no DATA trailing.
    const frame = try h3_frame.decodeFrame(buf[0..len]);
    try std.testing.expectEqual(@as(u64, @intFromEnum(h3_frame.FrameType.headers)), frame.frame.frame_type);
    try std.testing.expectEqual(len, frame.consumed);
}

test "encodeResponseHeadersWithDynamic roundtrips through decodeResponse" {
    var dt = qpack.DynamicTable.init(std.testing.allocator);
    defer dt.deinit();
    dt.setCapacity(4096);

    const resp = Response{ .status = 201, .extra_headers = &.{.{ .name = "x-id", .value = "abc" }} };
    var buf: [512]u8 = undefined;
    var instr: [512]u8 = undefined;
    const enc = try encodeResponseHeadersWithDynamic(&buf, resp, &dt, &instr);
    try std.testing.expect(enc.len > 0);

    const result = try decodeResponseWithDynamic(buf[0..enc.len], &dt);
    try std.testing.expectEqual(@as(u16, 201), result.response.status);
    // headers-only: no DATA frame, so body stays null.
    try std.testing.expect(result.response.body == null);
}

test "encodeDataFrame and takeDataFrame roundtrip" {
    const payload = "chunk-of-body";
    var buf: [64]u8 = undefined;
    const len = try encodeDataFrame(&buf, payload);
    const taken = try takeDataFrame(buf[0..len]);
    try std.testing.expectEqualStrings(payload, taken.payload);
    try std.testing.expectEqual(len, taken.consumed);
}

test "takeDataFrame propagates IncompleteFrame on split frame" {
    const payload = "abcdefghij";
    var buf: [64]u8 = undefined;
    const len = try encodeDataFrame(&buf, payload);
    try std.testing.expectError(error.IncompleteFrame, takeDataFrame(buf[0 .. len - 1]));
}

test "takeDataFrame rejects non-DATA frame" {
    const resp = Response{ .status = 200 };
    var buf: [64]u8 = undefined;
    const len = try encodeResponseHeaders(&buf, resp);
    try std.testing.expectError(error.ExpectedDataFrame, takeDataFrame(buf[0..len]));
}

test "ResponseBody.fromChunks streams chunks in order" {
    const chunks = [_][]const u8{ "hello-", "chunked-", "world" };
    var body = try ResponseBody.fromChunks(std.testing.allocator, &chunks);
    defer body.deinit();

    var out: [1024]u8 = undefined;
    var pos: usize = 0;
    while (try body.next(out[pos..])) |n| {
        pos += n;
    }
    try std.testing.expectEqualStrings("hello-chunked-world", out[0..pos]);
}

test "ResponseBody.fromRepeating generates a byte pattern" {
    var body = try ResponseBody.fromRepeating(std.testing.allocator, 0x41, 20_000);
    defer body.deinit();

    var out: [4096]u8 = undefined;
    var total: usize = 0;
    while (try body.next(out[0..])) |n| {
        for (out[0..n]) |b| try std.testing.expectEqual(@as(u8, 0x41), b);
        total += n;
    }
    try std.testing.expectEqual(@as(usize, 20_000), total);
}
