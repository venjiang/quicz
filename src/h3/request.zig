//! HTTP/3 request/response (RFC 9114 §4).
//!
//! Implements HTTP/3 request and response encoding/decoding
//! over QUIC streams using QPACK header compression.

const std = @import("std");
const h3_frame = @import("frame.zig");
const qpack = @import("qpack.zig");

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
    /// Response body.
    body: ?[]const u8 = null,

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
    // QPACK prefix: RIC=0, DB=0, then :method GET (static index 8)
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]); // RIC
    try std.testing.expectEqual(@as(u8, 0x00), buf[1]); // DB
    try std.testing.expectEqual(@as(u8, 0xc8), buf[2]); // :method GET
}

/// Decode an HTTP/3 request from a byte buffer containing HEADERS + optional DATA frames.
/// Returns the decoded request and the number of bytes consumed.
pub fn decodeRequest(data: []const u8) !struct { request: DecodedRequest, consumed: usize } {
    var pos: usize = 0;
    var method: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var scheme: ?[]const u8 = null;
    var authority: ?[]const u8 = null;
    var body: ?[]const u8 = null;

    // Parse HEADERS frame
    const headers_result = try h3_frame.decodeFrame(data[pos..]);
    if (headers_result.frame.frame_type != @intFromEnum(h3_frame.FrameType.headers)) {
        return error.ExpectedHeadersFrame;
    }
    pos += headers_result.consumed;

    // Decode QPACK header block
    var fields: [32]qpack.HeaderField = undefined;
    const field_count = try qpack.decodeHeaderBlock(headers_result.frame.payload, &fields);

    for (fields[0..field_count]) |field| {
        if (std.mem.eql(u8, field.name, ":method")) {
            method = field.value;
        } else if (std.mem.eql(u8, field.name, ":path")) {
            path = field.value;
        } else if (std.mem.eql(u8, field.name, ":scheme")) {
            scheme = field.value;
        } else if (std.mem.eql(u8, field.name, ":authority")) {
            authority = field.value;
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
        },
        .consumed = pos,
    };
}

/// Decode an HTTP/3 response from a byte buffer containing HEADERS + optional DATA frames.
pub fn decodeResponse(data: []const u8) !struct { response: DecodedResponse, consumed: usize } {
    var pos: usize = 0;
    var status: ?u16 = null;
    var body: ?[]const u8 = null;

    // Parse HEADERS frame
    const headers_result = try h3_frame.decodeFrame(data[pos..]);
    if (headers_result.frame.frame_type != @intFromEnum(h3_frame.FrameType.headers)) {
        return error.ExpectedHeadersFrame;
    }
    pos += headers_result.consumed;

    // Decode QPACK header block
    var fields: [32]qpack.HeaderField = undefined;
    const field_count = try qpack.decodeHeaderBlock(headers_result.frame.payload, &fields);

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
        .response = .{
            .status = status.?,
            .body = body,
        },
        .consumed = pos,
    };
}

/// A decoded HTTP request (borrows from the input buffer).
pub const DecodedRequest = struct {
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    body: ?[]const u8,
};

/// A decoded HTTP response (borrows from the input buffer).
pub const DecodedResponse = struct {
    status: u16,
    body: ?[]const u8,

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
