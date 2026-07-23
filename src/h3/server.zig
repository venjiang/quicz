//! HTTP/3 server handler (RFC 9114 §4-6).
//!
//! Processes incoming H3 requests over QUIC streams and sends responses.
//! Works with any QUIC Connection that provides stream I/O.

const std = @import("std");
const h3_frame = @import("frame.zig");
const h3_request = @import("request.zig");
const h3_connection = @import("connection.zig");
const qpack = @import("qpack.zig");
const buffer = @import("../quic/buffer.zig");

/// H3 server request handler callback.
/// Receives a decoded request, returns a response to send.
pub const RequestHandler = *const fn (req: h3_request.DecodedRequest) h3_request.Response;

/// HTTP/3 server state machine over a QUIC connection.
pub const H3Server = struct {
    conn: *H3ServerConnection,
    handler: RequestHandler,
    control_stream_id: ?u64 = null,
    settings_sent: bool = false,
    goaway_sent: bool = false,
    goaway_last_stream_id: ?u64 = null,

    pub const H3ServerConnection = struct {
        /// Open a locally-initiated unidirectional stream.
        openUniStreamFn: *const fn (ctx: *anyopaque) anyerror!u64,
        /// Send data on a stream.
        sendOnStreamFn: *const fn (ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) anyerror!void,
        /// Receive data from a stream. Returns null if no data available.
        recvOnStreamFn: *const fn (ctx: *anyopaque, stream_id: u64, buf: []u8) anyerror!?usize,
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
    };

    /// Initialize the server and send SETTINGS on the control stream.
    pub fn init(conn: *H3ServerConnection, handler: RequestHandler) !H3Server {
        var server = H3Server{
            .conn = conn,
            .handler = handler,
        };
        try server.sendSettings();
        return server;
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

        // SETTINGS frame with max_field_section_size=8192
        var settings_payload: [16]u8 = undefined;
        const sp_len = try h3_connection.H3Connection.encodeSettings(&settings_payload, 8192);

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
    /// Reads the request, calls the handler, and sends the response.
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

        // Decode request
        const decoded = try h3_request.decodeRequest(req_buf[0..total_read]);

        // Call handler
        const response = self.handler(decoded.request);

        // Encode and send response
        var resp_buf: [8192]u8 = undefined;
        const resp_len = try h3_request.encodeResponse(&resp_buf, response);
        try self.conn.sendOnStream(stream_id, resp_buf[0..resp_len], true);
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

    const server = try H3Server.init(&conn, handler);
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

    var server = try H3Server.init(&conn, handler);
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

    var server = try H3Server.init(&conn, handler);
    try std.testing.expect(!server.goaway_sent);

    try server.sendGoaway(4);
    try std.testing.expect(server.goaway_sent);
    try std.testing.expectEqual(@as(?u64, 4), server.goaway_last_stream_id);
}
