//! HTTP/3 client handler (RFC 9114 §4-6).
//!
//! Sends H3 requests over QUIC streams and receives responses.
//! Works with any QUIC Connection that provides stream I/O.

const std = @import("std");
const h3_frame = @import("frame.zig");
const h3_request = @import("request.zig");
const h3_connection = @import("connection.zig");
const qpack = @import("qpack.zig");

/// HTTP/3 client state machine over a QUIC connection.
pub const H3Client = struct {
    conn: *H3ClientConnection,
    control_stream_id: ?u64 = null,
    settings_sent: bool = false,
    settings_received: bool = false,
    next_request_stream_id: u64 = 0,
    goaway_received: bool = false,

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
    pub fn init(conn: *H3ClientConnection) !H3Client {
        var client = H3Client{
            .conn = conn,
        };
        try client.sendSettings();
        return client;
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

        // SETTINGS frame
        var settings_payload: [16]u8 = undefined;
        const sp_len = try h3_connection.H3Connection.encodeSettings(&settings_payload, 8192);

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
                const result = h3_request.decodeResponse(resp_buf[0..total_read]) catch continue;
                return result.response;
            }
        }

        if (total_read == 0) return error.NoResponse;

        const result = try h3_request.decodeResponse(resp_buf[0..total_read]);
        return result.response;
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

    const client = try H3Client.init(&conn);
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

    var client = try H3Client.init(&conn);

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
