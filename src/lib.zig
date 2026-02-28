const std = @import("std");

pub const Error = error{
    ConnectionClosed,
    InvalidPacket,
    CryptoError,
    Internal,
};

pub const Config = struct {
    max_datagram_size: u16 = 1350,
    initial_rtt_ms: u32 = 333,
};

pub const ConnectionSide = enum { client, server };

pub const QuicConnection = struct {
    allocator: std.mem.Allocator,
    config: Config,
    side: ConnectionSide,

    pub fn init(
        allocator: std.mem.Allocator,
        side: ConnectionSide,
        config: Config,
    ) !QuicConnection {
        return QuicConnection{
            .allocator = allocator,
            .config = config,
            .side = side,
        };
    }

    pub fn deinit(self: *QuicConnection) void {
        _ = self;
    }

    pub fn processDatagram(
        self: *QuicConnection,
        now_millis: i64,
        datagram: []const u8,
    ) Error!void {
        _ = self;
        _ = now_millis;
        _ = datagram;
    }

    pub fn pollTx(
        self: *QuicConnection,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        _ = self;
        _ = now_millis;
        _ = out_buf;
        return null;
    }

    pub fn openStream(self: *QuicConnection) Error!u64 {
        _ = self;
        return 0;
    }

    pub fn sendOnStream(
        self: *QuicConnection,
        stream_id: u64,
        data: []const u8,
        fin: bool,
    ) Error!void {
        _ = self;
        _ = stream_id;
        _ = data;
        _ = fin;
    }

    pub fn recvOnStream(
        self: *QuicConnection,
        stream_id: u64,
        buf: []u8,
    ) Error!?usize {
        _ = self;
        _ = stream_id;
        _ = buf;
        return null;
    }
};
