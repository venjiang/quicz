const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{RetryTokenExampleFailed};

const FixedWriter = struct {
    buffer: []u8,
    pos: usize = 0,

    pub fn writer(self: *FixedWriter) *FixedWriter {
        return self;
    }

    pub fn writeByte(self: *FixedWriter, byte: u8) !void {
        if (self.pos >= self.buffer.len) return error.NoSpaceLeft;
        self.buffer[self.pos] = byte;
        self.pos += 1;
    }

    pub fn writeAll(self: *FixedWriter, bytes: []const u8) !void {
        if (self.buffer.len - self.pos < bytes.len) return error.NoSpaceLeft;
        @memcpy(self.buffer[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    pub fn getWritten(self: FixedWriter) []const u8 {
        return self.buffer[0..self.pos];
    }
};

fn fixedWriter(buffer: []u8) FixedWriter {
    return .{ .buffer = buffer };
}

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var server = try quicz.QuicConnection.init(allocator, .server, .{});
    defer server.deinit();

    const retry_token = "retry-token-for-client-address";
    try server.issueRetryToken(retry_token);

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var retry = quicz.packet.RetryPacket{
        .version = .v1,
        .dcid = &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd },
        .scid = &[_]u8{ 0x10, 0x20, 0x30, 0x40 },
        .token = retry_token,
        .integrity_tag = [_]u8{0} ** quicz.protection.aead_tag_len,
    };

    var retry_raw: [128]u8 = undefined;
    var retry_out = fixedWriter(&retry_raw);
    try quicz.packet.encodeRetryPacket(retry_out.writer(), retry);
    retry.integrity_tag = try quicz.protection.retryIntegrityTag(
        allocator,
        &original_dcid,
        retry_out.getWritten()[0 .. retry_out.getWritten().len - quicz.protection.aead_tag_len],
    );

    retry_out = fixedWriter(&retry_raw);
    try quicz.packet.encodeRetryPacket(retry_out.writer(), retry);
    const retry_integrity_valid = try quicz.protection.verifyRetryIntegrityTag(allocator, &original_dcid, retry_out.getWritten());
    if (!retry_integrity_valid) return error.RetryTokenExampleFailed;

    var parsed = try quicz.packet.parseRetryPacket(retry_out.getWritten(), allocator);
    defer quicz.packet.deinitRetryPacket(&parsed, allocator);

    try server.sendPing();
    var tx: [16]u8 = undefined;
    if (try server.pollTx(0, &tx) != null) return error.RetryTokenExampleFailed;

    try server.validateRetryToken(parsed.token);
    const payload = (try server.pollTx(1, &tx)) orelse return error.RetryTokenExampleFailed;
    if (!server.peerAddressValidated() or server.pendingRetryTokenCount() != 0) return error.RetryTokenExampleFailed;

    server.validateRetryToken(parsed.token) catch |err| {
        if (err != error.InvalidPacket) return err;
    };

    std.debug.print(
        "[retry] token_len={} integrity={} address_validated={} ping_bytes={}\n",
        .{ parsed.token.len, retry_integrity_valid, server.peerAddressValidated(), payload.len },
    );
    std.debug.print("[retry] consumed token is not reusable\n", .{});
}
