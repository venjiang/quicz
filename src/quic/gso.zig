//! GSO/GRO — Generic Segmentation/Receive Offload for QUIC (RFC 9000 §14.5).
//!
//! Provides batch UDP send/receive interfaces for high-throughput
//! QUIC implementations. GSO segments large buffers into MTU-sized
//! datagrams; GRO coalesces received datagrams.

const std = @import("std");

/// A batch of UDP datagrams for GSO send or GRO receive.
pub const DatagramBatch = struct {
    /// Datagram payloads.
    datagrams: []const []const u8,
    /// Number of valid datagrams in the batch.
    count: usize,
    /// Destination address (for send) or source address (for receive).
    addr: ?[]const u8 = null,
};

/// GSO segmenter: splits a large buffer into MTU-sized segments.
pub const GsoSegmenter = struct {
    /// Maximum segment size (typically path MTU).
    segment_size: usize,
    /// Whether GSO is supported by the platform.
    supported: bool = false,

    pub fn init(segment_size: usize) GsoSegmenter {
        return .{
            .segment_size = segment_size,
            .supported = detectGsoSupport(),
        };
    }

    /// Calculate the number of segments needed for a buffer.
    pub fn segmentCount(self: *const GsoSegmenter, total_len: usize) usize {
        if (total_len == 0) return 0;
        return (total_len + self.segment_size - 1) / self.segment_size;
    }

    /// Get the i-th segment of a buffer.
    pub fn getSegment(self: *const GsoSegmenter, data: []const u8, index: usize) []const u8 {
        const start = index * self.segment_size;
        if (start >= data.len) return &.{};
        const end = @min(start + self.segment_size, data.len);
        return data[start..end];
    }

    /// Segment a buffer into a caller-provided array of slices.
    pub fn segmentAll(self: *const GsoSegmenter, data: []const u8, out: [][]const u8) usize {
        const count = self.segmentCount(data.len);
        const n = @min(count, out.len);
        for (0..n) |i| {
            out[i] = self.getSegment(data, i);
        }
        return n;
    }
};

/// GRO coalescer: merges received datagrams into larger buffers.
pub const GroCoalescer = struct {
    /// Maximum coalesced buffer size.
    max_buffer_size: usize = 65536,
    /// Whether GRO is supported by the platform.
    supported: bool = false,

    pub fn init() GroCoalescer {
        return .{
            .supported = detectGroSupport(),
        };
    }

    /// Calculate the total size of coalesced datagrams.
    pub fn coalescedSize(datagrams: []const []const u8) usize {
        var total: usize = 0;
        for (datagrams) |dg| {
            total += dg.len;
        }
        return total;
    }

    /// Check if a batch of datagrams can be coalesced.
    pub fn canCoalesce(self: *const GroCoalescer, datagrams: []const []const u8) bool {
        return self.supported and coalescedSize(datagrams) <= self.max_buffer_size;
    }
};

/// Detect GSO support (platform-specific, stubbed).
fn detectGsoSupport() bool {
    // On Linux: check for UDP_SEGMENT socket option
    // On macOS: not supported natively, use manual segmentation
    return false;
}

/// Detect GRO support (platform-specific, stubbed).
fn detectGroSupport() bool {
    // On Linux: check for UDP_GRO socket option
    // On macOS: not supported natively
    return false;
}

test "GsoSegmenter segment count" {
    const seg = GsoSegmenter.init(1200);
    try std.testing.expectEqual(@as(usize, 0), seg.segmentCount(0));
    try std.testing.expectEqual(@as(usize, 1), seg.segmentCount(1));
    try std.testing.expectEqual(@as(usize, 1), seg.segmentCount(1200));
    try std.testing.expectEqual(@as(usize, 2), seg.segmentCount(1201));
    try std.testing.expectEqual(@as(usize, 2), seg.segmentCount(2400));
    try std.testing.expectEqual(@as(usize, 3), seg.segmentCount(2401));
}

test "GsoSegmenter get segment" {
    const seg = GsoSegmenter.init(4);
    const data = "hello world!";

    try std.testing.expectEqualStrings("hell", seg.getSegment(data, 0));
    try std.testing.expectEqualStrings("o wo", seg.getSegment(data, 1));
    try std.testing.expectEqualStrings("rld!", seg.getSegment(data, 2));
    try std.testing.expectEqual(@as(usize, 0), seg.getSegment(data, 3).len);
}

test "GsoSegmenter segment all" {
    const seg = GsoSegmenter.init(5);
    const data = "hello world";
    var out: [4][]const u8 = undefined;
    const n = seg.segmentAll(data, &out);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqualStrings("hello", out[0]);
    try std.testing.expectEqualStrings(" worl", out[1]);
    try std.testing.expectEqualStrings("d", out[2]);
}

test "GroCoalescer coalesced size" {
    const dgs = [_][]const u8{ "hello", " ", "world" };
    try std.testing.expectEqual(@as(usize, 11), GroCoalescer.coalescedSize(&dgs));
}

test "GroCoalescer can coalesce" {
    var gro = GroCoalescer.init();
    gro.supported = true;
    gro.max_buffer_size = 100;

    const small = [_][]const u8{ "hello", "world" };
    try std.testing.expect(gro.canCoalesce(&small));

    gro.max_buffer_size = 5;
    try std.testing.expect(!gro.canCoalesce(&small));
}
