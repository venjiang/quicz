//! Huffman coding for HTTP/2/3 header compression (RFC 7541 Appendix B /
//! RFC 9204 §3.2).
//!
//! QPACK and HPACK share the same Huffman code. Decoders MUST support
//! Huffman-encoded strings; most interop peers (quic-go, quiche, nghttp3)
//! emit H=1 literals, so a QPACK implementation without a Huffman decoder
//! cannot interoperate. This module implements the RFC 7541 Appendix B
//! code via a comptime-built binary trie. The 257-entry code table below
//! is the normative RFC data (symbols 0-255 plus EOS=256).

const std = @import("std");

pub const DecodeError = error{
    /// Bits do not form a valid Huffman code.
    InvalidHuffmanEncoding,
    /// Output buffer is too small for the decoded bytes.
    OutputBufferTooSmall,
    /// The EOS symbol (0x3ffffffe/30-bit) appeared in the encoded data.
    EosSymbolDecoded,
    /// Trailing padding is not all 1s or exceeds 7 bits.
    InvalidPadding,
};

/// One entry in the RFC 7541 Appendix B Huffman code table.
const HuffmanEntry = struct {
    symbol: u16, // 0-255 for bytes, 256 for EOS
    code: u32,
    bit_len: u8,
};

/// RFC 7541 Appendix B Huffman code table (normative data).
const huffman_table = [_]HuffmanEntry{
    .{ .symbol = 0, .code = 0x1ff8, .bit_len = 13 },
    .{ .symbol = 1, .code = 0x7fffd8, .bit_len = 23 },
    .{ .symbol = 2, .code = 0xfffffe2, .bit_len = 28 },
    .{ .symbol = 3, .code = 0xfffffe3, .bit_len = 28 },
    .{ .symbol = 4, .code = 0xfffffe4, .bit_len = 28 },
    .{ .symbol = 5, .code = 0xfffffe5, .bit_len = 28 },
    .{ .symbol = 6, .code = 0xfffffe6, .bit_len = 28 },
    .{ .symbol = 7, .code = 0xfffffe7, .bit_len = 28 },
    .{ .symbol = 8, .code = 0xfffffe8, .bit_len = 28 },
    .{ .symbol = 9, .code = 0xffffea, .bit_len = 24 },
    .{ .symbol = 10, .code = 0x3ffffffc, .bit_len = 30 },
    .{ .symbol = 11, .code = 0xfffffe9, .bit_len = 28 },
    .{ .symbol = 12, .code = 0xfffffea, .bit_len = 28 },
    .{ .symbol = 13, .code = 0x3ffffffd, .bit_len = 30 },
    .{ .symbol = 14, .code = 0xfffffeb, .bit_len = 28 },
    .{ .symbol = 15, .code = 0xfffffec, .bit_len = 28 },
    .{ .symbol = 16, .code = 0xfffffed, .bit_len = 28 },
    .{ .symbol = 17, .code = 0xfffffee, .bit_len = 28 },
    .{ .symbol = 18, .code = 0xfffffef, .bit_len = 28 },
    .{ .symbol = 19, .code = 0xffffff0, .bit_len = 28 },
    .{ .symbol = 20, .code = 0xffffff1, .bit_len = 28 },
    .{ .symbol = 21, .code = 0xffffff2, .bit_len = 28 },
    .{ .symbol = 22, .code = 0x3ffffffe, .bit_len = 30 },
    .{ .symbol = 23, .code = 0xffffff3, .bit_len = 28 },
    .{ .symbol = 24, .code = 0xffffff4, .bit_len = 28 },
    .{ .symbol = 25, .code = 0xffffff5, .bit_len = 28 },
    .{ .symbol = 26, .code = 0xffffff6, .bit_len = 28 },
    .{ .symbol = 27, .code = 0xffffff7, .bit_len = 28 },
    .{ .symbol = 28, .code = 0xffffff8, .bit_len = 28 },
    .{ .symbol = 29, .code = 0xffffff9, .bit_len = 28 },
    .{ .symbol = 30, .code = 0xffffffa, .bit_len = 28 },
    .{ .symbol = 31, .code = 0xffffffb, .bit_len = 28 },
    .{ .symbol = 32, .code = 0x14, .bit_len = 6 },
    .{ .symbol = 33, .code = 0x3f8, .bit_len = 10 },
    .{ .symbol = 34, .code = 0x3f9, .bit_len = 10 },
    .{ .symbol = 35, .code = 0xffa, .bit_len = 12 },
    .{ .symbol = 36, .code = 0x1ff9, .bit_len = 13 },
    .{ .symbol = 37, .code = 0x15, .bit_len = 6 },
    .{ .symbol = 38, .code = 0xf8, .bit_len = 8 },
    .{ .symbol = 39, .code = 0x7fa, .bit_len = 11 },
    .{ .symbol = 40, .code = 0x3fa, .bit_len = 10 },
    .{ .symbol = 41, .code = 0x3fb, .bit_len = 10 },
    .{ .symbol = 42, .code = 0xf9, .bit_len = 8 },
    .{ .symbol = 43, .code = 0x7fb, .bit_len = 11 },
    .{ .symbol = 44, .code = 0xfa, .bit_len = 8 },
    .{ .symbol = 45, .code = 0x16, .bit_len = 6 },
    .{ .symbol = 46, .code = 0x17, .bit_len = 6 },
    .{ .symbol = 47, .code = 0x18, .bit_len = 6 },
    .{ .symbol = 48, .code = 0x0, .bit_len = 5 },
    .{ .symbol = 49, .code = 0x1, .bit_len = 5 },
    .{ .symbol = 50, .code = 0x2, .bit_len = 5 },
    .{ .symbol = 51, .code = 0x19, .bit_len = 6 },
    .{ .symbol = 52, .code = 0x1a, .bit_len = 6 },
    .{ .symbol = 53, .code = 0x1b, .bit_len = 6 },
    .{ .symbol = 54, .code = 0x1c, .bit_len = 6 },
    .{ .symbol = 55, .code = 0x1d, .bit_len = 6 },
    .{ .symbol = 56, .code = 0x1e, .bit_len = 6 },
    .{ .symbol = 57, .code = 0x1f, .bit_len = 6 },
    .{ .symbol = 58, .code = 0x5c, .bit_len = 7 },
    .{ .symbol = 59, .code = 0xfb, .bit_len = 8 },
    .{ .symbol = 60, .code = 0x7ffc, .bit_len = 15 },
    .{ .symbol = 61, .code = 0x20, .bit_len = 6 },
    .{ .symbol = 62, .code = 0xffb, .bit_len = 12 },
    .{ .symbol = 63, .code = 0x3fc, .bit_len = 10 },
    .{ .symbol = 64, .code = 0x1ffa, .bit_len = 13 },
    .{ .symbol = 65, .code = 0x21, .bit_len = 6 },
    .{ .symbol = 66, .code = 0x5d, .bit_len = 7 },
    .{ .symbol = 67, .code = 0x5e, .bit_len = 7 },
    .{ .symbol = 68, .code = 0x5f, .bit_len = 7 },
    .{ .symbol = 69, .code = 0x60, .bit_len = 7 },
    .{ .symbol = 70, .code = 0x61, .bit_len = 7 },
    .{ .symbol = 71, .code = 0x62, .bit_len = 7 },
    .{ .symbol = 72, .code = 0x63, .bit_len = 7 },
    .{ .symbol = 73, .code = 0x64, .bit_len = 7 },
    .{ .symbol = 74, .code = 0x65, .bit_len = 7 },
    .{ .symbol = 75, .code = 0x66, .bit_len = 7 },
    .{ .symbol = 76, .code = 0x67, .bit_len = 7 },
    .{ .symbol = 77, .code = 0x68, .bit_len = 7 },
    .{ .symbol = 78, .code = 0x69, .bit_len = 7 },
    .{ .symbol = 79, .code = 0x6a, .bit_len = 7 },
    .{ .symbol = 80, .code = 0x6b, .bit_len = 7 },
    .{ .symbol = 81, .code = 0x6c, .bit_len = 7 },
    .{ .symbol = 82, .code = 0x6d, .bit_len = 7 },
    .{ .symbol = 83, .code = 0x6e, .bit_len = 7 },
    .{ .symbol = 84, .code = 0x6f, .bit_len = 7 },
    .{ .symbol = 85, .code = 0x70, .bit_len = 7 },
    .{ .symbol = 86, .code = 0x71, .bit_len = 7 },
    .{ .symbol = 87, .code = 0x72, .bit_len = 7 },
    .{ .symbol = 88, .code = 0xfc, .bit_len = 8 },
    .{ .symbol = 89, .code = 0x73, .bit_len = 7 },
    .{ .symbol = 90, .code = 0xfd, .bit_len = 8 },
    .{ .symbol = 91, .code = 0x1ffb, .bit_len = 13 },
    .{ .symbol = 92, .code = 0x7fff0, .bit_len = 19 },
    .{ .symbol = 93, .code = 0x1ffc, .bit_len = 13 },
    .{ .symbol = 94, .code = 0x3ffc, .bit_len = 14 },
    .{ .symbol = 95, .code = 0x22, .bit_len = 6 },
    .{ .symbol = 96, .code = 0x7ffd, .bit_len = 15 },
    .{ .symbol = 97, .code = 0x3, .bit_len = 5 },
    .{ .symbol = 98, .code = 0x23, .bit_len = 6 },
    .{ .symbol = 99, .code = 0x4, .bit_len = 5 },
    .{ .symbol = 100, .code = 0x24, .bit_len = 6 },
    .{ .symbol = 101, .code = 0x5, .bit_len = 5 },
    .{ .symbol = 102, .code = 0x25, .bit_len = 6 },
    .{ .symbol = 103, .code = 0x26, .bit_len = 6 },
    .{ .symbol = 104, .code = 0x27, .bit_len = 6 },
    .{ .symbol = 105, .code = 0x6, .bit_len = 5 },
    .{ .symbol = 106, .code = 0x74, .bit_len = 7 },
    .{ .symbol = 107, .code = 0x75, .bit_len = 7 },
    .{ .symbol = 108, .code = 0x28, .bit_len = 6 },
    .{ .symbol = 109, .code = 0x29, .bit_len = 6 },
    .{ .symbol = 110, .code = 0x2a, .bit_len = 6 },
    .{ .symbol = 111, .code = 0x7, .bit_len = 5 },
    .{ .symbol = 112, .code = 0x2b, .bit_len = 6 },
    .{ .symbol = 113, .code = 0x76, .bit_len = 7 },
    .{ .symbol = 114, .code = 0x2c, .bit_len = 6 },
    .{ .symbol = 115, .code = 0x8, .bit_len = 5 },
    .{ .symbol = 116, .code = 0x9, .bit_len = 5 },
    .{ .symbol = 117, .code = 0x2d, .bit_len = 6 },
    .{ .symbol = 118, .code = 0x77, .bit_len = 7 },
    .{ .symbol = 119, .code = 0x78, .bit_len = 7 },
    .{ .symbol = 120, .code = 0x79, .bit_len = 7 },
    .{ .symbol = 121, .code = 0x7a, .bit_len = 7 },
    .{ .symbol = 122, .code = 0x7b, .bit_len = 7 },
    .{ .symbol = 123, .code = 0x7ffe, .bit_len = 15 },
    .{ .symbol = 124, .code = 0x7fc, .bit_len = 11 },
    .{ .symbol = 125, .code = 0x3ffd, .bit_len = 14 },
    .{ .symbol = 126, .code = 0x1ffd, .bit_len = 13 },
    .{ .symbol = 127, .code = 0xffffffc, .bit_len = 28 },
    .{ .symbol = 128, .code = 0xfffe6, .bit_len = 20 },
    .{ .symbol = 129, .code = 0x3fffd2, .bit_len = 22 },
    .{ .symbol = 130, .code = 0xfffe7, .bit_len = 20 },
    .{ .symbol = 131, .code = 0xfffe8, .bit_len = 20 },
    .{ .symbol = 132, .code = 0x3fffd3, .bit_len = 22 },
    .{ .symbol = 133, .code = 0x3fffd4, .bit_len = 22 },
    .{ .symbol = 134, .code = 0x3fffd5, .bit_len = 22 },
    .{ .symbol = 135, .code = 0x7fffd9, .bit_len = 23 },
    .{ .symbol = 136, .code = 0x3fffd6, .bit_len = 22 },
    .{ .symbol = 137, .code = 0x7fffda, .bit_len = 23 },
    .{ .symbol = 138, .code = 0x7fffdb, .bit_len = 23 },
    .{ .symbol = 139, .code = 0x7fffdc, .bit_len = 23 },
    .{ .symbol = 140, .code = 0x7fffdd, .bit_len = 23 },
    .{ .symbol = 141, .code = 0x7fffde, .bit_len = 23 },
    .{ .symbol = 142, .code = 0xffffeb, .bit_len = 24 },
    .{ .symbol = 143, .code = 0x7fffdf, .bit_len = 23 },
    .{ .symbol = 144, .code = 0xffffec, .bit_len = 24 },
    .{ .symbol = 145, .code = 0xffffed, .bit_len = 24 },
    .{ .symbol = 146, .code = 0x3fffd7, .bit_len = 22 },
    .{ .symbol = 147, .code = 0x7fffe0, .bit_len = 23 },
    .{ .symbol = 148, .code = 0xffffee, .bit_len = 24 },
    .{ .symbol = 149, .code = 0x7fffe1, .bit_len = 23 },
    .{ .symbol = 150, .code = 0x7fffe2, .bit_len = 23 },
    .{ .symbol = 151, .code = 0x7fffe3, .bit_len = 23 },
    .{ .symbol = 152, .code = 0x7fffe4, .bit_len = 23 },
    .{ .symbol = 153, .code = 0x1fffdc, .bit_len = 21 },
    .{ .symbol = 154, .code = 0x3fffd8, .bit_len = 22 },
    .{ .symbol = 155, .code = 0x7fffe5, .bit_len = 23 },
    .{ .symbol = 156, .code = 0x3fffd9, .bit_len = 22 },
    .{ .symbol = 157, .code = 0x7fffe6, .bit_len = 23 },
    .{ .symbol = 158, .code = 0x7fffe7, .bit_len = 23 },
    .{ .symbol = 159, .code = 0xffffef, .bit_len = 24 },
    .{ .symbol = 160, .code = 0x3fffda, .bit_len = 22 },
    .{ .symbol = 161, .code = 0x1fffdd, .bit_len = 21 },
    .{ .symbol = 162, .code = 0xfffe9, .bit_len = 20 },
    .{ .symbol = 163, .code = 0x3fffdb, .bit_len = 22 },
    .{ .symbol = 164, .code = 0x3fffdc, .bit_len = 22 },
    .{ .symbol = 165, .code = 0x7fffe8, .bit_len = 23 },
    .{ .symbol = 166, .code = 0x7fffe9, .bit_len = 23 },
    .{ .symbol = 167, .code = 0x1fffde, .bit_len = 21 },
    .{ .symbol = 168, .code = 0x7fffea, .bit_len = 23 },
    .{ .symbol = 169, .code = 0x3fffdd, .bit_len = 22 },
    .{ .symbol = 170, .code = 0x3fffde, .bit_len = 22 },
    .{ .symbol = 171, .code = 0xfffff0, .bit_len = 24 },
    .{ .symbol = 172, .code = 0x1fffdf, .bit_len = 21 },
    .{ .symbol = 173, .code = 0x3fffdf, .bit_len = 22 },
    .{ .symbol = 174, .code = 0x7fffeb, .bit_len = 23 },
    .{ .symbol = 175, .code = 0x7fffec, .bit_len = 23 },
    .{ .symbol = 176, .code = 0x1fffe0, .bit_len = 21 },
    .{ .symbol = 177, .code = 0x1fffe1, .bit_len = 21 },
    .{ .symbol = 178, .code = 0x3fffe0, .bit_len = 22 },
    .{ .symbol = 179, .code = 0x1fffe2, .bit_len = 21 },
    .{ .symbol = 180, .code = 0x7fffed, .bit_len = 23 },
    .{ .symbol = 181, .code = 0x3fffe1, .bit_len = 22 },
    .{ .symbol = 182, .code = 0x7fffee, .bit_len = 23 },
    .{ .symbol = 183, .code = 0x7fffef, .bit_len = 23 },
    .{ .symbol = 184, .code = 0xfffea, .bit_len = 20 },
    .{ .symbol = 185, .code = 0x3fffe2, .bit_len = 22 },
    .{ .symbol = 186, .code = 0x3fffe3, .bit_len = 22 },
    .{ .symbol = 187, .code = 0x3fffe4, .bit_len = 22 },
    .{ .symbol = 188, .code = 0x7ffff0, .bit_len = 23 },
    .{ .symbol = 189, .code = 0x3fffe5, .bit_len = 22 },
    .{ .symbol = 190, .code = 0x3fffe6, .bit_len = 22 },
    .{ .symbol = 191, .code = 0x7ffff1, .bit_len = 23 },
    .{ .symbol = 192, .code = 0x3ffffe0, .bit_len = 26 },
    .{ .symbol = 193, .code = 0x3ffffe1, .bit_len = 26 },
    .{ .symbol = 194, .code = 0xfffeb, .bit_len = 20 },
    .{ .symbol = 195, .code = 0x7fff1, .bit_len = 19 },
    .{ .symbol = 196, .code = 0x3fffe7, .bit_len = 22 },
    .{ .symbol = 197, .code = 0x7ffff2, .bit_len = 23 },
    .{ .symbol = 198, .code = 0x3fffe8, .bit_len = 22 },
    .{ .symbol = 199, .code = 0x1ffffec, .bit_len = 25 },
    .{ .symbol = 200, .code = 0x3ffffe2, .bit_len = 26 },
    .{ .symbol = 201, .code = 0x3ffffe3, .bit_len = 26 },
    .{ .symbol = 202, .code = 0x3ffffe4, .bit_len = 26 },
    .{ .symbol = 203, .code = 0x7ffffde, .bit_len = 27 },
    .{ .symbol = 204, .code = 0x7ffffdf, .bit_len = 27 },
    .{ .symbol = 205, .code = 0x3ffffe5, .bit_len = 26 },
    .{ .symbol = 206, .code = 0xfffff1, .bit_len = 24 },
    .{ .symbol = 207, .code = 0x1ffffed, .bit_len = 25 },
    .{ .symbol = 208, .code = 0x7fff2, .bit_len = 19 },
    .{ .symbol = 209, .code = 0x1fffe3, .bit_len = 21 },
    .{ .symbol = 210, .code = 0x3ffffe6, .bit_len = 26 },
    .{ .symbol = 211, .code = 0x7ffffe0, .bit_len = 27 },
    .{ .symbol = 212, .code = 0x7ffffe1, .bit_len = 27 },
    .{ .symbol = 213, .code = 0x3ffffe7, .bit_len = 26 },
    .{ .symbol = 214, .code = 0x7ffffe2, .bit_len = 27 },
    .{ .symbol = 215, .code = 0xfffff2, .bit_len = 24 },
    .{ .symbol = 216, .code = 0x1fffe4, .bit_len = 21 },
    .{ .symbol = 217, .code = 0x1fffe5, .bit_len = 21 },
    .{ .symbol = 218, .code = 0x3ffffe8, .bit_len = 26 },
    .{ .symbol = 219, .code = 0x3ffffe9, .bit_len = 26 },
    .{ .symbol = 220, .code = 0xffffffd, .bit_len = 28 },
    .{ .symbol = 221, .code = 0x7ffffe3, .bit_len = 27 },
    .{ .symbol = 222, .code = 0x7ffffe4, .bit_len = 27 },
    .{ .symbol = 223, .code = 0x7ffffe5, .bit_len = 27 },
    .{ .symbol = 224, .code = 0xfffec, .bit_len = 20 },
    .{ .symbol = 225, .code = 0xfffff3, .bit_len = 24 },
    .{ .symbol = 226, .code = 0xfffed, .bit_len = 20 },
    .{ .symbol = 227, .code = 0x1fffe6, .bit_len = 21 },
    .{ .symbol = 228, .code = 0x3fffe9, .bit_len = 22 },
    .{ .symbol = 229, .code = 0x1fffe7, .bit_len = 21 },
    .{ .symbol = 230, .code = 0x1fffe8, .bit_len = 21 },
    .{ .symbol = 231, .code = 0x7ffff3, .bit_len = 23 },
    .{ .symbol = 232, .code = 0x3fffea, .bit_len = 22 },
    .{ .symbol = 233, .code = 0x3fffeb, .bit_len = 22 },
    .{ .symbol = 234, .code = 0x1ffffee, .bit_len = 25 },
    .{ .symbol = 235, .code = 0x1ffffef, .bit_len = 25 },
    .{ .symbol = 236, .code = 0xfffff4, .bit_len = 24 },
    .{ .symbol = 237, .code = 0xfffff5, .bit_len = 24 },
    .{ .symbol = 238, .code = 0x3ffffea, .bit_len = 26 },
    .{ .symbol = 239, .code = 0x7ffff4, .bit_len = 23 },
    .{ .symbol = 240, .code = 0x3ffffeb, .bit_len = 26 },
    .{ .symbol = 241, .code = 0x7ffffe6, .bit_len = 27 },
    .{ .symbol = 242, .code = 0x3ffffec, .bit_len = 26 },
    .{ .symbol = 243, .code = 0x3ffffed, .bit_len = 26 },
    .{ .symbol = 244, .code = 0x7ffffe7, .bit_len = 27 },
    .{ .symbol = 245, .code = 0x7ffffe8, .bit_len = 27 },
    .{ .symbol = 246, .code = 0x7ffffe9, .bit_len = 27 },
    .{ .symbol = 247, .code = 0x7ffffea, .bit_len = 27 },
    .{ .symbol = 248, .code = 0x7ffffeb, .bit_len = 27 },
    .{ .symbol = 249, .code = 0xffffffe, .bit_len = 28 },
    .{ .symbol = 250, .code = 0x7ffffec, .bit_len = 27 },
    .{ .symbol = 251, .code = 0x7ffffed, .bit_len = 27 },
    .{ .symbol = 252, .code = 0x7ffffee, .bit_len = 27 },
    .{ .symbol = 253, .code = 0x7ffffef, .bit_len = 27 },
    .{ .symbol = 254, .code = 0x7fffff0, .bit_len = 27 },
    .{ .symbol = 255, .code = 0x3ffffee, .bit_len = 26 },
    .{ .symbol = 256, .code = 0x3fffffff, .bit_len = 30 },
};

const EOS_SYMBOL: u16 = 256;
const MAX_TRIE_NODES = 1024;
const UNALLOCATED: u16 = 0xFFFF;

const TrieNode = struct {
    child_0: u16 = UNALLOCATED,
    child_1: u16 = UNALLOCATED,
    leaf_symbol_0: u16 = 0,
    leaf_symbol_1: u16 = 0,
};

const DecodeTrie = struct {
    nodes: [MAX_TRIE_NODES]TrieNode = @as([MAX_TRIE_NODES]TrieNode, @splat(.{})),
    count: u16 = 1,
};

/// Build the decode trie at comptime from the code table.
fn buildDecodeTrie() DecodeTrie {
    @setEvalBranchQuota(200000);
    var trie = DecodeTrie{};
    for (huffman_table) |entry| {
        var node_idx: u16 = 0;
        var i: u8 = 0;
        while (i < entry.bit_len) : (i += 1) {
            const bit_pos = entry.bit_len - 1 - i;
            const bit: u1 = @intCast((entry.code >> @intCast(bit_pos)) & 1);
            const is_last = i == entry.bit_len - 1;
            if (is_last) {
                if (bit == 0) {
                    trie.nodes[node_idx].leaf_symbol_0 = entry.symbol;
                } else {
                    trie.nodes[node_idx].leaf_symbol_1 = entry.symbol;
                }
            } else {
                const child_ptr = if (bit == 0) &trie.nodes[node_idx].child_0 else &trie.nodes[node_idx].child_1;
                if (child_ptr.* == UNALLOCATED) {
                    child_ptr.* = trie.count;
                    trie.count += 1;
                }
                node_idx = child_ptr.*;
            }
        }
    }
    return trie;
}

const decode_trie = buildDecodeTrie();

/// Decode a Huffman-encoded byte slice per RFC 7541 Section 5.2.
/// Writes decoded bytes to `out_buf` and returns the number written.
pub fn decode(encoded: []const u8, out_buf: []u8) DecodeError!usize {
    var out_pos: usize = 0;
    var node_idx: u16 = 0;
    var bits_in_code: u8 = 0;

    for (encoded) |byte| {
        var bit_idx: u4 = 8;
        while (bit_idx > 0) {
            bit_idx -= 1;
            const bit: u1 = @intCast((byte >> @as(u3, @intCast(bit_idx))) & 1);
            bits_in_code += 1;

            const is_leaf = if (bit == 0) decodeTrieIsLeafZero(node_idx) else decodeTrieIsLeafOne(node_idx);
            if (is_leaf) {
                const sym: u16 = if (bit == 0) decode_trie.nodes[node_idx].leaf_symbol_0 else decode_trie.nodes[node_idx].leaf_symbol_1;
                if (sym == EOS_SYMBOL) return DecodeError.EosSymbolDecoded;
                if (out_pos >= out_buf.len) return DecodeError.OutputBufferTooSmall;
                out_buf[out_pos] = @truncate(sym);
                out_pos += 1;
                node_idx = 0;
                bits_in_code = 0;
            } else {
                const child = if (bit == 0) decode_trie.nodes[node_idx].child_0 else decode_trie.nodes[node_idx].child_1;
                if (child == UNALLOCATED) return DecodeError.InvalidHuffmanEncoding;
                node_idx = child;
            }
        }
    }

    // Trailing padding: at most 7 bits, all 1s (the MSBs of the EOS code).
    if (node_idx != 0) {
        if (bits_in_code > 7) return DecodeError.InvalidPadding;
        var check_idx: u16 = 0;
        var i: u8 = 0;
        while (i < bits_in_code) : (i += 1) {
            if (decodeTrieIsLeafOne(check_idx)) return DecodeError.InvalidPadding;
            const child = decode_trie.nodes[check_idx].child_1;
            if (child == UNALLOCATED) return DecodeError.InvalidPadding;
            check_idx = child;
        }
        if (check_idx != node_idx) return DecodeError.InvalidPadding;
    }

    return out_pos;
}

inline fn decodeTrieIsLeafZero(idx: u16) bool {
    return decode_trie.nodes[idx].leaf_symbol_0 != 0 or decode_trie.nodes[idx].child_0 == UNALLOCATED;
}
inline fn decodeTrieIsLeafOne(idx: u16) bool {
    return decode_trie.nodes[idx].leaf_symbol_1 != 0 or decode_trie.nodes[idx].child_1 == UNALLOCATED;
}

test "RFC 7541 Appendix C.1 example" {
    // "www.example.com" Huffman-encoded.
    const encoded = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    var out: [64]u8 = undefined;
    const n = try decode(&encoded, &out);
    try std.testing.expectEqualStrings("www.example.com", out[0..n]);
}

test "EOS symbol rejected" {
    // EOS code is 0x3ffffffe (30 bits). Feed a long run of 1s then a 0 which
    // forms the EOS code prefix.
    const encoded = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe };
    var out: [64]u8 = undefined;
    try std.testing.expectError(error.EosSymbolDecoded, decode(&encoded, &out));
}

test "invalid Huffman rejected" {
    // 0xff 0xff 0xff 0xff 0xff 0xff 0xff 0xfe: 63 ones then a zero. The 63-ones
    // prefix exceeds the longest code (30 bits) and hits an unallocated branch.
    const encoded = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe };
    var out: [64]u8 = undefined;
    _ = decode(&encoded, &out) catch |err| switch (err) {
        error.InvalidHuffmanEncoding, error.EosSymbolDecoded, error.InvalidPadding => return,
        else => return err,
    };
    return error.TestUnexpectedResult;
}

pub const EncodeError = error{
    OutputBufferTooSmall,
};

/// Huffman-encode `input` per RFC 7541 Section 5.2. Returns the number of
/// encoded bytes written to `out_buf`. Trailing padding uses the most
/// significant bits of the EOS code (all 1s), per RFC 7541.
pub fn encode(input: []const u8, out_buf: []u8) EncodeError!usize {
    var bit_buf: u64 = 0;
    var bit_count: u8 = 0;
    var out_pos: usize = 0;

    for (input) |byte| {
        const entry = huffman_table[byte];
        // MSB-first: append the code's bits after those already buffered.
        bit_buf = (bit_buf << @as(u6, @intCast(entry.bit_len))) | entry.code;
        bit_count += entry.bit_len;
        while (bit_count >= 8) {
            bit_count -= 8;
            if (out_pos >= out_buf.len) return error.OutputBufferTooSmall;
            out_buf[out_pos] = @intCast((bit_buf >> @as(u6, @intCast(bit_count))) & 0xff);
            out_pos += 1;
            // Drop the emitted high bits so bit_buf never grows unbounded.
            bit_buf &= (@as(u64, 1) << @as(u6, @intCast(bit_count))) - 1;
        }
    }

    if (bit_count > 0) {
        if (out_pos >= out_buf.len) return error.OutputBufferTooSmall;
        const pad_len = 8 - bit_count;
        // Pad with the most significant bits of the EOS code (all 1s).
        out_buf[out_pos] = @intCast((bit_buf << @as(u6, @intCast(pad_len))) | ((@as(u64, 1) << @as(u6, @intCast(pad_len))) - 1));
        out_pos += 1;
    }

    return out_pos;
}

test "Huffman encode/decode roundtrip for every byte" {
    var i: u16 = 0;
    while (i < 256) : (i += 1) {
        const input = [_]u8{@intCast(i)};
        var huff: [8]u8 = undefined;
        var out: [8]u8 = undefined;
        const hn = try encode(&input, &huff);
        const dn = try decode(huff[0..hn], &out);
        try std.testing.expectEqual(@as(usize, 1), dn);
        try std.testing.expectEqual(input[0], out[0]);
    }
}

test "RFC 7541 Appendix C.1 encode" {
    const input = "www.example.com";
    var huff: [64]u8 = undefined;
    const hn = try encode(input, &huff);
    // The RFC C.1 example encoding.
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff }, huff[0..hn]);
}
