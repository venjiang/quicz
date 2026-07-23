//! quicz interop client for QUIC-Interop-Runner.
//!
//! Downloads files from URLs in REQUESTS environment variable.
//! Saves downloaded files to /downloads.
//! Test case controlled by TESTCASE environment variable.

const std = @import("std");

pub fn main() !void {
    const testcase = std.posix.getenv("TESTCASE") orelse "handshake";
    const requests = std.posix.getenv("REQUESTS") orelse "";
    std.debug.print("quicz interop client: testcase={s} requests={s}\n", .{ testcase, requests });

    // TODO: Implement full interop client:
    // 1. Parse REQUESTS URLs
    // 2. Establish QUIC connection to server
    // 3. Download files using HTTP/0.9
    // 4. Save files to /downloads
    // 5. Support test cases: handshake, transfer, retry, resumption, zerortt, http3
    // 6. Handle SSLKEYLOGFILE for key logging
    //
    // Reference: quic-go interop client
    // https://github.com/quic-go/quic-go/blob/master/interop/client/main.go

    std.debug.print("quicz interop client: not yet implemented\n", .{});
    return error.NotImplement;
}
