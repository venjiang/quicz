//! quicz interop server for QUIC-Interop-Runner.
//!
//! Serves files from /www on port 443 using HTTP/0.9 over QUIC.
//! Loads certificates from /certs/priv.key and /certs/cert.pem.
//! Test case controlled by TESTCASE environment variable.

const std = @import("std");

pub fn main() !void {
    const testcase = std.posix.getenv("TESTCASE") orelse "handshake";
    std.debug.print("quicz interop server: testcase={s}\n", .{testcase});

    // TODO: Implement full interop server:
    // 1. Load certificate from /certs/cert.pem and /certs/priv.key
    // 2. Bind UDP socket on port 443
    // 3. Accept QUIC connections
    // 4. Serve files from /www using HTTP/0.9
    // 5. Support test cases: handshake, transfer, retry, resumption, zerortt, http3
    //
    // Reference: quic-go interop server
    // https://github.com/quic-go/quic-go/blob/master/interop/server/main.go

    std.debug.print("quicz interop server: not yet implemented\n", .{});
    return error.NotImplemented;
}
