//! 0-RTT session resumption echo demo.
//!
//! Usage:
//!   zig build run-zero-rtt-echo
//!
//! Demonstrates the complete 0-RTT resumption lifecycle using quicz's
//! SessionCache, ResumptionManager, ZeroRttState, and ReplayProtection:
//!
//!   1. First connection: full handshake, server issues a session ticket.
//!   2. Client stores the ticket in SessionCache.
//!   3. Second connection: client offers PSK from the cached ticket,
//!      sends 0-RTT early data before the handshake completes.
//!   4. Server accepts or rejects 0-RTT; client reacts accordingly.
//!   5. ReplayProtection rejects duplicate or out-of-order attempts.
//!
//! This is a self-contained state-machine demo (no network I/O).
//! For a full UDP loopback integration test, see udp_zero_rtt_loopback.zig.

const std = @import("std");
const quicz = @import("quicz");

const ResumptionManager = quicz.zero_rtt.ResumptionManager;
const ReplayProtection = quicz.zero_rtt.ReplayProtection;

const server_id = "echo.example.com:4433";

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    std.debug.print("=== 0-RTT Session Resumption Echo Demo ===\n\n", .{});

    // ---------------------------------------------------------------
    // Phase 1: First connection — full handshake, obtain session ticket
    // ---------------------------------------------------------------
    std.debug.print("[Phase 1] Full handshake (no cached ticket)\n", .{});

    var mgr = ResumptionManager.init(allocator);
    defer mgr.deinit();

    // No ticket yet — resumption attempt returns null.
    const no_psk = mgr.attemptResumption(server_id, 1000);
    std.debug.assert(no_psk == null);
    std.debug.assert(mgr.state == .none);
    std.debug.print("  No cached ticket → state = {s}, PSK = null\n", .{@tagName(mgr.state)});
    std.debug.print("  → Performing full TLS 1.3 handshake...\n", .{});

    // Simulate: handshake completes, server sends NewSessionTicket.
    // In a real connection the ticket arrives via the CRYPTO stream;
    // here we construct it directly.
    const psk_from_handshake = @as([32]u8, @splat(0xDE));
    const ticket_nonce = try allocator.dupe(u8, "nonce-001");
    try mgr.cache.store(.{
        .server_id = try allocator.dupe(u8, server_id),
        .psk = psk_from_handshake,
        .lifetime_sec = 7200,
        .age_add = 0x1234_5678,
        .nonce = ticket_nonce,
        .allows_early_data = true,
        .remembered_max_data = 1_048_576,
        .remembered_max_stream_data = 65536,
        .remembered_max_streams_bidi = 100,
        .remembered_max_streams_uni = 3,
        .created_at_sec = 1000,
    });
    std.debug.print("  Session ticket stored: lifetime=7200s, early_data=true\n", .{});
    std.debug.print("  Cache size: {d}\n\n", .{mgr.cache.count()});

    // ---------------------------------------------------------------
    // Phase 2: Second connection — 0-RTT resumption with early data
    // ---------------------------------------------------------------
    std.debug.print("[Phase 2] Resumed connection (0-RTT)\n", .{});

    // Client attempts resumption 1 second later.
    const resumed_psk = mgr.attemptResumption(server_id, 1001);
    std.debug.assert(resumed_psk != null);
    std.debug.assert(mgr.state == .offered);
    std.debug.assert(mgr.canSendEarlyData());
    std.debug.print("  PSK offered → state = {s}\n", .{@tagName(mgr.state)});

    // Client sends early data immediately (before handshake completes).
    const early_payload = "GET / HTTP/3\r\nHost: echo.example.com\r\n\r\n";
    mgr.markEarlyDataSent();
    std.debug.print("  0-RTT early data sent ({d} bytes): \"{s}\"\n", .{ early_payload.len, early_payload });

    // Server accepts 0-RTT.
    mgr.onServerAccepted();
    std.debug.assert(mgr.state == .accepted);
    std.debug.print("  Server accepted 0-RTT → state = {s}\n", .{@tagName(mgr.state)});
    std.debug.print("  Echo response: \"{s}\"\n\n", .{early_payload});

    // ---------------------------------------------------------------
    // Phase 3: Server rejects 0-RTT (e.g., ticket rotated)
    // ---------------------------------------------------------------
    std.debug.print("[Phase 3] Resumed connection (server rejects 0-RTT)\n", .{});

    // Store a fresh ticket for a different server to demo rejection.
    const reject_server = "strict.example.com:4433";
    const reject_nonce = try allocator.dupe(u8, "nonce-002");
    try mgr.cache.store(.{
        .server_id = try allocator.dupe(u8, reject_server),
        .psk = @as([32]u8, @splat(0xAA)),
        .lifetime_sec = 3600,
        .age_add = 0,
        .nonce = reject_nonce,
        .allows_early_data = true,
        .created_at_sec = 2000,
    });

    _ = mgr.attemptResumption(reject_server, 2001);
    std.debug.print("  PSK offered to {s}\n", .{reject_server});

    mgr.onServerRejected();
    std.debug.assert(mgr.state == .rejected);
    std.debug.assert(!mgr.canSendEarlyData());
    std.debug.print("  Server rejected → state = {s}, falling back to 1-RTT\n\n", .{@tagName(mgr.state)});

    // ---------------------------------------------------------------
    // Phase 4: Ticket without early_data permission
    // ---------------------------------------------------------------
    std.debug.print("[Phase 4] Ticket without early_data permission\n", .{});

    const no_early_server = "noearly.example.com:4433";
    const no_early_nonce = try allocator.dupe(u8, "nonce-003");
    try mgr.cache.store(.{
        .server_id = try allocator.dupe(u8, no_early_server),
        .psk = @as([32]u8, @splat(0xBB)),
        .lifetime_sec = 3600,
        .age_add = 0,
        .nonce = no_early_nonce,
        .allows_early_data = false,
        .created_at_sec = 3000,
    });

    const no_early_psk = mgr.attemptResumption(no_early_server, 3001);
    std.debug.assert(no_early_psk == null);
    std.debug.assert(mgr.state == .none);
    std.debug.print("  Ticket exists but allows_early_data=false → no PSK, state = {s}\n\n", .{@tagName(mgr.state)});

    // ---------------------------------------------------------------
    // Phase 5: Expired ticket
    // ---------------------------------------------------------------
    std.debug.print("[Phase 5] Expired ticket\n", .{});

    // The first ticket (created_at=1000, lifetime=7200) expires at t=8200.
    const expired_psk = mgr.attemptResumption(server_id, 9000);
    std.debug.assert(expired_psk == null);
    std.debug.print("  Ticket expired (created=1000, lifetime=7200, now=9000) → null\n\n", .{});

    // ---------------------------------------------------------------
    // Phase 6: Replay protection
    // ---------------------------------------------------------------
    std.debug.print("[Phase 6] Replay protection\n", .{});

    var replay = ReplayProtection.init(allocator);
    defer replay.deinit();

    const v1 = try replay.validateAttempt("server-A", 5000);
    std.debug.print("  Attempt t=5000 → valid={}\n", .{v1});

    const v2 = try replay.validateAttempt("server-A", 5000);
    std.debug.print("  Attempt t=5000 (replay) → valid={}\n", .{v2});

    const v3 = try replay.validateAttempt("server-A", 4999);
    std.debug.print("  Attempt t=4999 (past) → valid={}\n", .{v3});

    const v4 = try replay.validateAttempt("server-A", 5001);
    std.debug.print("  Attempt t=5001 (future) → valid={}\n", .{v4});

    const v5 = try replay.validateAttempt("server-B", 5000);
    std.debug.print("  Attempt server-B t=5000 (new server) → valid={}\n\n", .{v5});

    // ---------------------------------------------------------------
    // Phase 7: Session cache pruning
    // ---------------------------------------------------------------
    std.debug.print("[Phase 7] Session cache pruning\n", .{});
    std.debug.print("  Cache size before prune: {d}\n", .{mgr.cache.count()});
    mgr.cache.pruneExpired(9000);
    std.debug.print("  Cache size after prune(t=9000): {d}\n\n", .{mgr.cache.count()});

    std.debug.print("=== Demo complete ===\n", .{});
}
