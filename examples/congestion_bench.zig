//! Congestion control comparison benchmark.
//!
//! Usage:
//!   zig build run-congestion-bench
//!
//! simulated loopback path with periodic packet loss.  For each algorithm
//! the benchmark:
//!
//!   1. Starts from the RFC 9002 initial congestion window.
//!   2. Simulates ACK-driven window growth (slow start → congestion avoidance).
//!   3. Injects loss events at fixed intervals.
//!   4. Prints the cwnd trajectory and summary statistics.
//!
//! No network I/O — this is a pure state-machine simulation.

const std = @import("std");
const quicz = @import("quicz");

const Recovery = quicz.recovery.Recovery;
const RecoveryConfig = quicz.recovery.Config;

const max_datagram_size: usize = 1200;
const initial_rtt_ns: u32 = 50;

/// Simulation parameters.
const sim_duration_ms: i64 = 10_000;
const ack_interval_ms: i64 = 5; // one ACK batch every 5 ms
const bytes_per_ack: usize = max_datagram_size; // one segment ACKed per batch
const loss_interval_ms: i64 = 1000; // inject loss every 1 s

const AlgoResult = struct {
    name: []const u8,
    peak_cwnd: usize,
    final_cwnd: usize,
    loss_events: usize,
    min_cwnd_after_loss: usize,
};

pub fn main() !void {
    std.debug.print("=== Congestion Control Comparison Benchmark ===\n", .{});
    std.debug.print("Path: RTT={d}ms, MDS={d}B, loss every {d}ms, duration={d}ms\n\n", .{
        initial_rtt_ns,
        max_datagram_size,
        loss_interval_ms,
        sim_duration_ms,
    });

    const algos = [_]struct { name: []const u8, config: RecoveryConfig }{
        .{ .name = "NewReno", .config = .{ .max_datagram_size = @intCast(max_datagram_size), .initial_rtt_ns = initial_rtt_ns, .congestion_algorithm = .new_reno } },
        .{ .name = "CUBIC", .config = .{ .max_datagram_size = @intCast(max_datagram_size), .initial_rtt_ns = initial_rtt_ns, .congestion_algorithm = .cubic } },
    };

    var results: [2]AlgoResult = undefined;

    for (algos, 0..) |entry, idx| {
        results[idx] = runSimulation(entry.name, entry.config) catch |err| {
            std.debug.print("  ERROR: {s}\n", .{@errorName(err)});
            results[idx] = .{ .name = entry.name, .peak_cwnd = 0, .final_cwnd = 0, .loss_events = 0, .min_cwnd_after_loss = 0 };
        };
    }

    // Summary table
    std.debug.print("\n=== Summary ===\n", .{});
    std.debug.print("{s:<10} {s:>12} {s:>12} {s:>6} {s:>14}\n", .{
        "Algorithm",
        "Peak cwnd",
        "Final cwnd",
        "Losses",
        "Min after loss",
    });
    std.debug.print("{s}\n", .{@as([58]u8, @splat('-'))});
    for (results) |r| {
        std.debug.print("{s:<10} {d:>10} B {d:>10} B {d:>6} {d:>12} B\n", .{
            r.name,
            r.peak_cwnd,
            r.final_cwnd,
            r.loss_events,
            r.min_cwnd_after_loss,
        });
    }
    std.debug.print("\nDone.\n", .{});
}

fn runSimulation(
    name: []const u8,
    config: RecoveryConfig,
) !AlgoResult {
    std.debug.print("[{s}]\n", .{name});

    var recovery = Recovery.init(config);
    const initial_cwnd = recovery.congestion_window;
    std.debug.print("  Initial cwnd: {d} B ({d} segments)\n", .{
        initial_cwnd,
        initial_cwnd / max_datagram_size,
    });

    var peak_cwnd: usize = initial_cwnd;
    var loss_events: usize = 0;
    var min_cwnd_after_loss: usize = std.math.maxInt(usize);
    var next_loss_ms: i64 = loss_interval_ms;
    var now_ms: i64 = 0;
    const print_interval_ms: i64 = 500;
    var next_print_ms: i64 = print_interval_ms;

    std.debug.print("  {s:>8} {s:>12} {s:>10} {s}\n", .{ "t(ms)", "cwnd(B)", "segs", "event" });

    while (now_ms < sim_duration_ms) {
        // Simulate sending a batch of packets up to available window.
        const available = recovery.availableCongestionWindow();
        const send_bytes = @min(available, bytes_per_ack);
        if (send_bytes > 0) {
            recovery.onPacketSent(send_bytes);
        }

        // Simulate ACK arrival after one RTT.
        const sent_time = now_ms - @as(i64, initial_rtt_ns);
        if (send_bytes > 0) {
            recovery.onPacketAcked(send_bytes, sent_time, initial_rtt_ns, 0);
        }

        // Track peak.
        if (recovery.congestion_window > peak_cwnd) {
            peak_cwnd = recovery.congestion_window;
        }

        // Inject loss event.
        if (now_ms >= next_loss_ms) {
            recovery.onCongestionEvent(sent_time, now_ms);
            loss_events += 1;
            if (recovery.congestion_window < min_cwnd_after_loss) {
                min_cwnd_after_loss = recovery.congestion_window;
            }
            std.debug.print("  {d:>8} {d:>12} {d:>10} LOSS -> cwnd={d}B\n", .{
                now_ms,
                recovery.congestion_window,
                recovery.congestion_window / max_datagram_size,
                recovery.congestion_window,
            });
            next_loss_ms += loss_interval_ms;
        } else if (now_ms >= next_print_ms) {
            std.debug.print("  {d:>8} {d:>12} {d:>10}\n", .{
                now_ms,
                recovery.congestion_window,
                recovery.congestion_window / max_datagram_size,
            });
            next_print_ms += print_interval_ms;
        }

        now_ms += ack_interval_ms;
    }

    const final_cwnd = recovery.congestion_window;
    std.debug.print("  Final cwnd: {d} B ({d} segments), peak: {d} B, losses: {d}\n\n", .{
        final_cwnd,
        final_cwnd / max_datagram_size,
        peak_cwnd,
        loss_events,
    });

    return .{
        .name = name,
        .peak_cwnd = peak_cwnd,
        .final_cwnd = final_cwnd,
        .loss_events = loss_events,
        .min_cwnd_after_loss = if (min_cwnd_after_loss == std.math.maxInt(usize)) 0 else min_cwnd_after_loss,
    };
}
