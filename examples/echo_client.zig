const std = @import("std");

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    _ = gpa; // reserved for future quicz integration

    const stdout = std.fs.File.stdout();

    // Prepare destination address (server)
    const server_addr = try std.net.Address.parseIp4("127.0.0.1", 4443);

    // Create UDP socket using Zig 0.15.2 std.net API (no DatagramSocket helper in 0.15.2)
    const sockfd = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.UDP);
    defer std.posix.close(sockfd);

    try std.posix.connect(sockfd, &server_addr.any, server_addr.getOsSockLen());

    const msg = "hello from quicz client";
    _ = try std.posix.send(sockfd, msg, 0);
    try stdout.writeAll("[client] sent: ");
    try stdout.writeAll(msg);
    try stdout.writeAll("\n");

    var buf: [1024]u8 = undefined;
    const recv_len = try std.posix.recv(sockfd, &buf, 0);
    const echo = buf[0..recv_len];
    try stdout.writeAll("[client] received echo: ");
    try stdout.writeAll(echo);
    try stdout.writeAll("\n");
}
