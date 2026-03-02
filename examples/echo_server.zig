const std = @import("std");

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    _ = gpa; // reserved for future quicz integration

    const stdout = std.fs.File.stdout();

    try stdout.writeAll("quicz UDP echo server listening on 127.0.0.1:4443\n");

    // Bind UDP socket on 127.0.0.1:4443 using Zig 0.15.2 std.net API (posix-level UDP)
    const address = try std.net.Address.parseIp4("127.0.0.1", 4443);
    const sockfd = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.UDP);
    defer std.posix.close(sockfd);

    try std.posix.bind(sockfd, &address.any, address.getOsSockLen());

    var buf: [1024]u8 = undefined;
    while (true) {
        var src_addr: std.net.Address = undefined;
        var src_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
        const recv_len = try std.posix.recvfrom(sockfd, &buf, 0, &src_addr.any, &src_len);
        const msg = buf[0..recv_len];
        try stdout.writeAll("[server] received: ");
        try stdout.writeAll(msg);
        try stdout.writeAll("\n");
        // Echo back to sender
        _ = try std.posix.sendto(sockfd, msg, 0, &src_addr.any, src_len);
    }
}
