const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

fn requireError(expected: anyerror, result: anyerror!void) !void {
    result catch |err| {
        if (err == expected) return;
        return err;
    };
    return error.UnexpectedState;
}

fn pollRequired(conn: *quicz.QuicConnection, out: []u8) ![]const u8 {
    return (try conn.pollTx(0, out)) orelse error.UnexpectedState;
}

fn requirePollError(expected: anyerror, result: anyerror!?[]u8) !void {
    _ = result catch |err| {
        if (err == expected) return;
        return err;
    };
    return error.UnexpectedState;
}

fn printConnectionClose(gpa: std.mem.Allocator, payload: []const u8) !void {
    var decoded = try quicz.frame.decodeFrameSlice(payload, gpa);
    defer quicz.frame.deinitFrame(&decoded.frame, gpa);
    if (decoded.len != payload.len) return error.UnexpectedState;

    switch (decoded.frame) {
        .connection_close => |close| {
            std.debug.print(
                "[close] connection close error={} frame_type={} reason={s}\n",
                .{ close.error_code, close.frame_type, close.reason_phrase },
            );
        },
        else => return error.UnexpectedState,
    }
}

fn printApplicationClose(gpa: std.mem.Allocator, payload: []const u8) !void {
    var decoded = try quicz.frame.decodeFrameSlice(payload, gpa);
    defer quicz.frame.deinitFrame(&decoded.frame, gpa);
    if (decoded.len != payload.len) return error.UnexpectedState;

    switch (decoded.frame) {
        .application_close => |close| {
            std.debug.print(
                "[close] application close error={} reason={s}\n",
                .{ close.error_code, close.reason_phrase },
            );
        },
        else => return error.UnexpectedState,
    }
}

fn printPeerClose(prefix: []const u8, close: quicz.PeerClose) void {
    switch (close) {
        .connection => |connection| {
            std.debug.print(
                "[close] {s} peer transport close error={} frame_type={} reason={s}\n",
                .{ prefix, connection.error_code, connection.frame_type, connection.reason_phrase },
            );
        },
        .application => |application| {
            std.debug.print(
                "[close] {s} peer application close error={} reason={s}\n",
                .{ prefix, application.error_code, application.reason_phrase },
            );
        },
    }
}

fn protectedShortCloseExample(gpa: std.mem.Allocator) !void {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try quicz.QuicConnection.init(gpa, .client, .{});
    defer client.deinit();
    var server = try quicz.QuicConnection.init(gpa, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    try client.closeConnection(0, @intFromEnum(quicz.frame.FrameType.stream), "protected done");
    const protected_close = (try client.pollProtectedShortDatagram(0, &server_dcid, secrets.client)) orelse return error.UnexpectedState;
    defer gpa.free(protected_close);
    try server.processProtectedShortDatagram(1, secrets.client, server_dcid.len, protected_close);
    printPeerClose("protected receiver", server.peerClose() orelse return error.UnexpectedState);

    const retransmit = (try client.pollProtectedShortDatagram(2, &server_dcid, secrets.client)) orelse return error.UnexpectedState;
    defer gpa.free(retransmit);

    std.debug.print(
        "[close] protected close bytes={} retransmit={} sender={s} receiver={s}\n",
        .{
            protected_close.len,
            retransmit.len,
            @tagName(client.connectionState()),
            @tagName(server.connectionState()),
        },
    );

    var app_server = try quicz.QuicConnection.init(gpa, .server, .{});
    defer app_server.deinit();
    try app_server.validatePeerAddress();
    var app_client = try quicz.QuicConnection.init(gpa, .client, .{});
    defer app_client.deinit();

    try app_server.closeApplication(42, "protected app done");
    const protected_app_close = (try app_server.pollProtectedShortDatagram(4, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer gpa.free(protected_app_close);
    try app_client.processProtectedShortDatagram(5, secrets.server, client_dcid.len, protected_app_close);
    printPeerClose("protected app receiver", app_client.peerClose() orelse return error.UnexpectedState);
    std.debug.print(
        "[close] protected application close bytes={} receiver={s}\n",
        .{ protected_app_close.len, @tagName(app_client.connectionState()) },
    );
}

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    var client = try quicz.QuicConnection.init(gpa, .client, .{});
    defer client.deinit();
    var server = try quicz.QuicConnection.init(gpa, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    try client.closeConnection(0, @intFromEnum(quicz.frame.FrameType.stream), "done");
    var datagram: [128]u8 = undefined;
    const connection_close = try pollRequired(&client, &datagram);
    try printConnectionClose(gpa, connection_close);
    std.debug.print(
        "[close] sender state={s} deadline_ms={}\n",
        .{ @tagName(client.connectionState()), client.closeDeadlineMillis().? },
    );
    try server.processDatagram(0, connection_close);
    printPeerClose("receiver", server.peerClose() orelse return error.UnexpectedState);
    try requireError(error.ConnectionClosed, server.sendPing());
    std.debug.print(
        "[close] receiver state={s} rejected send after CONNECTION_CLOSE\n",
        .{@tagName(server.connectionState())},
    );

    const retransmitted_close = (try client.pollTx(1, &datagram)) orelse return error.UnexpectedState;
    try printConnectionClose(gpa, retransmitted_close);
    std.debug.print(
        "[close] sender retransmitted close while state={s}\n",
        .{@tagName(client.connectionState())},
    );

    try requirePollError(error.ConnectionClosed, client.pollTx(client.closeDeadlineMillis().?, &datagram));
    std.debug.print("[close] sender expired state={s}\n", .{@tagName(client.connectionState())});

    var app_server = try quicz.QuicConnection.init(gpa, .server, .{});
    defer app_server.deinit();
    try app_server.validatePeerAddress();
    var app_client = try quicz.QuicConnection.init(gpa, .client, .{});
    defer app_client.deinit();

    try app_server.closeApplication(42, "app done");
    const application_close = try pollRequired(&app_server, &datagram);
    try printApplicationClose(gpa, application_close);
    try app_client.processDatagram(0, application_close);
    printPeerClose("application receiver", app_client.peerClose() orelse return error.UnexpectedState);
    try requireError(error.ConnectionClosed, app_client.sendPing());
    std.debug.print("[close] application receiver state={s}\n", .{@tagName(app_client.connectionState())});

    try protectedShortCloseExample(gpa);
}
