const std = @import("std");
const quicz = @import("quicz");

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &dcid);
    const v2_secrets = try quicz.protection.deriveInitialSecrets(.v2, &dcid);

    const client_key_hex = std.fmt.bytesToHex(secrets.client.key, .lower);
    const client_iv_hex = std.fmt.bytesToHex(secrets.client.iv, .lower);
    const server_key_hex = std.fmt.bytesToHex(secrets.server.key, .lower);
    const server_iv_hex = std.fmt.bytesToHex(secrets.server.iv, .lower);
    const v2_client_key_hex = std.fmt.bytesToHex(v2_secrets.client.key, .lower);
    const v2_client_iv_hex = std.fmt.bytesToHex(v2_secrets.client.iv, .lower);
    const v2_server_key_hex = std.fmt.bytesToHex(v2_secrets.server.key, .lower);
    const v2_server_iv_hex = std.fmt.bytesToHex(v2_secrets.server.iv, .lower);
    const next_client = quicz.protection.nextAes128PacketProtectionKeys(secrets.client);
    const next_client_secret_hex = std.fmt.bytesToHex(next_client.secret, .lower);
    const next_client_key_hex = std.fmt.bytesToHex(next_client.key, .lower);
    const next_client_iv_hex = std.fmt.bytesToHex(next_client.iv, .lower);
    const sample = [_]u8{
        0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8,
        0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b,
    };
    const mask = quicz.protection.aes128HeaderProtectionMask(secrets.client.hp, sample);
    const mask_hex = std.fmt.bytesToHex(mask, .lower);

    var protected_first: u8 = 0xc3;
    var protected_packet_number = [_]u8{ 0x00, 0x00, 0x00, 0x02 };
    try quicz.protection.applyHeaderProtectionMask(.long, &protected_first, &protected_packet_number, mask);
    const protected_packet_number_hex = std.fmt.bytesToHex(protected_packet_number, .lower);

    const server_scid = [_]u8{ 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 };
    const plaintext = "server initial";
    const initial_header = quicz.packet.LongHeader{
        .version = .v1,
        .dcid = &[_]u8{},
        .scid = &server_scid,
        .packet_type = .initial,
        .token = &[_]u8{},
        .packet_number = 1,
        .payload_length = 0,
    };
    const protected_packet = try quicz.protection.protectLongPacketAes128(allocator, initial_header, .{
        .len = 2,
        .truncated_packet_number = 1,
    }, secrets.server, plaintext);
    defer allocator.free(protected_packet);
    var opened_packet = try quicz.protection.unprotectLongPacketAes128(allocator, secrets.server, protected_packet, 0);
    defer quicz.protection.deinitProtectedLongPacket(&opened_packet, allocator);

    std.debug.print("[initial-keys] dcid=8394c8f03e515708 client_key={s} client_iv={s}\n", .{
        &client_key_hex,
        &client_iv_hex,
    });
    std.debug.print("[initial-keys] server_key={s} server_iv={s}\n", .{
        &server_key_hex,
        &server_iv_hex,
    });
    std.debug.print("[initial-keys] v2_client_key={s} v2_client_iv={s}\n", .{
        &v2_client_key_hex,
        &v2_client_iv_hex,
    });
    std.debug.print("[initial-keys] v2_server_key={s} v2_server_iv={s} differs_from_v1={}\n", .{
        &v2_server_key_hex,
        &v2_server_iv_hex,
        !std.mem.eql(u8, &secrets.client.key, &v2_secrets.client.key) and
            !std.mem.eql(u8, &secrets.server.key, &v2_secrets.server.key),
    });
    std.debug.print("[initial-keys] key_update_secret={s} next_key={s} next_iv={s} hp_retained={}\n", .{
        &next_client_secret_hex,
        &next_client_key_hex,
        &next_client_iv_hex,
        std.mem.eql(u8, &secrets.client.hp, &next_client.hp),
    });
    std.debug.print("[initial-keys] client_hp_mask={s} protected_first=0x{x} protected_pn={s}\n", .{
        &mask_hex,
        protected_first,
        &protected_packet_number_hex,
    });
    std.debug.print("[initial-keys] protected_initial_bytes={} opened={}\n", .{
        protected_packet.len,
        std.mem.eql(u8, plaintext, opened_packet.packet.plaintext),
    });
}
