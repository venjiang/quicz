const std = @import("std");
const buffer = @import("buffer.zig");
const packet = @import("packet.zig");
const protocol_limits = @import("protocol_limits.zig");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

const max_connection_id_len = protocol_limits.max_connection_id_len;

/// RFC 9001 QUIC v1 Initial salt.
pub const initial_salt_v1 = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

/// RFC 9369 QUIC v2 Initial salt.
pub const initial_salt_v2 = [_]u8{
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
};

pub const initial_secret_len = HkdfSha256.prk_length;
pub const traffic_secret_len = HkdfSha256.prk_length;
pub const aes_128_key_len = 16;
pub const iv_len = 12;
pub const aes_128_hp_key_len = 16;
pub const aead_tag_len = Aes128Gcm.tag_length;
pub const header_protection_sample_len = 16;
pub const header_protection_mask_len = 5;

/// RFC 9001 fixed key used only for Retry Integrity Tag generation.
pub const retry_integrity_key = [_]u8{
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};

/// RFC 9001 fixed nonce used only for Retry Integrity Tag generation.
pub const retry_integrity_nonce = [_]u8{
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
};

/// RFC 9369 fixed key used only for QUIC v2 Retry Integrity Tag generation.
pub const retry_integrity_key_v2 = [_]u8{
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
    0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
};

/// RFC 9369 fixed nonce used only for QUIC v2 Retry Integrity Tag generation.
pub const retry_integrity_nonce_v2 = [_]u8{
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
};

pub const ProtectionError = error{
    UnsupportedVersion,
    InvalidConnectionIdLength,
    InvalidPacketNumber,
    InvalidPacketNumberLength,
    InvalidPayloadLength,
    AuthenticationFailed,
};

const HkdfLabelSet = struct {
    key: []const u8,
    iv: []const u8,
    hp: []const u8,
    ku: []const u8,
};

const hkdf_labels_v1 = HkdfLabelSet{
    .key = "quic key",
    .iv = "quic iv",
    .hp = "quic hp",
    .ku = "quic ku",
};

const hkdf_labels_v2 = HkdfLabelSet{
    .key = "quicv2 key",
    .iv = "quicv2 iv",
    .hp = "quicv2 hp",
    .ku = "quicv2 ku",
};

const InitialProtectionProfile = struct {
    salt: *const [initial_salt_v1.len]u8,
    labels: HkdfLabelSet,
};

const RetryIntegrityProfile = struct {
    key: [aes_128_key_len]u8,
    nonce: [iv_len]u8,
};

/// Packet protection material derived from one QUIC packet protection secret.
pub const Aes128PacketProtectionKeys = struct {
    /// Packet protection secret for one endpoint direction.
    secret: [traffic_secret_len]u8,
    /// AEAD_AES_128_GCM packet protection key.
    key: [aes_128_key_len]u8,
    /// Per-direction packet protection IV.
    iv: [iv_len]u8,
    /// AES header protection key.
    hp: [aes_128_hp_key_len]u8,
};

/// RFC 9001 Initial packet protection keys for both endpoint directions.
pub const InitialSecrets = struct {
    /// HKDF-Extract output shared by both Initial directions.
    initial_secret: [initial_secret_len]u8,
    /// Keys used by clients to protect Initial packets.
    client: Aes128PacketProtectionKeys,
    /// Keys used by servers to protect Initial packets.
    server: Aes128PacketProtectionKeys,
};

/// Long-header packet opened after QUIC packet protection is removed.
pub const OpenedLongPacket = struct {
    /// Unprotected long-header fields. `payload_length` preserves the protected
    /// wire payload length, including the AEAD authentication tag.
    header: packet.LongHeader,
    /// Decrypted QUIC packet payload bytes.
    plaintext: []const u8,
};

/// Opened long-header packet plus the number of datagram bytes consumed.
pub const DecodedProtectedLongPacket = struct {
    packet: OpenedLongPacket,
    len: usize,
};

/// Short-header packet opened after QUIC packet protection is removed.
pub const OpenedShortPacket = struct {
    /// Unprotected short-header fields reconstructed with connection CID context.
    header: packet.ShortHeader,
    /// Decrypted QUIC packet payload bytes.
    plaintext: []const u8,
};

/// Opened short-header packet plus the number of datagram bytes consumed.
pub const DecodedProtectedShortPacket = struct {
    packet: OpenedShortPacket,
    len: usize,
};

/// Current and next 1-RTT keys used while a QUIC key update is in progress.
pub const ShortPacketKeyUpdateKeys = struct {
    /// Keys for the currently active key phase.
    current: Aes128PacketProtectionKeys,
    /// Keys derived with `nextAes128PacketProtectionKeys(current)`.
    next: Aes128PacketProtectionKeys,
    /// Short-header key phase bit corresponding to `current`.
    current_key_phase: bool,
    /// Retained previous-generation keys for opening delayed packets still
    /// protected with the old key phase (RFC 9001 §6.5). Null when no
    /// previous generation is retained.
    previous: ?Aes128PacketProtectionKeys = null,
    /// Short-header key phase bit corresponding to `previous`.
    previous_key_phase: ?bool = null,
};

/// Caller-owned key-phase state for one 1-RTT packet-protection direction.
///
/// This tracks current and next keys without owning TLS traffic-secret
/// production. Endpoints normally keep separate instances for local send keys
/// and peer receive keys.
pub const Aes128KeyPhaseState = struct {
    current: Aes128PacketProtectionKeys,
    next: Aes128PacketProtectionKeys,
    current_key_phase: bool,
    key_update_count: u64,
    /// Previously active keys retained for one PTO after a key update, so
    /// delayed packets protected with the old key phase can still be opened
    /// (RFC 9001 §6.5). Null before the first advance, after the retain
    /// window expires, or once a newer advance overwrites it.
    previous: ?Aes128PacketProtectionKeys = null,
    previous_key_phase: ?bool = null,
    previous_discard_deadline_millis: ?i64 = null,

    /// Initialize key-phase state from the currently active 1-RTT keys.
    pub fn init(current: Aes128PacketProtectionKeys, current_key_phase: bool) Aes128KeyPhaseState {
        return .{
            .current = current,
            .next = nextAes128PacketProtectionKeys(current),
            .current_key_phase = current_key_phase,
            .key_update_count = 0,
        };
    }

    /// Keys and phase used to protect the next locally sent packet.
    pub fn currentKeys(self: Aes128KeyPhaseState) Aes128PacketProtectionKeys {
        return self.current;
    }

    /// Short-header key phase bit corresponding to `currentKeys()`.
    pub fn currentKeyPhase(self: Aes128KeyPhaseState) bool {
        return self.current_key_phase;
    }

    /// Number of key-phase advances applied since initialization.
    pub fn keyUpdateCount(self: Aes128KeyPhaseState) u64 {
        return self.key_update_count;
    }

    /// Current retained key generation.
    pub fn currentKeyGeneration(self: Aes128KeyPhaseState) u64 {
        return self.key_update_count;
    }

    /// Next retained key generation.
    pub fn nextKeyGeneration(self: Aes128KeyPhaseState) u64 {
        return self.key_update_count +| 1;
    }

    /// Previously retained key generation, if any. The previous generation is
    /// `key_update_count - 1` after at least one advance.
    pub fn previousKeyGeneration(self: Aes128KeyPhaseState) ?u64 {
        if (self.previous == null) return null;
        return self.key_update_count -% 1;
    }

    /// Return whether the state still retains keys for `generation`.
    pub fn retainsKeyGeneration(self: Aes128KeyPhaseState, generation: u64) bool {
        if (generation == self.currentKeyGeneration()) return true;
        if (generation == self.nextKeyGeneration()) return true;
        if (self.previousKeyGeneration()) |prev_gen| {
            return generation == prev_gen;
        }
        return false;
    }

    /// Current, next, and retained previous keys for opening a packet that
    /// might use any of those key phases.
    pub fn keyUpdateKeys(self: Aes128KeyPhaseState) ShortPacketKeyUpdateKeys {
        return .{
            .current = self.current,
            .next = self.next,
            .current_key_phase = self.current_key_phase,
            .previous = self.previous,
            .previous_key_phase = self.previous_key_phase,
        };
    }

    /// Start a local key update before sending with the next key phase.
    pub fn initiateKeyUpdate(self: *Aes128KeyPhaseState) void {
        self.advance();
    }

    /// Advance after a peer packet using the next key phase was authenticated.
    ///
    /// Returns true only when the peer key phase differed from the active phase.
    pub fn updateAfterReceiving(self: *Aes128KeyPhaseState, peer_key_phase: bool) bool {
        if (peer_key_phase == self.current_key_phase) return false;
        self.advance();
        return true;
    }

    /// Schedule the retained previous key to be discarded at `deadline_millis`.
    /// Has no effect when no previous generation is retained.
    pub fn schedulePreviousDiscard(self: *Aes128KeyPhaseState, deadline_millis: i64) void {
        if (self.previous == null) return;
        self.previous_discard_deadline_millis = deadline_millis;
    }

    /// Drop the retained previous key once its discard deadline has passed.
    /// Returns true if the previous key was discarded by this call.
    pub fn discardExpiredPrevious(self: *Aes128KeyPhaseState, now_millis: i64) bool {
        const deadline = self.previous_discard_deadline_millis orelse return false;
        if (now_millis < deadline) return false;
        self.previous = null;
        self.previous_key_phase = null;
        self.previous_discard_deadline_millis = null;
        return true;
    }

    fn advance(self: *Aes128KeyPhaseState) void {
        // Retain the outgoing current key as previous so delayed packets
        // protected with the old key phase can still be opened during the
        // post-update retain window (RFC 9001 §6.5). A newer advance
        // overwrites any previous that was not yet discarded.
        self.previous = self.current;
        self.previous_key_phase = self.current_key_phase;
        self.previous_discard_deadline_millis = null;
        self.current = self.next;
        self.next = nextAes128PacketProtectionKeys(self.current);
        self.current_key_phase = !self.current_key_phase;
        self.key_update_count +|= 1;
    }
};

/// Header-visible metadata for one protected long-header packet.
///
/// Packet type, version, and consumed length are available before header
/// protection is removed. Payload bytes and packet number still require the
/// packet protection keys.
pub const ProtectedLongPacketInfo = struct {
    /// QUIC long-header version field.
    version: packet.Version,
    /// Long-header packet type carried in byte 0.
    packet_type: packet.PacketType,
    /// Number of datagram bytes consumed by this protected long packet.
    len: usize,
};

/// Derive Initial packet protection keys for supported QUIC versions.
///
/// `client_initial_dcid` is the Destination Connection ID from the first client
/// Initial packet. QUIC v1 follows RFC 9001; QUIC v2 follows RFC 9369's
/// Initial salt and `quicv2` packet-protection labels.
pub fn deriveInitialSecrets(
    version: packet.Version,
    client_initial_dcid: []const u8,
) ProtectionError!InitialSecrets {
    if (client_initial_dcid.len > max_connection_id_len) return error.InvalidConnectionIdLength;
    const profile = switch (version) {
        .v1 => InitialProtectionProfile{ .salt = &initial_salt_v1, .labels = hkdf_labels_v1 },
        .v2 => InitialProtectionProfile{ .salt = &initial_salt_v2, .labels = hkdf_labels_v2 },
        else => return error.UnsupportedVersion,
    };

    const initial_secret = HkdfSha256.extract(profile.salt, client_initial_dcid);
    const client_secret = hkdfExpandLabel(initial_secret, "client in", initial_secret_len);
    const server_secret = hkdfExpandLabel(initial_secret, "server in", initial_secret_len);

    return .{
        .initial_secret = initial_secret,
        .client = deriveAes128PacketProtectionKeysWithLabels(client_secret, profile.labels),
        .server = deriveAes128PacketProtectionKeysWithLabels(server_secret, profile.labels),
    };
}

/// Derive AEAD and header-protection keys from one QUIC packet protection secret.
///
/// The secret can be an Initial secret or a TLS-produced Handshake, 0-RTT, or
/// 1-RTT traffic secret for an AES-128-GCM QUIC cipher suite.
pub fn deriveAes128PacketProtectionKeys(secret: [traffic_secret_len]u8) Aes128PacketProtectionKeys {
    return deriveAes128PacketProtectionKeysWithLabels(secret, hkdf_labels_v1);
}

fn deriveAes128PacketProtectionKeysWithLabels(
    secret: [traffic_secret_len]u8,
    labels: HkdfLabelSet,
) Aes128PacketProtectionKeys {
    return .{
        .secret = secret,
        .key = hkdfExpandLabel(secret, labels.key, aes_128_key_len),
        .iv = hkdfExpandLabel(secret, labels.iv, iv_len),
        .hp = hkdfExpandLabel(secret, labels.hp, aes_128_hp_key_len),
    };
}

/// Derive the next 1-RTT traffic secret for QUIC key update.
pub fn nextAes128TrafficSecret(secret: [traffic_secret_len]u8) [traffic_secret_len]u8 {
    return hkdfExpandLabel(secret, hkdf_labels_v1.ku, traffic_secret_len);
}

/// Derive the next packet protection keys for a QUIC 1-RTT key update.
///
/// QUIC key update changes the packet protection key and IV from the next
/// traffic secret. The header protection key is retained across updates.
pub fn nextAes128PacketProtectionKeys(current: Aes128PacketProtectionKeys) Aes128PacketProtectionKeys {
    const next_secret = nextAes128TrafficSecret(current.secret);
    var next = deriveAes128PacketProtectionKeys(next_secret);
    next.hp = current.hp;
    return next;
}

/// Produce the RFC 9001 AES-based header protection mask.
///
/// AES-GCM QUIC cipher suites use AES-ECB over a 16-byte ciphertext sample and
/// consume the first five mask bytes for the first header byte and packet number.
pub fn aes128HeaderProtectionMask(
    hp_key: [aes_128_hp_key_len]u8,
    sample: [header_protection_sample_len]u8,
) [header_protection_mask_len]u8 {
    const aes = std.crypto.core.aes.Aes128.initEnc(hp_key);
    var block: [header_protection_sample_len]u8 = undefined;
    aes.encrypt(&block, &sample);
    return block[0..header_protection_mask_len].*;
}

/// Apply or remove a QUIC header protection mask in place.
///
/// Header protection is XOR-based, so applying the same mask twice restores the
/// original first byte and encoded packet number bytes.
pub fn applyHeaderProtectionMask(
    header_form: packet.HeaderForm,
    first_byte: *u8,
    packet_number_bytes: []u8,
    mask: [header_protection_mask_len]u8,
) ProtectionError!void {
    if (packet_number_bytes.len == 0 or packet_number_bytes.len > 4) return error.InvalidPacketNumberLength;
    const first_byte_mask: u8 = switch (header_form) {
        .long => 0x0f,
        .short => 0x1f,
    };
    first_byte.* ^= mask[0] & first_byte_mask;
    for (packet_number_bytes, 0..) |*byte, i| {
        byte.* ^= mask[i + 1];
    }
}

/// Build the RFC 9001 AEAD nonce from a packet protection IV and packet number.
pub fn packetProtectionNonce(iv: [iv_len]u8, packet_number: u64) ProtectionError![iv_len]u8 {
    if (packet_number > packet.max_packet_number) return error.InvalidPacketNumber;
    var nonce = iv;
    var packet_number_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &packet_number_bytes, packet_number, .big);
    for (packet_number_bytes, 0..) |byte, i| {
        nonce[iv_len - packet_number_bytes.len + i] ^= byte;
    }
    return nonce;
}

/// Protect a QUIC packet payload with AEAD_AES_128_GCM.
///
/// `associated_data` is the unprotected QUIC header through the encoded packet
/// number. Header protection is applied separately after this step.
pub fn protectAes128Payload(
    keys: Aes128PacketProtectionKeys,
    packet_number: u64,
    associated_data: []const u8,
    plaintext: []const u8,
    ciphertext: []u8,
    tag: *[aead_tag_len]u8,
) ProtectionError!void {
    if (ciphertext.len != plaintext.len) return error.InvalidPayloadLength;
    const nonce = try packetProtectionNonce(keys.iv, packet_number);
    Aes128Gcm.encrypt(ciphertext, tag, plaintext, associated_data, nonce, keys.key);
}

/// Remove AEAD_AES_128_GCM protection from a QUIC packet payload.
pub fn unprotectAes128Payload(
    keys: Aes128PacketProtectionKeys,
    packet_number: u64,
    associated_data: []const u8,
    ciphertext: []const u8,
    tag: [aead_tag_len]u8,
    plaintext: []u8,
) ProtectionError!void {
    if (plaintext.len != ciphertext.len) return error.InvalidPayloadLength;
    const nonce = try packetProtectionNonce(keys.iv, packet_number);
    Aes128Gcm.decrypt(plaintext, ciphertext, tag, associated_data, nonce, keys.key) catch return error.AuthenticationFailed;
}

/// Compute the Retry Integrity Tag for a transmitted Retry packet.
///
/// `retry_without_integrity_tag` is the exact Retry packet bytes as sent on the
/// wire, excluding the final 16-byte Retry Integrity Tag. The Original
/// Destination Connection ID comes from the client Initial packet that caused
/// this Retry and is prepended only in the Retry pseudo-packet. QUIC v1 uses
/// RFC 9001 fixed key material; QUIC v2 uses RFC 9369 fixed key material.
pub fn retryIntegrityTag(
    allocator: std.mem.Allocator,
    original_destination_connection_id: []const u8,
    retry_without_integrity_tag: []const u8,
) ![aead_tag_len]u8 {
    if (original_destination_connection_id.len > max_connection_id_len) return error.InvalidConnectionIdLength;
    const profile = try retryIntegrityProfileForDatagram(retry_without_integrity_tag);
    const pseudo_len = 1 + original_destination_connection_id.len + retry_without_integrity_tag.len;
    const pseudo_packet = try allocator.alloc(u8, pseudo_len);
    defer allocator.free(pseudo_packet);

    pseudo_packet[0] = @intCast(original_destination_connection_id.len);
    @memcpy(pseudo_packet[1..][0..original_destination_connection_id.len], original_destination_connection_id);
    @memcpy(pseudo_packet[1 + original_destination_connection_id.len ..], retry_without_integrity_tag);

    var ciphertext: [0]u8 = .{};
    const plaintext: [0]u8 = .{};
    var tag: [aead_tag_len]u8 = undefined;
    Aes128Gcm.encrypt(&ciphertext, &tag, &plaintext, pseudo_packet, profile.nonce, profile.key);
    return tag;
}

/// Verify the final 16 bytes of a Retry packet as the version-specific Integrity Tag.
pub fn verifyRetryIntegrityTag(
    allocator: std.mem.Allocator,
    original_destination_connection_id: []const u8,
    retry_datagram: []const u8,
) !bool {
    if (retry_datagram.len <= aead_tag_len) return error.InvalidPayloadLength;
    const tag_offset = retry_datagram.len - aead_tag_len;
    const computed = try retryIntegrityTag(allocator, original_destination_connection_id, retry_datagram[0..tag_offset]);

    var received: [aead_tag_len]u8 = undefined;
    @memcpy(&received, retry_datagram[tag_offset..]);
    return std.crypto.timing_safe.eql([aead_tag_len]u8, computed, received);
}

/// Serialize a QUIC Retry packet and fill its version-specific Integrity Tag.
///
/// The packet codec writes Retry unused bits in its canonical form; the
/// integrity tag is computed over those transmitted bytes plus the Original
/// Destination Connection ID from the client Initial that caused this Retry.
pub fn encodeRetryPacketWithIntegrity(
    allocator: std.mem.Allocator,
    original_destination_connection_id: []const u8,
    retry: packet.RetryPacket,
) ![]u8 {
    _ = try retryIntegrityProfileForVersion(retry.version);

    var tagged_retry = retry;
    tagged_retry.integrity_tag = [_]u8{0} ** aead_tag_len;

    const datagram = try allocator.alloc(u8, try retryPacketLen(tagged_retry));
    errdefer allocator.free(datagram);

    var out = buffer.fixedWriter(datagram);
    try packet.encodeRetryPacket(out.writer(), tagged_retry);
    std.debug.assert(out.getWritten().len == datagram.len);

    const tag_offset = datagram.len - aead_tag_len;
    const tag = try retryIntegrityTag(allocator, original_destination_connection_id, datagram[0..tag_offset]);
    @memcpy(datagram[tag_offset..], &tag);
    return datagram;
}

/// Verify and parse a QUIC Retry packet.
pub fn parseRetryPacketWithIntegrity(
    allocator: std.mem.Allocator,
    original_destination_connection_id: []const u8,
    retry_datagram: []const u8,
) !packet.RetryPacket {
    if (!try verifyRetryIntegrityTag(allocator, original_destination_connection_id, retry_datagram)) {
        return error.AuthenticationFailed;
    }
    return packet.parseRetryPacket(retry_datagram, allocator);
}

/// Return header-visible metadata for the first protected long-header packet.
///
/// This is used by coalesced-datagram receivers to decide which packet number
/// space and keys are needed before attempting AEAD opening. Retry packets are
/// intentionally rejected because they are not protected long-header packets.
pub fn peekProtectedLongPacketInfo(datagram: []const u8) !ProtectedLongPacketInfo {
    const prefix = try parseProtectedLongPrefix(datagram);
    if (prefix.length < @as(u64, aead_tag_len + 1)) return error.InvalidPayloadLength;

    const packet_end = try protectedLongPacketEnd(prefix);
    if (packet_end > datagram.len) return error.InvalidPayloadLength;
    try validateHeaderProtectionSample(packet_end, prefix.pn_offset);

    return .{
        .version = prefix.version,
        .packet_type = prefix.packet_type,
        .len = packet_end,
    };
}

/// Release buffers owned by a decoded protected long-header packet.
pub fn deinitProtectedLongPacket(decoded: *DecodedProtectedLongPacket, allocator: std.mem.Allocator) void {
    packet.deinitLongHeader(&decoded.packet.header, allocator);
    if (decoded.packet.plaintext.len != 0) {
        allocator.free(decoded.packet.plaintext);
    }
}

/// Release buffers owned by a decoded protected short-header packet.
pub fn deinitProtectedShortPacket(decoded: *DecodedProtectedShortPacket, allocator: std.mem.Allocator) void {
    packet.deinitShortHeader(&decoded.packet.header, allocator);
    if (decoded.packet.plaintext.len != 0) {
        allocator.free(decoded.packet.plaintext);
    }
}

/// Serialize and protect one QUIC long-header packet with AEAD_AES_128_GCM.
///
/// The returned datagram contains the long header, protected payload, AEAD tag,
/// and header protection. Callers own the returned slice and must free it.
pub fn protectLongPacketAes128(
    allocator: std.mem.Allocator,
    header: packet.LongHeader,
    packet_number_encoding: packet.PacketNumberEncoding,
    keys: Aes128PacketProtectionKeys,
    plaintext: []const u8,
) ![]u8 {
    const protected_payload_len = std.math.add(usize, plaintext.len, aead_tag_len) catch return error.InvalidPayloadLength;
    const protected_payload_len_u64 = std.math.cast(u64, protected_payload_len) orelse return error.InvalidPayloadLength;
    const wire_length = std.math.add(u64, protected_payload_len_u64, @as(u64, packet_number_encoding.len)) catch return error.InvalidPayloadLength;

    const header_len = try longHeaderLen(header, packet_number_encoding.len, wire_length);
    const pn_offset = header_len - packet_number_encoding.len;
    const total_len = std.math.add(usize, header_len, protected_payload_len) catch return error.InvalidPayloadLength;
    try validateHeaderProtectionSample(total_len, pn_offset);

    var protected_header = header;
    protected_header.payload_length = protected_payload_len_u64;

    const datagram = try allocator.alloc(u8, total_len);
    errdefer allocator.free(datagram);

    var writer = buffer.fixedWriter(datagram[0..header_len]);
    try packet.encodeLongHeaderWithPacketNumberEncoding(writer.writer(), protected_header, packet_number_encoding);
    std.debug.assert(writer.getWritten().len == header_len);

    const ciphertext = datagram[header_len..][0..plaintext.len];
    var tag: [aead_tag_len]u8 = undefined;
    try protectAes128Payload(keys, header.packet_number, datagram[0..header_len], plaintext, ciphertext, &tag);
    @memcpy(datagram[header_len + plaintext.len ..][0..aead_tag_len], &tag);

    var sample: [header_protection_sample_len]u8 = undefined;
    @memcpy(&sample, datagram[pn_offset + 4 ..][0..header_protection_sample_len]);
    const mask = aes128HeaderProtectionMask(keys.hp, sample);
    try applyHeaderProtectionMask(.long, &datagram[0], datagram[pn_offset..header_len], mask);

    return datagram;
}

/// Remove protection from one AEAD_AES_128_GCM long-header packet.
///
/// `expected_packet_number` is the next packet number expected in the decoded
/// packet number space and is used to reconstruct the full packet number.
pub fn unprotectLongPacketAes128(
    allocator: std.mem.Allocator,
    keys: Aes128PacketProtectionKeys,
    datagram: []const u8,
    expected_packet_number: u64,
) !DecodedProtectedLongPacket {
    const prefix = try parseProtectedLongPrefix(datagram);
    const packet_end = try protectedLongPacketEnd(prefix);
    if (packet_end > datagram.len) return error.InvalidPayloadLength;
    try validateHeaderProtectionSample(packet_end, prefix.pn_offset);

    var sample: [header_protection_sample_len]u8 = undefined;
    @memcpy(&sample, datagram[prefix.pn_offset + 4 ..][0..header_protection_sample_len]);
    const mask = aes128HeaderProtectionMask(keys.hp, sample);

    const first_byte = datagram[0] ^ (mask[0] & 0x0f);
    const pn_len: u8 = @as(u8, @intCast(first_byte & 0x03)) + 1;
    if (prefix.length < @as(u64, pn_len) + @as(u64, aead_tag_len)) return error.InvalidPayloadLength;

    const payload_start = prefix.pn_offset + @as(usize, pn_len);
    const ciphertext_end = packet_end - aead_tag_len;
    if (payload_start > ciphertext_end) return error.InvalidPayloadLength;

    const aad = try allocator.alloc(u8, payload_start);
    defer allocator.free(aad);
    @memcpy(aad, datagram[0..payload_start]);
    try applyHeaderProtectionMask(.long, &aad[0], aad[prefix.pn_offset..payload_start], mask);
    std.debug.assert(aad[0] == first_byte);

    const packet_number = try decodeUnmaskedPacketNumber(expected_packet_number, aad[prefix.pn_offset..payload_start]);

    var tag: [aead_tag_len]u8 = undefined;
    @memcpy(&tag, datagram[ciphertext_end..packet_end]);

    const ciphertext = datagram[payload_start..ciphertext_end];
    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);

    try unprotectAes128Payload(keys, packet_number, aad, ciphertext, tag, plaintext);

    const dcid = try copyOwned(allocator, prefix.dcid);
    errdefer if (dcid.len != 0) allocator.free(dcid);
    const scid = try copyOwned(allocator, prefix.scid);
    errdefer if (scid.len != 0) allocator.free(scid);
    const token = try copyOwned(allocator, prefix.token);
    errdefer if (token.len != 0) allocator.free(token);

    return .{
        .packet = .{
            .header = .{
                .version = prefix.version,
                .dcid = dcid,
                .scid = scid,
                .packet_type = prefix.packet_type,
                .token = token,
                .packet_number = packet_number,
                .payload_length = prefix.length - @as(u64, pn_len),
            },
            .plaintext = plaintext,
        },
        .len = packet_end,
    };
}

/// Serialize and protect one QUIC short-header packet with AEAD_AES_128_GCM.
///
/// The destination CID length is encoded by the caller through the supplied
/// header. Short headers do not carry a payload length, so the whole returned
/// datagram is one protected 1-RTT packet.
pub fn protectShortPacketAes128(
    allocator: std.mem.Allocator,
    header: packet.ShortHeader,
    packet_number_encoding: packet.PacketNumberEncoding,
    keys: Aes128PacketProtectionKeys,
    plaintext: []const u8,
) ![]u8 {
    const protected_payload_len = std.math.add(usize, plaintext.len, aead_tag_len) catch return error.InvalidPayloadLength;
    const header_len = try shortHeaderLen(header, packet_number_encoding.len);
    const pn_offset = header_len - packet_number_encoding.len;
    const total_len = std.math.add(usize, header_len, protected_payload_len) catch return error.InvalidPayloadLength;
    try validateHeaderProtectionSample(total_len, pn_offset);

    const datagram = try allocator.alloc(u8, total_len);
    errdefer allocator.free(datagram);

    var writer = buffer.fixedWriter(datagram[0..header_len]);
    try packet.encodeShortHeaderWithPacketNumberEncoding(writer.writer(), header, packet_number_encoding);
    std.debug.assert(writer.getWritten().len == header_len);

    const ciphertext = datagram[header_len..][0..plaintext.len];
    var tag: [aead_tag_len]u8 = undefined;
    try protectAes128Payload(keys, header.packet_number, datagram[0..header_len], plaintext, ciphertext, &tag);
    @memcpy(datagram[header_len + plaintext.len ..][0..aead_tag_len], &tag);

    var sample: [header_protection_sample_len]u8 = undefined;
    @memcpy(&sample, datagram[pn_offset + 4 ..][0..header_protection_sample_len]);
    const mask = aes128HeaderProtectionMask(keys.hp, sample);
    try applyHeaderProtectionMask(.short, &datagram[0], datagram[pn_offset..header_len], mask);

    return datagram;
}

/// Reveal the short-header spin bit without removing header protection.
///
/// QUIC header protection does not mask the spin bit. This helper does not
/// authenticate the packet payload and should only be used for routing,
/// observability, or deterministic spin-bit policy tests.
pub fn peekShortPacketSpinBit(datagram: []const u8) ProtectionError!bool {
    if (datagram.len == 0) return error.InvalidPayloadLength;
    if ((datagram[0] & 0x80) != 0) return error.InvalidPayloadLength;
    if ((datagram[0] & 0x40) == 0) return error.InvalidPayloadLength;
    return (datagram[0] & 0x20) != 0;
}

/// Reveal the short-header key phase bit using AES header protection.
///
/// The destination CID length is endpoint routing context. This does not
/// authenticate the packet payload; use it only to select the AEAD key for a
/// subsequent open attempt.
pub fn peekShortPacketKeyPhaseAes128(
    hp_key: [aes_128_hp_key_len]u8,
    datagram: []const u8,
    dcid_len: usize,
) ProtectionError!bool {
    const first_byte = try unmaskShortPacketFirstByte(hp_key, datagram, dcid_len);
    return (first_byte & 0x04) != 0;
}

/// Remove protection from one AEAD_AES_128_GCM short-header packet.
///
/// `dcid_len` comes from connection routing context because short headers do
/// not carry a destination connection-id length. `expected_packet_number` is
/// the next packet number expected in the Application packet number space.
pub fn unprotectShortPacketAes128(
    allocator: std.mem.Allocator,
    keys: Aes128PacketProtectionKeys,
    datagram: []const u8,
    dcid_len: usize,
    expected_packet_number: u64,
) !DecodedProtectedShortPacket {
    if (dcid_len > max_connection_id_len) return error.InvalidConnectionIdLength;
    if (datagram.len <= 1 + dcid_len) return error.InvalidPayloadLength;
    if ((datagram[0] & 0x80) != 0) return error.InvalidPayloadLength;
    if ((datagram[0] & 0x40) == 0) return error.InvalidPayloadLength;

    const pn_offset = 1 + dcid_len;
    try validateHeaderProtectionSample(datagram.len, pn_offset);

    var sample: [header_protection_sample_len]u8 = undefined;
    @memcpy(&sample, datagram[pn_offset + 4 ..][0..header_protection_sample_len]);
    const mask = aes128HeaderProtectionMask(keys.hp, sample);

    const first_byte = datagram[0] ^ (mask[0] & 0x1f);
    const pn_len: u8 = @as(u8, @intCast(first_byte & 0x03)) + 1;
    const payload_start = pn_offset + @as(usize, pn_len);
    const ciphertext_end = datagram.len - aead_tag_len;
    if (payload_start > ciphertext_end) return error.InvalidPayloadLength;

    const aad = try allocator.alloc(u8, payload_start);
    defer allocator.free(aad);
    @memcpy(aad, datagram[0..payload_start]);
    try applyHeaderProtectionMask(.short, &aad[0], aad[pn_offset..payload_start], mask);
    std.debug.assert(aad[0] == first_byte);

    var reader = buffer.fixedReader(aad);
    var header = try packet.parseShortHeaderWithExpectedPacketNumber(
        reader.reader(),
        allocator,
        dcid_len,
        expected_packet_number,
    );
    errdefer packet.deinitShortHeader(&header, allocator);

    const packet_number = header.packet_number;
    const ciphertext = datagram[payload_start..ciphertext_end];
    var tag: [aead_tag_len]u8 = undefined;
    @memcpy(&tag, datagram[ciphertext_end..]);

    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);

    try unprotectAes128Payload(keys, packet_number, aad, ciphertext, tag, plaintext);

    return .{
        .packet = .{
            .header = header,
            .plaintext = plaintext,
        },
        .len = datagram.len,
    };
}

/// Remove protection from a 1-RTT short packet that can use current, next, or
/// retained previous keys.
///
/// The key phase bit is revealed with the current header-protection key. When
/// it matches the current phase the packet is opened with `current`. When it
/// differs the packet is opened with `next` first (the peer initiated a key
/// update), falling back to the retained `previous` only if `next` fails to
/// authenticate and the phase matches the old key phase - modeling the delayed
/// old-key packet case from RFC 9001 §6.5. Because the key phase bit is a
/// single toggling bit, `next` must be tried before `previous` so that a
/// second peer update (same phase as a discarded generation) is not mistaken
/// for a delayed old-key packet.
pub fn unprotectShortPacketAes128WithKeyUpdate(
    allocator: std.mem.Allocator,
    keys: ShortPacketKeyUpdateKeys,
    datagram: []const u8,
    dcid_len: usize,
    expected_packet_number: u64,
) !DecodedProtectedShortPacket {
    const key_phase = try peekShortPacketKeyPhaseAes128(keys.current.hp, datagram, dcid_len);
    if (key_phase == keys.current_key_phase) {
        return unprotectShortPacketAes128(allocator, keys.current, datagram, dcid_len, expected_packet_number);
    }
    if (unprotectShortPacketAes128(allocator, keys.next, datagram, dcid_len, expected_packet_number)) |decoded| {
        return decoded;
    } else |next_err| {
        if (keys.previous) |prev| {
            if (keys.previous_key_phase) |prev_kp| {
                if (key_phase == prev_kp) {
                    return unprotectShortPacketAes128(allocator, prev, datagram, dcid_len, expected_packet_number);
                }
            }
        }
        return next_err;
    }
}

const ProtectedLongPrefix = struct {
    version: packet.Version,
    dcid: []const u8,
    scid: []const u8,
    packet_type: packet.PacketType,
    token: []const u8,
    length: u64,
    pn_offset: usize,
};

fn varIntLen(value: u64) ProtectionError!usize {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    if (value <= 4611686018427387903) return 8;
    return error.InvalidPayloadLength;
}

fn longHeaderLen(header: packet.LongHeader, pn_len: u8, wire_length: u64) !usize {
    if (pn_len == 0 or pn_len > 4) return error.InvalidPacketNumberLength;
    const token_len = if (header.packet_type == .initial) header.token.len else 0;
    var len: usize = 1 + 4 + 1 + header.dcid.len + 1 + header.scid.len;
    if (header.packet_type == .initial) {
        const token_len_u64 = std.math.cast(u64, token_len) orelse return error.InvalidPayloadLength;
        len += try varIntLen(token_len_u64);
        len += token_len;
    }
    len += try varIntLen(wire_length);
    len += pn_len;
    return len;
}

fn validateHeaderProtectionSample(packet_len: usize, pn_offset: usize) ProtectionError!void {
    const sample_offset = std.math.add(usize, pn_offset, 4) catch return error.InvalidPayloadLength;
    const sample_end = std.math.add(usize, sample_offset, header_protection_sample_len) catch return error.InvalidPayloadLength;
    if (sample_end > packet_len) return error.InvalidPayloadLength;
}

fn unmaskShortPacketFirstByte(
    hp_key: [aes_128_hp_key_len]u8,
    datagram: []const u8,
    dcid_len: usize,
) ProtectionError!u8 {
    if (dcid_len > max_connection_id_len) return error.InvalidConnectionIdLength;
    if (datagram.len <= 1 + dcid_len) return error.InvalidPayloadLength;
    if ((datagram[0] & 0x80) != 0) return error.InvalidPayloadLength;
    if ((datagram[0] & 0x40) == 0) return error.InvalidPayloadLength;

    const pn_offset = 1 + dcid_len;
    try validateHeaderProtectionSample(datagram.len, pn_offset);

    var sample: [header_protection_sample_len]u8 = undefined;
    @memcpy(&sample, datagram[pn_offset + 4 ..][0..header_protection_sample_len]);
    const mask = aes128HeaderProtectionMask(hp_key, sample);
    return datagram[0] ^ (mask[0] & 0x1f);
}

fn retryIntegrityProfileForVersion(version: packet.Version) ProtectionError!RetryIntegrityProfile {
    return switch (version) {
        .v1 => .{ .key = retry_integrity_key, .nonce = retry_integrity_nonce },
        .v2 => .{ .key = retry_integrity_key_v2, .nonce = retry_integrity_nonce_v2 },
        else => error.UnsupportedVersion,
    };
}

fn retryIntegrityProfileForDatagram(retry_without_integrity_tag: []const u8) ProtectionError!RetryIntegrityProfile {
    if (retry_without_integrity_tag.len < 5) return error.InvalidPayloadLength;
    if ((retry_without_integrity_tag[0] & 0x80) == 0) return error.InvalidPayloadLength;
    if ((retry_without_integrity_tag[0] & 0x40) == 0) return error.InvalidPayloadLength;

    const version: packet.Version = @enumFromInt(std.mem.readInt(u32, retry_without_integrity_tag[1..5], .big));
    return retryIntegrityProfileForVersion(version);
}

fn parseProtectedLongPrefix(datagram: []const u8) !ProtectedLongPrefix {
    var reader = buffer.fixedReader(datagram);

    const first_byte = try reader.readByte();
    if ((first_byte & 0x80) == 0) return error.InvalidHeaderForm;
    if ((first_byte & 0x40) == 0) return error.InvalidFixedBit;

    const packet_type_bits: u2 = @intCast((first_byte >> 4) & 0x03);

    var version_buf: [4]u8 = undefined;
    try reader.readNoEof(&version_buf);
    const version: packet.Version = @enumFromInt(std.mem.readInt(u32, &version_buf, .big));
    const packet_type = packet.longHeaderPacketTypeFromBits(version, packet_type_bits);
    if (packet_type == .retry) return error.UnsupportedPacketType;

    const dcid_len = try reader.readByte();
    if (dcid_len > 20) return error.InvalidConnectionIdLength;
    const dcid = try readBorrowedBytes(&reader, dcid_len);

    const scid_len = try reader.readByte();
    if (scid_len > 20) return error.InvalidConnectionIdLength;
    const scid = try readBorrowedBytes(&reader, scid_len);

    var token: []const u8 = &[_]u8{};
    if (packet_type == .initial) {
        const token_len_varint = try packet.decodeVarInt(reader.reader());
        const token_len = std.math.cast(usize, token_len_varint.value) orelse return error.InvalidPayloadLength;
        token = try readBorrowedBytes(&reader, token_len);
    }

    const length_varint = try packet.decodeVarInt(reader.reader());
    return .{
        .version = version,
        .dcid = dcid,
        .scid = scid,
        .packet_type = packet_type,
        .token = token,
        .length = length_varint.value,
        .pn_offset = reader.pos,
    };
}

fn readBorrowedBytes(reader: *buffer.FixedReader, len: usize) ![]const u8 {
    if (len > reader.remainingLen()) return error.InvalidPayloadLength;
    const start = reader.pos;
    reader.pos += len;
    return reader.data[start..reader.pos];
}

fn protectedLongPacketEnd(prefix: ProtectedLongPrefix) ProtectionError!usize {
    const pn_offset_u64 = std.math.cast(u64, prefix.pn_offset) orelse return error.InvalidPayloadLength;
    const end_u64 = std.math.add(u64, pn_offset_u64, prefix.length) catch return error.InvalidPayloadLength;
    return std.math.cast(usize, end_u64) orelse return error.InvalidPayloadLength;
}

fn decodeUnmaskedPacketNumber(expected_packet_number: u64, packet_number_bytes: []const u8) !u64 {
    if (packet_number_bytes.len == 0 or packet_number_bytes.len > 4) return error.InvalidPacketNumberLength;
    var truncated: u64 = 0;
    for (packet_number_bytes) |byte| {
        truncated = (truncated << 8) | byte;
    }
    return packet.reconstructPacketNumber(expected_packet_number, truncated, @intCast(packet_number_bytes.len));
}

fn copyOwned(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    if (data.len == 0) return &[_]u8{};
    const owned = try allocator.alloc(u8, data.len);
    @memcpy(owned, data);
    return owned;
}

fn retryPacketLen(retry: packet.RetryPacket) !usize {
    if (retry.dcid.len > max_connection_id_len or retry.scid.len > max_connection_id_len) return error.InvalidConnectionIdLength;
    if (retry.token.len == 0) return error.InvalidRetryPacket;

    var len: usize = 1 + 4 + 1 + 1 + aead_tag_len;
    len = std.math.add(usize, len, retry.dcid.len) catch return error.InvalidPayloadLength;
    len = std.math.add(usize, len, retry.scid.len) catch return error.InvalidPayloadLength;
    len = std.math.add(usize, len, retry.token.len) catch return error.InvalidPayloadLength;
    return len;
}

fn shortHeaderLen(header: packet.ShortHeader, pn_len: u8) !usize {
    if (header.dcid.len > max_connection_id_len) return error.InvalidConnectionIdLength;
    if (pn_len == 0 or pn_len > 4) return error.InvalidPacketNumberLength;
    var len: usize = 1;
    len = std.math.add(usize, len, header.dcid.len) catch return error.InvalidPayloadLength;
    len = std.math.add(usize, len, pn_len) catch return error.InvalidPayloadLength;
    return len;
}

fn hkdfExpandLabel(
    secret: [traffic_secret_len]u8,
    label: []const u8,
    comptime len: usize,
) [len]u8 {
    return std.crypto.tls.hkdfExpandLabel(HkdfSha256, secret, label, "", len);
}

fn expectHex(expected_hex: []const u8, actual: []const u8) !void {
    var expected: [64]u8 = undefined;
    const decoded = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqualSlices(u8, decoded, actual);
}

test "deriveInitialSecrets matches RFC 9001 Appendix A.1 vectors" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try deriveInitialSecrets(.v1, &dcid);

    try expectHex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44", &secrets.initial_secret);

    try expectHex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea", &secrets.client.secret);
    try expectHex("1f369613dd76d5467730efcbe3b1a22d", &secrets.client.key);
    try expectHex("fa044b2f42a3fd3b46fb255c", &secrets.client.iv);
    try expectHex("9f50449e04a0e810283a1e9933adedd2", &secrets.client.hp);

    try expectHex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b", &secrets.server.secret);
    try expectHex("cf3a5331653c364c88f0f379b6067e37", &secrets.server.key);
    try expectHex("0ac1493ca1905853b0bba03e", &secrets.server.iv);
    try expectHex("c206b8d9b9f0f37644430b490eeaa314", &secrets.server.hp);
}

test "deriveInitialSecrets matches RFC 9369 Appendix A.1 vectors" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try deriveInitialSecrets(.v2, &dcid);

    try expectHex("2062e8b3cd8d52092614b8071d0aa1fb7c2e3ac193f78b280e72d8f5751f6aba", &secrets.initial_secret);

    try expectHex("14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b", &secrets.client.secret);
    try expectHex("8b1a0bc121284290a29e0971b5cd045d", &secrets.client.key);
    try expectHex("91f73e2351d8fa91660e909f", &secrets.client.iv);
    try expectHex("45b95e15235d6f45a6b19cbcb0294ba9", &secrets.client.hp);

    try expectHex("0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1", &secrets.server.secret);
    try expectHex("82db637861d55e1d011f19ea71d5d2a7", &secrets.server.key);
    try expectHex("dd13c276499c0249d3310652", &secrets.server.iv);
    try expectHex("edf6d05c83121201b436e16877593c3a", &secrets.server.hp);
}

test "deriveInitialSecrets rejects unsupported versions and invalid CID length" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const unknown_version: packet.Version = @enumFromInt(0x0a0a0a0a);
    try std.testing.expectError(error.UnsupportedVersion, deriveInitialSecrets(unknown_version, &dcid));

    const long_dcid = [_]u8{0xaa} ** 21;
    try std.testing.expectError(error.InvalidConnectionIdLength, deriveInitialSecrets(.v1, &long_dcid));
    try std.testing.expectError(error.InvalidConnectionIdLength, deriveInitialSecrets(.v2, &long_dcid));
}

test "nextAes128PacketProtectionKeys derives QUIC key update material" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try deriveInitialSecrets(.v1, &dcid);
    const next_client = nextAes128PacketProtectionKeys(secrets.client);

    try expectHex("4428ffa195ad665b9ebf9456945b99e8ff848512cab93d0426436409047d666c", &next_client.secret);
    try expectHex("e85fece7a6f1b06576c46503cabcfa0d", &next_client.key);
    try expectHex("994107a30fb5ed593e8976f2", &next_client.iv);
    try expectHex("9f50449e04a0e810283a1e9933adedd2", &next_client.hp);

    const direct_next_secret = nextAes128TrafficSecret(secrets.client.secret);
    try std.testing.expectEqualSlices(u8, &next_client.secret, &direct_next_secret);
    try std.testing.expect(!std.mem.eql(u8, &secrets.client.key, &next_client.key));
    try std.testing.expect(!std.mem.eql(u8, &secrets.client.iv, &next_client.iv));
    try std.testing.expectEqualSlices(u8, &secrets.client.hp, &next_client.hp);
}

test "Aes128KeyPhaseState advances send and receive phases" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try deriveInitialSecrets(.v1, &dcid);

    var state = Aes128KeyPhaseState.init(secrets.client, false);
    const first_next = state.next;
    try std.testing.expect(!state.currentKeyPhase());
    try std.testing.expectEqual(@as(u64, 0), state.keyUpdateCount());
    try std.testing.expectEqual(@as(u64, 0), state.currentKeyGeneration());
    try std.testing.expectEqual(@as(u64, 1), state.nextKeyGeneration());
    try std.testing.expect(state.retainsKeyGeneration(0));
    try std.testing.expect(state.retainsKeyGeneration(1));
    try std.testing.expect(!state.retainsKeyGeneration(2));
    const first_current = state.currentKeys();
    try std.testing.expectEqualSlices(u8, &secrets.client.secret, &first_current.secret);
    try std.testing.expectEqualSlices(u8, &first_next.secret, &state.keyUpdateKeys().next.secret);

    state.initiateKeyUpdate();
    try std.testing.expect(state.currentKeyPhase());
    try std.testing.expectEqual(@as(u64, 1), state.keyUpdateCount());
    // The previous generation is retained after an advance so delayed packets
    // protected with the old key phase can still be opened (RFC 9001 §6.5).
    try std.testing.expectEqual(@as(?u64, 0), state.previousKeyGeneration());
    try std.testing.expect(state.retainsKeyGeneration(0));
    try std.testing.expect(state.retainsKeyGeneration(1));
    try std.testing.expect(state.retainsKeyGeneration(2));
    const updated_current = state.currentKeys();
    const updated_keys = state.keyUpdateKeys();
    try std.testing.expectEqualSlices(u8, &first_next.secret, &updated_current.secret);
    try std.testing.expectEqualSlices(u8, &secrets.client.hp, &updated_current.hp);
    try std.testing.expectEqualSlices(u8, &updated_current.secret, &updated_keys.current.secret);
    try std.testing.expectEqual(true, updated_keys.current_key_phase);
    try std.testing.expect(updated_keys.previous != null);
    try std.testing.expectEqual(@as(?bool, false), updated_keys.previous_key_phase);

    try std.testing.expect(!state.updateAfterReceiving(true));
    try std.testing.expectEqual(@as(u64, 1), state.keyUpdateCount());
    try std.testing.expect(state.updateAfterReceiving(false));
    try std.testing.expect(!state.currentKeyPhase());
    try std.testing.expectEqual(@as(u64, 2), state.keyUpdateCount());
    // A newer advance overwrites the retained previous: generation 1 is now
    // previous, and generation 0 is no longer retained.
    try std.testing.expectEqual(@as(?u64, 1), state.previousKeyGeneration());
    try std.testing.expect(!state.retainsKeyGeneration(0));
    try std.testing.expect(state.retainsKeyGeneration(1));
    try std.testing.expect(state.retainsKeyGeneration(2));
    try std.testing.expect(state.retainsKeyGeneration(3));
    try std.testing.expectEqual(false, state.keyUpdateKeys().current_key_phase);
}

test "Aes128KeyPhaseState retains previous key until discard deadline" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try deriveInitialSecrets(.v1, &dcid);

    var state = Aes128KeyPhaseState.init(secrets.client, false);
    state.initiateKeyUpdate();
    try std.testing.expectEqual(@as(?u64, 0), state.previousKeyGeneration());
    try std.testing.expect(state.retainsKeyGeneration(0));

    // Before a deadline is scheduled, the previous key never expires.
    try std.testing.expect(!state.discardExpiredPrevious(1_000_000));

    // Schedule a discard deadline one PTO ahead; the previous key is retained
    // until the deadline passes, then dropped (RFC 9001 §6.5 / RFC 9002 §6.2).
    state.schedulePreviousDiscard(1_000);
    try std.testing.expect(!state.discardExpiredPrevious(999));
    try std.testing.expect(state.retainsKeyGeneration(0));
    try std.testing.expect(state.discardExpiredPrevious(1_000));
    try std.testing.expectEqual(@as(?u64, null), state.previousKeyGeneration());
    try std.testing.expect(!state.retainsKeyGeneration(0));
    try std.testing.expect(state.retainsKeyGeneration(1));

    // Once previous is gone, a further call is a no-op.
    try std.testing.expect(!state.discardExpiredPrevious(2_000));
}

test "AES header protection mask matches RFC 9001 Appendix A.2 sample" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try deriveInitialSecrets(.v1, &dcid);

    var sample: [header_protection_sample_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sample, "d1b1c98dd7689fb8ec11d242b123dc9b");
    const mask = aes128HeaderProtectionMask(secrets.client.hp, sample);
    try expectHex("437b9aec36", &mask);

    var first_byte: u8 = 0xc3;
    var packet_number = [_]u8{ 0x00, 0x00, 0x00, 0x02 };
    try applyHeaderProtectionMask(.long, &first_byte, &packet_number, mask);

    try std.testing.expectEqual(@as(u8, 0xc0), first_byte);
    try expectHex("7b9aec34", &packet_number);

    try applyHeaderProtectionMask(.long, &first_byte, &packet_number, mask);
    try std.testing.expectEqual(@as(u8, 0xc3), first_byte);
    try expectHex("00000002", &packet_number);
}

test "applyHeaderProtectionMask validates packet number length and short header mask bits" {
    const mask = [_]u8{ 0xff, 0x01, 0x02, 0x03, 0x04 };

    var first_byte: u8 = 0x40;
    var empty_packet_number = [_]u8{};
    try std.testing.expectError(error.InvalidPacketNumberLength, applyHeaderProtectionMask(.short, &first_byte, &empty_packet_number, mask));

    var long_packet_number = [_]u8{ 0, 1, 2, 3, 4 };
    try std.testing.expectError(error.InvalidPacketNumberLength, applyHeaderProtectionMask(.short, &first_byte, &long_packet_number, mask));

    var short_first: u8 = 0x41;
    var packet_number = [_]u8{ 0xaa, 0xbb };
    try applyHeaderProtectionMask(.short, &short_first, &packet_number, mask);
    try std.testing.expectEqual(@as(u8, 0x5e), short_first);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xab, 0xb9 }, &packet_number);
}

test "packetProtectionNonce XORs packet number into IV" {
    const iv = [_]u8{ 0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c };
    const nonce = try packetProtectionNonce(iv, 2);
    try expectHex("fa044b2f42a3fd3b46fb255e", &nonce);
    try std.testing.expectError(error.InvalidPacketNumber, packetProtectionNonce(iv, packet.max_packet_number + 1));
}

test "protectAes128Payload matches RFC 9001 Appendix A.3 server Initial" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try deriveInitialSecrets(.v1, &dcid);

    const aad_hex = "c1000000010008f067a5502a4262b50040750001";
    var associated_data: [aad_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&associated_data, aad_hex);

    const plaintext_hex =
        "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739" ++
        "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94" ++
        "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00" ++
        "020304";
    var plaintext: [plaintext_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&plaintext, plaintext_hex);

    const protected_payload_hex =
        "5a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb3" ++
        "8cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9" ++
        "c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f" ++
        "58891850abbdca3d20398c276456cbc42158407dd074ee";
    var expected_protected_payload: [protected_payload_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_protected_payload, protected_payload_hex);

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [aead_tag_len]u8 = undefined;
    try protectAes128Payload(secrets.server, 1, &associated_data, &plaintext, &ciphertext, &tag);

    var protected_payload: [plaintext.len + aead_tag_len]u8 = undefined;
    @memcpy(protected_payload[0..ciphertext.len], &ciphertext);
    @memcpy(protected_payload[ciphertext.len..], &tag);
    try std.testing.expectEqualSlices(u8, &expected_protected_payload, &protected_payload);

    var opened: [plaintext.len]u8 = undefined;
    try unprotectAes128Payload(secrets.server, 1, &associated_data, &ciphertext, tag, &opened);
    try std.testing.expectEqualSlices(u8, &plaintext, &opened);

    tag[0] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, unprotectAes128Payload(secrets.server, 1, &associated_data, &ciphertext, tag, &opened));
}

test "protectLongPacketAes128 matches RFC 9001 Appendix A.3 server Initial" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try deriveInitialSecrets(.v1, &dcid);
    const server_scid = [_]u8{ 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 };

    const plaintext_hex =
        "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739" ++
        "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94" ++
        "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00" ++
        "020304";
    var plaintext: [plaintext_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&plaintext, plaintext_hex);

    const expected_packet_hex =
        "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a" ++
        "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3" ++
        "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84" ++
        "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4" ++
        "2158407dd074ee";
    var expected_packet: [expected_packet_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_packet, expected_packet_hex);

    const header = packet.LongHeader{
        .version = .v1,
        .dcid = &[_]u8{},
        .scid = &server_scid,
        .packet_type = .initial,
        .token = &[_]u8{},
        .packet_number = 1,
        .payload_length = 0,
    };
    const protected = try protectLongPacketAes128(std.testing.allocator, header, .{
        .len = 2,
        .truncated_packet_number = 1,
    }, secrets.server, &plaintext);
    defer std.testing.allocator.free(protected);
    try std.testing.expectEqualSlices(u8, &expected_packet, protected);

    var opened = try unprotectLongPacketAes128(std.testing.allocator, secrets.server, protected, 0);
    defer deinitProtectedLongPacket(&opened, std.testing.allocator);
    try std.testing.expectEqual(@as(usize, expected_packet.len), opened.len);
    try std.testing.expectEqual(packet.Version.v1, opened.packet.header.version);
    try std.testing.expectEqual(packet.PacketType.initial, opened.packet.header.packet_type);
    try std.testing.expectEqual(@as(u64, 1), opened.packet.header.packet_number);
    try std.testing.expectEqual(@as(u64, plaintext.len + aead_tag_len), opened.packet.header.payload_length);
    try std.testing.expectEqualSlices(u8, &[_]u8{}, opened.packet.header.dcid);
    try std.testing.expectEqualSlices(u8, &server_scid, opened.packet.header.scid);
    try std.testing.expectEqualSlices(u8, &plaintext, opened.packet.plaintext);

    var tampered = expected_packet;
    tampered[tampered.len - 1] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, unprotectLongPacketAes128(std.testing.allocator, secrets.server, &tampered, 0));
}

test "protectLongPacketAes128 roundtrips QUIC v2 Initial packet type bits" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const secrets = try deriveInitialSecrets(.v2, &dcid);
    const plaintext = "quic v2 initial protected payload";

    const protected = try protectLongPacketAes128(std.testing.allocator, .{
        .version = .v2,
        .dcid = &dcid,
        .scid = &scid,
        .packet_type = .initial,
        .token = &[_]u8{},
        .packet_number = 0,
        .payload_length = 0,
    }, try packet.encodePacketNumberForHeader(0, null), secrets.client, plaintext);
    defer std.testing.allocator.free(protected);

    try std.testing.expectEqual(@as(u8, 0xd0), protected[0] & 0xf0);

    const info = try peekProtectedLongPacketInfo(protected);
    try std.testing.expectEqual(packet.Version.v2, info.version);
    try std.testing.expectEqual(packet.PacketType.initial, info.packet_type);
    try std.testing.expectEqual(protected.len, info.len);

    var opened = try unprotectLongPacketAes128(std.testing.allocator, secrets.client, protected, 0);
    defer deinitProtectedLongPacket(&opened, std.testing.allocator);

    try std.testing.expectEqual(packet.Version.v2, opened.packet.header.version);
    try std.testing.expectEqual(packet.PacketType.initial, opened.packet.header.packet_type);
    try std.testing.expectEqualSlices(u8, plaintext, opened.packet.plaintext);
}

test "protectShortPacketAes128 roundtrips a protected short packet" {
    const dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const secrets = try deriveInitialSecrets(.v1, &dcid);
    const plaintext = [_]u8{
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
    };
    const header = packet.ShortHeader{
        .dcid = &dcid,
        .spin_bit = true,
        .key_phase = false,
        .packet_number = 7,
    };

    const protected = try protectShortPacketAes128(std.testing.allocator, header, .{
        .len = 1,
        .truncated_packet_number = 7,
    }, secrets.client, &plaintext);
    defer std.testing.allocator.free(protected);

    try std.testing.expect((protected[0] & 0x80) == 0);
    try std.testing.expect((protected[0] & 0x40) != 0);
    try std.testing.expect((protected[0] & 0x20) != 0);
    try std.testing.expect(try peekShortPacketSpinBit(protected));
    try std.testing.expectError(error.InvalidPayloadLength, peekShortPacketSpinBit(&[_]u8{}));

    var opened = try unprotectShortPacketAes128(std.testing.allocator, secrets.client, protected, dcid.len, 0);
    defer deinitProtectedShortPacket(&opened, std.testing.allocator);
    try std.testing.expectEqual(protected.len, opened.len);
    try std.testing.expectEqual(@as(u64, 7), opened.packet.header.packet_number);
    try std.testing.expect(opened.packet.header.spin_bit);
    try std.testing.expect(!opened.packet.header.key_phase);
    try std.testing.expectEqualSlices(u8, &dcid, opened.packet.header.dcid);
    try std.testing.expectEqualSlices(u8, &plaintext, opened.packet.plaintext);

    protected[protected.len - 1] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, unprotectShortPacketAes128(std.testing.allocator, secrets.client, protected, dcid.len, 0));
}

test "unprotectShortPacketAes128WithKeyUpdate selects next key phase" {
    const dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const secrets = try deriveInitialSecrets(.v1, &dcid);
    const next_client = nextAes128PacketProtectionKeys(secrets.client);
    const plaintext = [_]u8{
        0x01,
        0x00,
        0x00,
        0x00,
    };

    const protected = try protectShortPacketAes128(std.testing.allocator, .{
        .dcid = &dcid,
        .spin_bit = false,
        .key_phase = true,
        .packet_number = 0,
    }, try packet.encodePacketNumberForHeader(0, null), next_client, &plaintext);
    defer std.testing.allocator.free(protected);

    try std.testing.expect(try peekShortPacketKeyPhaseAes128(secrets.client.hp, protected, dcid.len));
    try std.testing.expectError(error.AuthenticationFailed, unprotectShortPacketAes128(std.testing.allocator, secrets.client, protected, dcid.len, 0));

    var opened = try unprotectShortPacketAes128WithKeyUpdate(std.testing.allocator, .{
        .current = secrets.client,
        .next = next_client,
        .current_key_phase = false,
    }, protected, dcid.len, 0);
    defer deinitProtectedShortPacket(&opened, std.testing.allocator);

    try std.testing.expectEqual(@as(u64, 0), opened.packet.header.packet_number);
    try std.testing.expect(opened.packet.header.key_phase);
    try std.testing.expectEqualSlices(u8, &plaintext, opened.packet.plaintext);
}

test "protectShortPacketAes128 rejects packets without a header protection sample" {
    const dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const secrets = try deriveInitialSecrets(.v1, &dcid);
    const plaintext = [_]u8{0x01};
    const header = packet.ShortHeader{
        .dcid = &dcid,
        .spin_bit = false,
        .key_phase = false,
        .packet_number = 0,
    };

    try std.testing.expectError(error.InvalidPayloadLength, protectShortPacketAes128(std.testing.allocator, header, .{
        .len = 1,
        .truncated_packet_number = 0,
    }, secrets.client, &plaintext));
}

test "peekProtectedLongPacketInfo returns protected long packet boundaries" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const secrets = try deriveInitialSecrets(.v1, &dcid);

    const initial = try protectLongPacketAes128(std.testing.allocator, .{
        .version = .v1,
        .dcid = &dcid,
        .scid = &scid,
        .packet_type = .initial,
        .token = &[_]u8{},
        .packet_number = 0,
        .payload_length = 0,
    }, try packet.encodePacketNumberForHeader(0, null), secrets.client, "initial protected payload");
    defer std.testing.allocator.free(initial);

    const handshake = try protectLongPacketAes128(std.testing.allocator, .{
        .version = .v1,
        .dcid = &dcid,
        .scid = &scid,
        .packet_type = .handshake,
        .token = &[_]u8{},
        .packet_number = 0,
        .payload_length = 0,
    }, try packet.encodePacketNumberForHeader(0, null), secrets.server, "handshake protected payload");
    defer std.testing.allocator.free(handshake);

    const coalesced = try std.testing.allocator.alloc(u8, initial.len + handshake.len);
    defer std.testing.allocator.free(coalesced);
    @memcpy(coalesced[0..initial.len], initial);
    @memcpy(coalesced[initial.len..], handshake);

    const first = try peekProtectedLongPacketInfo(coalesced);
    try std.testing.expectEqual(packet.Version.v1, first.version);
    try std.testing.expectEqual(packet.PacketType.initial, first.packet_type);
    try std.testing.expectEqual(initial.len, first.len);

    const second = try peekProtectedLongPacketInfo(coalesced[first.len..]);
    try std.testing.expectEqual(packet.Version.v1, second.version);
    try std.testing.expectEqual(packet.PacketType.handshake, second.packet_type);
    try std.testing.expectEqual(handshake.len, second.len);
}

test "protectLongPacketAes128 rejects packets without a header protection sample" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try deriveInitialSecrets(.v1, &dcid);
    const plaintext = [_]u8{ 0x06, 0x00 };
    const header = packet.LongHeader{
        .version = .v1,
        .dcid = &dcid,
        .scid = &[_]u8{},
        .packet_type = .initial,
        .token = &[_]u8{},
        .packet_number = 0,
        .payload_length = 0,
    };
    try std.testing.expectError(error.InvalidPayloadLength, protectLongPacketAes128(std.testing.allocator, header, .{
        .len = 1,
        .truncated_packet_number = 0,
    }, secrets.client, &plaintext));
}

test "retryIntegrityTag matches RFC 9001 Appendix A.4 Retry packet" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const retry_hex =
        "ff000000010008f067a5502a4262b5746f6b656e" ++
        "04a265ba2eff4d829058fb3f0f2496ba";
    var retry_packet: [retry_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&retry_packet, retry_hex);

    const tag_offset = retry_packet.len - aead_tag_len;
    const tag = try retryIntegrityTag(std.testing.allocator, &original_dcid, retry_packet[0..tag_offset]);
    try expectHex("04a265ba2eff4d829058fb3f0f2496ba", &tag);
    try std.testing.expect(try verifyRetryIntegrityTag(std.testing.allocator, &original_dcid, &retry_packet));

    var tampered = retry_packet;
    tampered[tampered.len - 1] ^= 0x01;
    try std.testing.expect(!try verifyRetryIntegrityTag(std.testing.allocator, &original_dcid, &tampered));
}

test "retryIntegrityTag matches RFC 9369 Appendix A.4 Retry packet" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const retry_hex =
        "cf6b3343cf0008f067a5502a4262b5746f6b656e" ++
        "c8646ce8bfe33952d955543665dcc7b6";
    var retry_packet: [retry_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&retry_packet, retry_hex);

    const tag_offset = retry_packet.len - aead_tag_len;
    const tag = try retryIntegrityTag(std.testing.allocator, &original_dcid, retry_packet[0..tag_offset]);
    try expectHex("c8646ce8bfe33952d955543665dcc7b6", &tag);
    try std.testing.expect(try verifyRetryIntegrityTag(std.testing.allocator, &original_dcid, &retry_packet));

    var parsed = try parseRetryPacketWithIntegrity(std.testing.allocator, &original_dcid, &retry_packet);
    defer packet.deinitRetryPacket(&parsed, std.testing.allocator);
    try std.testing.expectEqual(packet.Version.v2, parsed.version);
    try std.testing.expectEqualSlices(u8, &[_]u8{}, parsed.dcid);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 }, parsed.scid);
    try std.testing.expectEqualSlices(u8, "token", parsed.token);

    var tampered = retry_packet;
    tampered[tampered.len - 1] ^= 0x01;
    try std.testing.expect(!try verifyRetryIntegrityTag(std.testing.allocator, &original_dcid, &tampered));
}

test "encodeRetryPacketWithIntegrity produces verifiable Retry packet" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const retry = packet.RetryPacket{
        .version = .v1,
        .dcid = &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd },
        .scid = &[_]u8{ 0x10, 0x20, 0x30, 0x40 },
        .token = "token",
        .integrity_tag = [_]u8{0} ** aead_tag_len,
    };

    const datagram = try encodeRetryPacketWithIntegrity(std.testing.allocator, &original_dcid, retry);
    defer std.testing.allocator.free(datagram);
    try std.testing.expect(try verifyRetryIntegrityTag(std.testing.allocator, &original_dcid, datagram));

    var parsed = try parseRetryPacketWithIntegrity(std.testing.allocator, &original_dcid, datagram);
    defer packet.deinitRetryPacket(&parsed, std.testing.allocator);
    try std.testing.expectEqual(packet.Version.v1, parsed.version);
    try std.testing.expectEqualSlices(u8, retry.dcid, parsed.dcid);
    try std.testing.expectEqualSlices(u8, retry.scid, parsed.scid);
    try std.testing.expectEqualSlices(u8, retry.token, parsed.token);

    var v2_retry = retry;
    v2_retry.version = .v2;
    const v2_datagram = try encodeRetryPacketWithIntegrity(std.testing.allocator, &original_dcid, v2_retry);
    defer std.testing.allocator.free(v2_datagram);
    try std.testing.expectEqual(@as(u8, 0xc0), v2_datagram[0]);
    try std.testing.expect(try verifyRetryIntegrityTag(std.testing.allocator, &original_dcid, v2_datagram));

    var parsed_v2 = try parseRetryPacketWithIntegrity(std.testing.allocator, &original_dcid, v2_datagram);
    defer packet.deinitRetryPacket(&parsed_v2, std.testing.allocator);
    try std.testing.expectEqual(packet.Version.v2, parsed_v2.version);
    try std.testing.expectEqualSlices(u8, v2_retry.dcid, parsed_v2.dcid);
    try std.testing.expectEqualSlices(u8, v2_retry.scid, parsed_v2.scid);
    try std.testing.expectEqualSlices(u8, v2_retry.token, parsed_v2.token);

    var tampered = try std.testing.allocator.dupe(u8, datagram);
    defer std.testing.allocator.free(tampered);
    tampered[5] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, parseRetryPacketWithIntegrity(std.testing.allocator, &original_dcid, tampered));

    var unknown_retry = retry;
    unknown_retry.version = @enumFromInt(0x0a0a0a0a);
    try std.testing.expectError(error.UnsupportedVersion, encodeRetryPacketWithIntegrity(std.testing.allocator, &original_dcid, unknown_retry));
}

test "retry integrity validates input bounds" {
    const long_original_dcid = [_]u8{0xaa} ** 21;
    const retry_without_tag = [_]u8{ 0xff, 0x00 };
    try std.testing.expectError(error.InvalidConnectionIdLength, retryIntegrityTag(std.testing.allocator, &long_original_dcid, &retry_without_tag));

    const original_dcid = [_]u8{0x83};
    const too_short_retry_without_tag = [_]u8{ 0xff, 0x00, 0x00, 0x00 };
    try std.testing.expectError(error.InvalidPayloadLength, retryIntegrityTag(std.testing.allocator, &original_dcid, &too_short_retry_without_tag));

    const unknown_version_retry = [_]u8{ 0xff, 0x0a, 0x0a, 0x0a, 0x0a };
    try std.testing.expectError(error.UnsupportedVersion, retryIntegrityTag(std.testing.allocator, &original_dcid, &unknown_version_retry));

    const too_short_retry = [_]u8{0xff} ** aead_tag_len;
    try std.testing.expectError(error.InvalidPayloadLength, verifyRetryIntegrityTag(std.testing.allocator, &original_dcid, &too_short_retry));
}

test "payload protection validates buffer lengths" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try deriveInitialSecrets(.v1, &dcid);
    const associated_data = [_]u8{0xc0};
    const plaintext = [_]u8{0x06};
    var empty_ciphertext = [_]u8{};
    var tag: [aead_tag_len]u8 = [_]u8{0} ** aead_tag_len;
    try std.testing.expectError(error.InvalidPayloadLength, protectAes128Payload(secrets.client, 0, &associated_data, &plaintext, &empty_ciphertext, &tag));

    const ciphertext = [_]u8{0x00};
    var empty_plaintext = [_]u8{};
    try std.testing.expectError(error.InvalidPayloadLength, unprotectAes128Payload(secrets.client, 0, &associated_data, &ciphertext, tag, &empty_plaintext));
}
