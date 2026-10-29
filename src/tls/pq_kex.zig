//! Post-quantum hybrid key exchange: X25519 + Kyber768 (draft00).
//!
//! Combines X25519 ECDH with Kyber768 KEM for both classical
//! and post-quantum security guarantees.

const std = @import("std");
const X25519 = std.crypto.dh.X25519;
const Kyber768 = std.crypto.kem.kyber_d00.Kyber768;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const secureRandomBytes = @import("tls13.zig").secureRandomBytes;

pub const x25519_public_len = X25519.public_length;
pub const x25519_shared_len = 32;
pub const kyber_public_key_len = Kyber768.PublicKey.encoded_length;
pub const kyber_ciphertext_len = Kyber768.ciphertext_length;
pub const kyber_shared_len = Kyber768.shared_length;
pub const hybrid_public_key_len = x25519_public_len + kyber_public_key_len;

/// Client-side key exchange state.
pub const ClientKex = struct {
    x25519_keypair: X25519.KeyPair,
    kyber_keypair: Kyber768.KeyPair,

    /// Generate from deterministic seeds (for testing).
    pub fn generateDeterministic(x25519_seed: [32]u8, kyber_seed: [Kyber768.seed_length]u8) !ClientKex {
        return .{
            .x25519_keypair = X25519.KeyPair.generateDeterministic(x25519_seed),
            .kyber_keypair = try Kyber768.KeyPair.generateDeterministic(kyber_seed),
        };
    }

    /// Serialize the combined public key: X25519 pk || Kyber768 pk.
    pub fn publicKeyShare(self: *const ClientKex) [hybrid_public_key_len]u8 {
        var share: [hybrid_public_key_len]u8 = undefined;
        @memcpy(share[0..x25519_public_len], &self.x25519_keypair.public_key);
        const kyber_pk = self.kyber_keypair.public_key.toBytes();
        @memcpy(share[x25519_public_len..], &kyber_pk);
        return share;
    }

    /// Compute the shared secret from the server's response.
    pub fn sharedSecret(self: *const ClientKex, server_response: []const u8) ![32]u8 {
        if (server_response.len < x25519_public_len + kyber_ciphertext_len)
            return error.InvalidResponse;

        var server_x25519_pk: [x25519_public_len]u8 = undefined;
        @memcpy(&server_x25519_pk, server_response[0..x25519_public_len]);
        const x25519_shared = X25519.scalarmult(
            self.x25519_keypair.secret_key,
            server_x25519_pk,
        ) catch return error.InvalidPeerKey;

        var kyber_ct: [kyber_ciphertext_len]u8 = undefined;
        @memcpy(&kyber_ct, server_response[x25519_public_len .. x25519_public_len + kyber_ciphertext_len]);
        const kyber_shared = try self.kyber_keypair.secret_key.decaps(&kyber_ct);

        return combineSecrets(&x25519_shared, &kyber_shared);
    }
};

/// Server-side: process client share, produce response + shared secret.
pub fn serverRespondDeterministic(
    client_share: []const u8,
    x25519_seed: [32]u8,
    kyber_seed: [Kyber768.encaps_seed_length]u8,
    allocator: std.mem.Allocator,
) !struct { response: []u8, shared: [32]u8 } {
    if (client_share.len < hybrid_public_key_len)
        return error.InvalidShare;

    var client_x25519_pk: [x25519_public_len]u8 = undefined;
    @memcpy(&client_x25519_pk, client_share[0..x25519_public_len]);

    var kyber_pk_bytes: [kyber_public_key_len]u8 = undefined;
    @memcpy(&kyber_pk_bytes, client_share[x25519_public_len..hybrid_public_key_len]);
    const client_kyber_pk = Kyber768.PublicKey.fromBytes(&kyber_pk_bytes) catch
        return error.InvalidShare;

    const server_x25519 = X25519.KeyPair.generateDeterministic(x25519_seed);
    const x25519_shared = X25519.scalarmult(
        server_x25519.secret_key,
        client_x25519_pk,
    ) catch return error.InvalidPeerKey;

    const encapsulated = client_kyber_pk.encapsDeterministic(&kyber_seed);

    const shared = try combineSecrets(&x25519_shared, &encapsulated.shared_secret);

    const response_len = x25519_public_len + kyber_ciphertext_len;
    const response = try allocator.alloc(u8, response_len);
    @memcpy(response[0..x25519_public_len], &server_x25519.public_key);
    @memcpy(response[x25519_public_len..], &encapsulated.ciphertext);

    return .{ .response = response, .shared = shared };
}

fn combineSecrets(x25519_shared: []const u8, kyber_shared: []const u8) ![32]u8 {
    var ikm: [x25519_shared_len + kyber_shared_len]u8 = undefined;
    @memcpy(ikm[0..x25519_shared_len], x25519_shared);
    @memcpy(ikm[x25519_shared_len..], kyber_shared);
    const prk = HkdfSha256.extract("X25519Kyber768Draft00", &ikm);
    var result: [32]u8 = undefined;
    HkdfSha256.expand(&result, "shared_secret", prk);
    return result;
}

test "X25519Kyber768 hybrid key exchange roundtrip" {
    var client_x25519_seed: [32]u8 = undefined;
    var client_kyber_seed: [Kyber768.seed_length]u8 = undefined;
    var server_x25519_seed: [32]u8 = undefined;
    var server_kyber_seed: [Kyber768.encaps_seed_length]u8 = undefined;
    secureRandomBytes(&client_x25519_seed);
    secureRandomBytes(&client_kyber_seed);
    secureRandomBytes(&server_x25519_seed);
    secureRandomBytes(&server_kyber_seed);

    const client = try ClientKex.generateDeterministic(client_x25519_seed, client_kyber_seed);
    const client_share = client.publicKeyShare();
    try std.testing.expectEqual(hybrid_public_key_len, client_share.len);

    const server_result = try serverRespondDeterministic(
        &client_share,
        server_x25519_seed,
        server_kyber_seed,
        std.testing.allocator,
    );
    defer std.testing.allocator.free(server_result.response);

    const client_shared = try client.sharedSecret(server_result.response);
    try std.testing.expectEqual(client_shared, server_result.shared);
}

test "X25519Kyber768 key lengths" {
    try std.testing.expectEqual(@as(usize, 32), x25519_public_len);
    try std.testing.expect(kyber_public_key_len > 0);
    try std.testing.expect(kyber_ciphertext_len > 0);
    try std.testing.expectEqual(hybrid_public_key_len, x25519_public_len + kyber_public_key_len);
}

test "X25519Kyber768 invalid share rejected" {
    const short_share = @as([10]u8, @splat(0));
    try std.testing.expectError(
        error.InvalidShare,
        serverRespondDeterministic(&short_share, @as([32]u8, @splat(1)), @as([Kyber768.encaps_seed_length]u8, @splat(2)), std.testing.allocator),
    );
}
