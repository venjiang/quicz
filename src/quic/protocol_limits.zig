/// Largest value encodable as a QUIC variable-length integer.
pub const max_quic_varint: u64 = (@as(u64, 1) << 62) - 1;

/// Largest valid QUIC stream count.
pub const max_stream_count: u64 = @as(u64, 1) << 60;

/// RFC 9000 connection IDs are encoded on at most 20 bytes.
pub const max_connection_id_len: usize = 20;

/// Client Initial packets must use at least an 8-byte destination connection ID.
pub const min_initial_destination_connection_id_len: usize = 8;

/// Client Initial UDP datagrams must be padded to at least 1200 bytes.
pub const min_initial_udp_datagram_len: usize = 1200;

/// QUIC endpoints must allow at least two active connection IDs.
pub const min_active_connection_id_limit: u64 = 2;

/// Closing and draining states last for three PTO periods.
pub const close_state_pto_multiplier: u64 = 3;

/// RFC path validation sends at most three PATH_CHALLENGE attempts here.
pub const max_path_challenge_transmissions: u8 = 3;

/// Packet-threshold loss marks packets three packet numbers behind.
pub const packet_threshold_loss_gap: u64 = 3;

/// Server anti-amplification budget is three times received bytes.
pub const anti_amplification_multiplier: usize = 3;
