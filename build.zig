const std = @import("std");
const builtin = @import("builtin");

const required_zig_version = "0.16.0";

// Build script for the current Zig stable template.
// - Builds the current example executables.
// - Uses src/lib.zig as a shared module imported by both executables.
pub fn build(b: *std.Build) void {
    // Keep build semantics tied to the Zig version this repository is tested with.
    comptime {
        if (!std.mem.eql(u8, builtin.zig_version_string, required_zig_version)) {
            @compileError("quicz requires Zig " ++ required_zig_version ++ "; found " ++ builtin.zig_version_string);
        }
    }

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Shared quicz module (library logic lives in src/lib.zig)
    const quicz_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "quicz",
        .root_module = quicz_mod,
    });
    b.installArtifact(lib);

    // Echo server executable
    const exe_server = b.addExecutable(.{
        .name = "quicz-echo-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/echo_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_server);

    // Echo client executable
    const exe_client = b.addExecutable(.{
        .name = "quicz-echo-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/echo_client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_client);

    // Codec roundtrip executable
    const exe_codec = b.addExecutable(.{
        .name = "quicz-codec-roundtrip",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/codec_roundtrip.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_codec);

    // Transport parameters executable
    const exe_transport_parameters = b.addExecutable(.{
        .name = "quicz-transport-parameters",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/transport_parameters.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_transport_parameters);

    // Flow-control executable
    const exe_flow_control = b.addExecutable(.{
        .name = "quicz-flow-control",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/flow_control.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_flow_control);

    // Unidirectional stream executable
    const exe_uni_stream = b.addExecutable(.{
        .name = "quicz-uni-stream",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/uni_stream.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_uni_stream);

    // Stream reset executable
    const exe_stream_reset = b.addExecutable(.{
        .name = "quicz-stream-reset",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/stream_reset.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_stream_reset);

    // STOP_SENDING executable
    const exe_stop_sending = b.addExecutable(.{
        .name = "quicz-stop-sending",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/stop_sending.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_stop_sending);

    // Crypto stream executable
    const exe_crypto_stream = b.addExecutable(.{
        .name = "quicz-crypto-stream",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/crypto_stream.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_crypto_stream);

    // TLS backend adapter executable
    const exe_tls_backend_adapter = b.addExecutable(.{
        .name = "quicz-tls-backend-adapter",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/tls_backend_adapter.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_tls_backend_adapter);

    // Graceful close executable
    const exe_graceful_close = b.addExecutable(.{
        .name = "quicz-graceful-close",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/graceful_close.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_graceful_close);

    // Idle timeout executable
    const exe_idle_timeout = b.addExecutable(.{
        .name = "quicz-idle-timeout",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/idle_timeout.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_idle_timeout);

    // Packet-number-space executable
    const exe_packet_spaces = b.addExecutable(.{
        .name = "quicz-packet-spaces",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/packet_spaces.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_packet_spaces);

    // ECN validation executable
    const exe_ecn_validation = b.addExecutable(.{
        .name = "quicz-ecn-validation",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/ecn_validation.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_ecn_validation);

    // Loss recovery executable
    const exe_loss_recovery = b.addExecutable(.{
        .name = "quicz-loss-recovery",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/loss_recovery.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_loss_recovery);

    // PTO recovery executable
    const exe_pto_recovery = b.addExecutable(.{
        .name = "quicz-pto-recovery",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/pto_recovery.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_pto_recovery);

    // Endpoint recovery timer executable
    const exe_endpoint_recovery_timers = b.addExecutable(.{
        .name = "quicz-endpoint-recovery-timers",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/endpoint_recovery_timers.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_endpoint_recovery_timers);

    // Path validation executable
    const exe_path_validation = b.addExecutable(.{
        .name = "quicz-path-validation",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/path_validation.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_path_validation);

    // Address validation executable
    const exe_address_validation = b.addExecutable(.{
        .name = "quicz-address-validation",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/address_validation.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_address_validation);

    // UDP address validation loopback executable
    const exe_udp_address_validation_loopback = b.addExecutable(.{
        .name = "quicz-udp-address-validation-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_address_validation_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_address_validation_loopback);

    // Retry token executable
    const exe_retry_token = b.addExecutable(.{
        .name = "quicz-retry-token",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/retry_token.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_retry_token);

    // Connection ID executable
    const exe_connection_ids = b.addExecutable(.{
        .name = "quicz-connection-ids",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/connection_ids.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_connection_ids);

    // Stateless reset executable
    const exe_stateless_reset = b.addExecutable(.{
        .name = "quicz-stateless-reset",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/stateless_reset.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_stateless_reset);

    // Initial keys executable
    const exe_initial_keys = b.addExecutable(.{
        .name = "quicz-initial-keys",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/initial_keys.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_initial_keys);

    // Endpoint routing executable
    const exe_endpoint_routing = b.addExecutable(.{
        .name = "quicz-endpoint-routing",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/endpoint_routing.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_endpoint_routing);

    // UDP endpoint loopback executable
    const exe_udp_endpoint_loopback = b.addExecutable(.{
        .name = "quicz-udp-endpoint-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_endpoint_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_endpoint_loopback);

    // UDP zero-length CID loopback executable
    const exe_udp_zero_cid_loopback = b.addExecutable(.{
        .name = "quicz-udp-zero-cid-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_zero_cid_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_zero_cid_loopback);

    // UDP preferred-address loopback executable
    const exe_udp_preferred_address_loopback = b.addExecutable(.{
        .name = "quicz-udp-preferred-address-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_preferred_address_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_preferred_address_loopback);

    // UDP replacement CID loopback executable
    const exe_udp_replacement_cid_loopback = b.addExecutable(.{
        .name = "quicz-udp-replacement-cid-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_replacement_cid_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_replacement_cid_loopback);

    // UDP connection ID loopback executable
    const exe_udp_connection_ids_loopback = b.addExecutable(.{
        .name = "quicz-udp-connection-ids-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_connection_ids_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_connection_ids_loopback);

    // UDP flow-control loopback executable
    const exe_udp_flow_control_loopback = b.addExecutable(.{
        .name = "quicz-udp-flow-control-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_flow_control_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_flow_control_loopback);

    // UDP spin-bit loopback executable
    const exe_udp_spin_bit_loopback = b.addExecutable(.{
        .name = "quicz-udp-spin-bit-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_spin_bit_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_spin_bit_loopback);

    // UDP ECN validation loopback executable
    const exe_udp_ecn_validation_loopback = b.addExecutable(.{
        .name = "quicz-udp-ecn-validation-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_ecn_validation_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_ecn_validation_loopback);

    // UDP PTO recovery loopback executable
    const exe_udp_pto_recovery_loopback = b.addExecutable(.{
        .name = "quicz-udp-pto-recovery-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_pto_recovery_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_pto_recovery_loopback);

    // UDP loss recovery loopback executable
    const exe_udp_loss_recovery_loopback = b.addExecutable(.{
        .name = "quicz-udp-loss-recovery-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_loss_recovery_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_loss_recovery_loopback);

    // UDP STREAM retransmission loopback executable
    const exe_udp_stream_retransmission_loopback = b.addExecutable(.{
        .name = "quicz-udp-stream-retransmission-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_stream_retransmission_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_stream_retransmission_loopback);

    // UDP congestion recovery loopback executable
    const exe_udp_congestion_recovery_loopback = b.addExecutable(.{
        .name = "quicz-udp-congestion-recovery-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_congestion_recovery_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_congestion_recovery_loopback);

    // UDP protected loopback executable
    const exe_udp_protected_loopback = b.addExecutable(.{
        .name = "quicz-udp-protected-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_protected_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_protected_loopback);

    // UDP Handshake keys loopback executable
    const exe_udp_handshake_keys_loopback = b.addExecutable(.{
        .name = "quicz-udp-handshake-keys-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_handshake_keys_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_handshake_keys_loopback);

    // UDP CryptoBackend CRYPTO stream loopback executable
    const exe_udp_crypto_stream_loopback = b.addExecutable(.{
        .name = "quicz-udp-crypto-stream-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_crypto_stream_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_crypto_stream_loopback);

    // UDP 0-RTT loopback executable
    const exe_udp_zero_rtt_loopback = b.addExecutable(.{
        .name = "quicz-udp-zero-rtt-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_zero_rtt_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_zero_rtt_loopback);

    // UDP 1-RTT loopback executable
    const exe_udp_one_rtt_loopback = b.addExecutable(.{
        .name = "quicz-udp-one-rtt-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_one_rtt_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_one_rtt_loopback);

    // UDP echo loopback executable
    const exe_udp_echo_loopback = b.addExecutable(.{
        .name = "quicz-udp-echo-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_echo_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_echo_loopback);

    // UDP CryptoBackend loopback executable
    const exe_udp_crypto_backend_loopback = b.addExecutable(.{
        .name = "quicz-udp-crypto-backend-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_crypto_backend_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_crypto_backend_loopback);

    // UDP HANDSHAKE_DONE loopback executable
    const exe_udp_handshake_done_loopback = b.addExecutable(.{
        .name = "quicz-udp-handshake-done-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_handshake_done_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_handshake_done_loopback);

    // UDP key update loopback executable
    const exe_udp_key_update_loopback = b.addExecutable(.{
        .name = "quicz-udp-key-update-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_key_update_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_key_update_loopback);

    // UDP path validation loopback executable
    const exe_udp_path_validation_loopback = b.addExecutable(.{
        .name = "quicz-udp-path-validation-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_path_validation_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_path_validation_loopback);

    // UDP Retry loopback executable
    const exe_udp_retry_loopback = b.addExecutable(.{
        .name = "quicz-udp-retry-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_retry_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_retry_loopback);

    // UDP close lifecycle loopback executable
    const exe_udp_close_lifecycle_loopback = b.addExecutable(.{
        .name = "quicz-udp-close-lifecycle-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_close_lifecycle_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_close_lifecycle_loopback);

    // UDP stateless reset loopback executable
    const exe_udp_stateless_reset_loopback = b.addExecutable(.{
        .name = "quicz-udp-stateless-reset-loopback",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_stateless_reset_loopback.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quicz", .module = quicz_mod },
            },
        }),
    });
    b.installArtifact(exe_udp_stateless_reset_loopback);

    // zig build run-server
    const run_server = b.step("run-server", "Run quicz echo server");
    const run_server_cmd = b.addRunArtifact(exe_server);
    run_server.dependOn(&run_server_cmd.step);
    run_server_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_server_cmd.addArgs(args);
    }

    // zig build run-client
    const run_client = b.step("run-client", "Run quicz echo client");
    const run_client_cmd = b.addRunArtifact(exe_client);
    run_client.dependOn(&run_client_cmd.step);
    run_client_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_client_cmd.addArgs(args);
    }

    // zig build run-codec
    const run_codec = b.step("run-codec", "Run quicz codec roundtrip example");
    const run_codec_cmd = b.addRunArtifact(exe_codec);
    run_codec.dependOn(&run_codec_cmd.step);
    run_codec_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_codec_cmd.addArgs(args);
    }

    // zig build run-transport-parameters
    const run_transport_parameters = b.step("run-transport-parameters", "Run quicz transport parameters example");
    const run_transport_parameters_cmd = b.addRunArtifact(exe_transport_parameters);
    run_transport_parameters.dependOn(&run_transport_parameters_cmd.step);
    run_transport_parameters_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_transport_parameters_cmd.addArgs(args);
    }

    // zig build run-flow-control
    const run_flow_control = b.step("run-flow-control", "Run quicz flow-control example");
    const run_flow_control_cmd = b.addRunArtifact(exe_flow_control);
    run_flow_control.dependOn(&run_flow_control_cmd.step);
    run_flow_control_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_flow_control_cmd.addArgs(args);
    }

    // zig build run-uni-stream
    const run_uni_stream = b.step("run-uni-stream", "Run quicz unidirectional stream example");
    const run_uni_stream_cmd = b.addRunArtifact(exe_uni_stream);
    run_uni_stream.dependOn(&run_uni_stream_cmd.step);
    run_uni_stream_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_uni_stream_cmd.addArgs(args);
    }

    // zig build run-stream-reset
    const run_stream_reset = b.step("run-stream-reset", "Run quicz stream reset example");
    const run_stream_reset_cmd = b.addRunArtifact(exe_stream_reset);
    run_stream_reset.dependOn(&run_stream_reset_cmd.step);
    run_stream_reset_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_stream_reset_cmd.addArgs(args);
    }

    // zig build run-stop-sending
    const run_stop_sending = b.step("run-stop-sending", "Run quicz STOP_SENDING example");
    const run_stop_sending_cmd = b.addRunArtifact(exe_stop_sending);
    run_stop_sending.dependOn(&run_stop_sending_cmd.step);
    run_stop_sending_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_stop_sending_cmd.addArgs(args);
    }

    // zig build run-crypto-stream
    const run_crypto_stream = b.step("run-crypto-stream", "Run quicz crypto stream example");
    const run_crypto_stream_cmd = b.addRunArtifact(exe_crypto_stream);
    run_crypto_stream.dependOn(&run_crypto_stream_cmd.step);
    run_crypto_stream_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_crypto_stream_cmd.addArgs(args);
    }

    // zig build run-tls-backend-adapter
    const run_tls_backend_adapter = b.step("run-tls-backend-adapter", "Run quicz TLS backend adapter example");
    const run_tls_backend_adapter_cmd = b.addRunArtifact(exe_tls_backend_adapter);
    run_tls_backend_adapter.dependOn(&run_tls_backend_adapter_cmd.step);
    run_tls_backend_adapter_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_tls_backend_adapter_cmd.addArgs(args);
    }

    // zig build run-graceful-close
    const run_graceful_close = b.step("run-graceful-close", "Run quicz graceful close example");
    const run_graceful_close_cmd = b.addRunArtifact(exe_graceful_close);
    run_graceful_close.dependOn(&run_graceful_close_cmd.step);
    run_graceful_close_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_graceful_close_cmd.addArgs(args);
    }

    // zig build run-idle-timeout
    const run_idle_timeout = b.step("run-idle-timeout", "Run quicz idle timeout example");
    const run_idle_timeout_cmd = b.addRunArtifact(exe_idle_timeout);
    run_idle_timeout.dependOn(&run_idle_timeout_cmd.step);
    run_idle_timeout_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_idle_timeout_cmd.addArgs(args);
    }

    // zig build run-packet-spaces
    const run_packet_spaces = b.step("run-packet-spaces", "Run quicz packet-number-space example");
    const run_packet_spaces_cmd = b.addRunArtifact(exe_packet_spaces);
    run_packet_spaces.dependOn(&run_packet_spaces_cmd.step);
    run_packet_spaces_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_packet_spaces_cmd.addArgs(args);
    }

    // zig build run-ecn-validation
    const run_ecn_validation = b.step("run-ecn-validation", "Run quicz ECN validation example");
    const run_ecn_validation_cmd = b.addRunArtifact(exe_ecn_validation);
    run_ecn_validation.dependOn(&run_ecn_validation_cmd.step);
    run_ecn_validation_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_ecn_validation_cmd.addArgs(args);
    }

    // zig build run-loss-recovery
    const run_loss_recovery = b.step("run-loss-recovery", "Run quicz loss recovery example");
    const run_loss_recovery_cmd = b.addRunArtifact(exe_loss_recovery);
    run_loss_recovery.dependOn(&run_loss_recovery_cmd.step);
    run_loss_recovery_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_loss_recovery_cmd.addArgs(args);
    }

    // zig build run-pto-recovery
    const run_pto_recovery = b.step("run-pto-recovery", "Run quicz PTO recovery example");
    const run_pto_recovery_cmd = b.addRunArtifact(exe_pto_recovery);
    run_pto_recovery.dependOn(&run_pto_recovery_cmd.step);
    run_pto_recovery_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_pto_recovery_cmd.addArgs(args);
    }

    // zig build run-endpoint-recovery-timers
    const run_endpoint_recovery_timers = b.step("run-endpoint-recovery-timers", "Run quicz endpoint recovery timer example");
    const run_endpoint_recovery_timers_cmd = b.addRunArtifact(exe_endpoint_recovery_timers);
    run_endpoint_recovery_timers.dependOn(&run_endpoint_recovery_timers_cmd.step);
    run_endpoint_recovery_timers_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_endpoint_recovery_timers_cmd.addArgs(args);
    }

    // zig build run-path-validation
    const run_path_validation = b.step("run-path-validation", "Run quicz path validation example");
    const run_path_validation_cmd = b.addRunArtifact(exe_path_validation);
    run_path_validation.dependOn(&run_path_validation_cmd.step);
    run_path_validation_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_path_validation_cmd.addArgs(args);
    }

    // zig build run-address-validation
    const run_address_validation = b.step("run-address-validation", "Run quicz address validation example");
    const run_address_validation_cmd = b.addRunArtifact(exe_address_validation);
    run_address_validation.dependOn(&run_address_validation_cmd.step);
    run_address_validation_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_address_validation_cmd.addArgs(args);
    }

    // zig build run-udp-address-validation-loopback
    const run_udp_address_validation_loopback = b.step("run-udp-address-validation-loopback", "Run quicz UDP address validation loopback example");
    const run_udp_address_validation_loopback_cmd = b.addRunArtifact(exe_udp_address_validation_loopback);
    run_udp_address_validation_loopback.dependOn(&run_udp_address_validation_loopback_cmd.step);
    run_udp_address_validation_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_address_validation_loopback_cmd.addArgs(args);
    }

    // zig build run-retry-token
    const run_retry_token = b.step("run-retry-token", "Run quicz Retry token example");
    const run_retry_token_cmd = b.addRunArtifact(exe_retry_token);
    run_retry_token.dependOn(&run_retry_token_cmd.step);
    run_retry_token_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_retry_token_cmd.addArgs(args);
    }

    // zig build run-connection-ids
    const run_connection_ids = b.step("run-connection-ids", "Run quicz connection ID example");
    const run_connection_ids_cmd = b.addRunArtifact(exe_connection_ids);
    run_connection_ids.dependOn(&run_connection_ids_cmd.step);
    run_connection_ids_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_connection_ids_cmd.addArgs(args);
    }

    // zig build run-stateless-reset
    const run_stateless_reset = b.step("run-stateless-reset", "Run quicz stateless reset example");
    const run_stateless_reset_cmd = b.addRunArtifact(exe_stateless_reset);
    run_stateless_reset.dependOn(&run_stateless_reset_cmd.step);
    run_stateless_reset_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_stateless_reset_cmd.addArgs(args);
    }

    // zig build run-initial-keys
    const run_initial_keys = b.step("run-initial-keys", "Run quicz Initial key derivation example");
    const run_initial_keys_cmd = b.addRunArtifact(exe_initial_keys);
    run_initial_keys.dependOn(&run_initial_keys_cmd.step);
    run_initial_keys_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_initial_keys_cmd.addArgs(args);
    }

    // zig build run-endpoint-routing
    const run_endpoint_routing = b.step("run-endpoint-routing", "Run quicz endpoint routing example");
    const run_endpoint_routing_cmd = b.addRunArtifact(exe_endpoint_routing);
    run_endpoint_routing.dependOn(&run_endpoint_routing_cmd.step);
    run_endpoint_routing_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_endpoint_routing_cmd.addArgs(args);
    }

    // zig build run-udp-endpoint-loopback
    const run_udp_endpoint_loopback = b.step("run-udp-endpoint-loopback", "Run quicz UDP endpoint loopback example");
    const run_udp_endpoint_loopback_cmd = b.addRunArtifact(exe_udp_endpoint_loopback);
    run_udp_endpoint_loopback.dependOn(&run_udp_endpoint_loopback_cmd.step);
    run_udp_endpoint_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_endpoint_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-zero-cid-loopback
    const run_udp_zero_cid_loopback = b.step("run-udp-zero-cid-loopback", "Run quicz UDP zero-length CID loopback example");
    const run_udp_zero_cid_loopback_cmd = b.addRunArtifact(exe_udp_zero_cid_loopback);
    run_udp_zero_cid_loopback.dependOn(&run_udp_zero_cid_loopback_cmd.step);
    run_udp_zero_cid_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_zero_cid_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-preferred-address-loopback
    const run_udp_preferred_address_loopback = b.step("run-udp-preferred-address-loopback", "Run quicz UDP preferred-address loopback example");
    const run_udp_preferred_address_loopback_cmd = b.addRunArtifact(exe_udp_preferred_address_loopback);
    run_udp_preferred_address_loopback.dependOn(&run_udp_preferred_address_loopback_cmd.step);
    run_udp_preferred_address_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_preferred_address_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-replacement-cid-loopback
    const run_udp_replacement_cid_loopback = b.step("run-udp-replacement-cid-loopback", "Run quicz UDP replacement CID loopback example");
    const run_udp_replacement_cid_loopback_cmd = b.addRunArtifact(exe_udp_replacement_cid_loopback);
    run_udp_replacement_cid_loopback.dependOn(&run_udp_replacement_cid_loopback_cmd.step);
    run_udp_replacement_cid_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_replacement_cid_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-connection-ids-loopback
    const run_udp_connection_ids_loopback = b.step("run-udp-connection-ids-loopback", "Run quicz UDP connection ID loopback example");
    const run_udp_connection_ids_loopback_cmd = b.addRunArtifact(exe_udp_connection_ids_loopback);
    run_udp_connection_ids_loopback.dependOn(&run_udp_connection_ids_loopback_cmd.step);
    run_udp_connection_ids_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_connection_ids_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-flow-control-loopback
    const run_udp_flow_control_loopback = b.step("run-udp-flow-control-loopback", "Run quicz UDP flow-control loopback example");
    const run_udp_flow_control_loopback_cmd = b.addRunArtifact(exe_udp_flow_control_loopback);
    run_udp_flow_control_loopback.dependOn(&run_udp_flow_control_loopback_cmd.step);
    run_udp_flow_control_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_flow_control_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-spin-bit-loopback
    const run_udp_spin_bit_loopback = b.step("run-udp-spin-bit-loopback", "Run quicz UDP spin-bit loopback example");
    const run_udp_spin_bit_loopback_cmd = b.addRunArtifact(exe_udp_spin_bit_loopback);
    run_udp_spin_bit_loopback.dependOn(&run_udp_spin_bit_loopback_cmd.step);
    run_udp_spin_bit_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_spin_bit_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-ecn-validation-loopback
    const run_udp_ecn_validation_loopback = b.step("run-udp-ecn-validation-loopback", "Run quicz UDP ECN validation loopback example");
    const run_udp_ecn_validation_loopback_cmd = b.addRunArtifact(exe_udp_ecn_validation_loopback);
    run_udp_ecn_validation_loopback.dependOn(&run_udp_ecn_validation_loopback_cmd.step);
    run_udp_ecn_validation_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_ecn_validation_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-pto-recovery-loopback
    const run_udp_pto_recovery_loopback = b.step("run-udp-pto-recovery-loopback", "Run quicz UDP PTO recovery loopback example");
    const run_udp_pto_recovery_loopback_cmd = b.addRunArtifact(exe_udp_pto_recovery_loopback);
    run_udp_pto_recovery_loopback.dependOn(&run_udp_pto_recovery_loopback_cmd.step);
    run_udp_pto_recovery_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_pto_recovery_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-loss-recovery-loopback
    const run_udp_loss_recovery_loopback = b.step("run-udp-loss-recovery-loopback", "Run quicz UDP loss recovery loopback example");
    const run_udp_loss_recovery_loopback_cmd = b.addRunArtifact(exe_udp_loss_recovery_loopback);
    run_udp_loss_recovery_loopback.dependOn(&run_udp_loss_recovery_loopback_cmd.step);
    run_udp_loss_recovery_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_loss_recovery_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-stream-retransmission-loopback
    const run_udp_stream_retransmission_loopback = b.step("run-udp-stream-retransmission-loopback", "Run quicz UDP STREAM retransmission loopback example");
    const run_udp_stream_retransmission_loopback_cmd = b.addRunArtifact(exe_udp_stream_retransmission_loopback);
    run_udp_stream_retransmission_loopback.dependOn(&run_udp_stream_retransmission_loopback_cmd.step);
    run_udp_stream_retransmission_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_stream_retransmission_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-congestion-recovery-loopback
    const run_udp_congestion_recovery_loopback = b.step("run-udp-congestion-recovery-loopback", "Run quicz UDP congestion recovery loopback example");
    const run_udp_congestion_recovery_loopback_cmd = b.addRunArtifact(exe_udp_congestion_recovery_loopback);
    run_udp_congestion_recovery_loopback.dependOn(&run_udp_congestion_recovery_loopback_cmd.step);
    run_udp_congestion_recovery_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_congestion_recovery_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-protected-loopback
    const run_udp_protected_loopback = b.step("run-udp-protected-loopback", "Run quicz UDP protected-packet loopback example");
    const run_udp_protected_loopback_cmd = b.addRunArtifact(exe_udp_protected_loopback);
    run_udp_protected_loopback.dependOn(&run_udp_protected_loopback_cmd.step);
    run_udp_protected_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_protected_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-handshake-keys-loopback
    const run_udp_handshake_keys_loopback = b.step("run-udp-handshake-keys-loopback", "Run quicz UDP Handshake keys loopback example");
    const run_udp_handshake_keys_loopback_cmd = b.addRunArtifact(exe_udp_handshake_keys_loopback);
    run_udp_handshake_keys_loopback.dependOn(&run_udp_handshake_keys_loopback_cmd.step);
    run_udp_handshake_keys_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_handshake_keys_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-crypto-stream-loopback
    const run_udp_crypto_stream_loopback = b.step("run-udp-crypto-stream-loopback", "Run quicz UDP CryptoBackend CRYPTO stream loopback example");
    const run_udp_crypto_stream_loopback_cmd = b.addRunArtifact(exe_udp_crypto_stream_loopback);
    run_udp_crypto_stream_loopback.dependOn(&run_udp_crypto_stream_loopback_cmd.step);
    run_udp_crypto_stream_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_crypto_stream_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-zero-rtt-loopback
    const run_udp_zero_rtt_loopback = b.step("run-udp-zero-rtt-loopback", "Run quicz UDP 0-RTT loopback example");
    const run_udp_zero_rtt_loopback_cmd = b.addRunArtifact(exe_udp_zero_rtt_loopback);
    run_udp_zero_rtt_loopback.dependOn(&run_udp_zero_rtt_loopback_cmd.step);
    run_udp_zero_rtt_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_zero_rtt_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-one-rtt-loopback
    const run_udp_one_rtt_loopback = b.step("run-udp-one-rtt-loopback", "Run quicz UDP 1-RTT loopback example");
    const run_udp_one_rtt_loopback_cmd = b.addRunArtifact(exe_udp_one_rtt_loopback);
    run_udp_one_rtt_loopback.dependOn(&run_udp_one_rtt_loopback_cmd.step);
    run_udp_one_rtt_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_one_rtt_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-echo-loopback
    const run_udp_echo_loopback = b.step("run-udp-echo-loopback", "Run quicz UDP echo loopback example");
    const run_udp_echo_loopback_cmd = b.addRunArtifact(exe_udp_echo_loopback);
    run_udp_echo_loopback.dependOn(&run_udp_echo_loopback_cmd.step);
    run_udp_echo_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_echo_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-crypto-backend-loopback
    const run_udp_crypto_backend_loopback = b.step("run-udp-crypto-backend-loopback", "Run quicz UDP CryptoBackend loopback example");
    const run_udp_crypto_backend_loopback_cmd = b.addRunArtifact(exe_udp_crypto_backend_loopback);
    run_udp_crypto_backend_loopback.dependOn(&run_udp_crypto_backend_loopback_cmd.step);
    run_udp_crypto_backend_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_crypto_backend_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-handshake-done-loopback
    const run_udp_handshake_done_loopback = b.step("run-udp-handshake-done-loopback", "Run quicz UDP HANDSHAKE_DONE loopback example");
    const run_udp_handshake_done_loopback_cmd = b.addRunArtifact(exe_udp_handshake_done_loopback);
    run_udp_handshake_done_loopback.dependOn(&run_udp_handshake_done_loopback_cmd.step);
    run_udp_handshake_done_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_handshake_done_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-key-update-loopback
    const run_udp_key_update_loopback = b.step("run-udp-key-update-loopback", "Run quicz UDP key update loopback example");
    const run_udp_key_update_loopback_cmd = b.addRunArtifact(exe_udp_key_update_loopback);
    run_udp_key_update_loopback.dependOn(&run_udp_key_update_loopback_cmd.step);
    run_udp_key_update_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_key_update_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-path-validation-loopback
    const run_udp_path_validation_loopback = b.step("run-udp-path-validation-loopback", "Run quicz UDP path validation loopback example");
    const run_udp_path_validation_loopback_cmd = b.addRunArtifact(exe_udp_path_validation_loopback);
    run_udp_path_validation_loopback.dependOn(&run_udp_path_validation_loopback_cmd.step);
    run_udp_path_validation_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_path_validation_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-retry-loopback
    const run_udp_retry_loopback = b.step("run-udp-retry-loopback", "Run quicz UDP Retry loopback example");
    const run_udp_retry_loopback_cmd = b.addRunArtifact(exe_udp_retry_loopback);
    run_udp_retry_loopback.dependOn(&run_udp_retry_loopback_cmd.step);
    run_udp_retry_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_retry_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-close-lifecycle-loopback
    const run_udp_close_lifecycle_loopback = b.step("run-udp-close-lifecycle-loopback", "Run quicz UDP close lifecycle loopback example");
    const run_udp_close_lifecycle_loopback_cmd = b.addRunArtifact(exe_udp_close_lifecycle_loopback);
    run_udp_close_lifecycle_loopback.dependOn(&run_udp_close_lifecycle_loopback_cmd.step);
    run_udp_close_lifecycle_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_close_lifecycle_loopback_cmd.addArgs(args);
    }

    // zig build run-udp-stateless-reset-loopback
    const run_udp_stateless_reset_loopback = b.step("run-udp-stateless-reset-loopback", "Run quicz UDP stateless reset loopback example");
    const run_udp_stateless_reset_loopback_cmd = b.addRunArtifact(exe_udp_stateless_reset_loopback);
    run_udp_stateless_reset_loopback.dependOn(&run_udp_stateless_reset_loopback_cmd.step);
    run_udp_stateless_reset_loopback_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_udp_stateless_reset_loopback_cmd.addArgs(args);
    }

    const lib_tests = b.addTest(.{
        .name = "quicz-tests",
        .root_module = quicz_mod,
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const test_step = b.step("test", "Run quicz unit tests");
    test_step.dependOn(&run_lib_tests.step);
}
