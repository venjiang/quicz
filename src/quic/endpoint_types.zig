const address_validation_token = @import("address_validation_token.zig");
const connection_config = @import("connection_config.zig");
const crypto_types = @import("crypto_types.zig");
const endpoint = @import("endpoint.zig");
const packet = @import("packet.zig");
const transport_types = @import("transport_types.zig");

const Config = connection_config.Config;
const CryptoBackendProgress = crypto_types.CryptoBackendProgress;
const Error = transport_types.Error;
const LossDetectionTimerDeadline = transport_types.LossDetectionTimerDeadline;
const PacketNumberSpace = transport_types.PacketNumberSpace;

/// Result of retiring one endpoint connection handle.
pub const EndpointConnectionRetireResult = struct {
    /// Number of active destination-CID routes removed for the connection.
    routes_retired: usize,
    /// Whether an armed loss/PTO timer was removed for the connection.
    recovery_timer_disarmed: bool,
};

/// Endpoint result after processing a client-side Version Negotiation response.
pub const EndpointVersionNegotiationResult = struct {
    /// Version selected from the validated Version Negotiation packet.
    selected_version: packet.Version,
    /// Config for the follow-up client connection attempt using that version.
    followup_config: Config,
    /// Route and timer cleanup applied to the superseded connection attempt.
    retired: EndpointConnectionRetireResult,
};

/// Endpoint result after accepting Version Negotiation and registering follow-up routing.
pub const EndpointVersionNegotiationFollowupResult = struct {
    /// Version Negotiation processing result, including selected version and old route cleanup.
    version_negotiation: EndpointVersionNegotiationResult,
    /// Route installed for the next client Initial Source CID.
    followup_route: endpoint.RouteResult,
};

/// Errors returned while coordinating endpoint-owned Version Negotiation follow-up state.
pub const EndpointVersionNegotiationError = Error || endpoint.RouteError;

/// Errors returned while coordinating endpoint-owned protected Initial accept state.
pub const EndpointProtectedInitialError = Error || endpoint.RouteError;

/// Errors returned while accepting endpoint-owned Retry follow-up Initials.
pub const EndpointRetryProtectedInitialError = EndpointProtectedInitialError || address_validation_token.Error;

/// Errors returned while coordinating routed protected endpoint datagrams.
pub const EndpointProtectedDatagramError = Error || endpoint.RouteError;

/// Errors returned while validating endpoint-owned address tokens.
pub const EndpointAddressValidationError = Error || address_validation_token.Error;

/// Errors returned while coordinating endpoint-owned connection ID lifecycle.
pub const EndpointConnectionIdError = Error || endpoint.RouteError;

/// Endpoint route policy for a locally issued connection ID.
pub const EndpointIssuedConnectionIdOptions = struct {
    /// Reject packets from a different UDP tuple while active migration is disabled.
    active_migration_disabled: bool = false,
};

/// Result of issuing a local connection ID and registering its endpoint route.
pub const EndpointIssuedConnectionIdResult = struct {
    /// NEW_CONNECTION_ID sequence number assigned by the connection.
    sequence_number: u64,
    /// Retire Prior To threshold applied to endpoint routes.
    retire_prior_to: u64,
    /// Number of older endpoint routes retired by the threshold.
    retired_count: usize,
};

/// Endpoint result after accepting and processing a protected client Initial.
pub const EndpointAcceptedProtectedInitialResult = struct {
    /// Endpoint accept metadata borrowed from the triggering datagram.
    initial_accept: endpoint.InitialAcceptResult,
    /// Routes installed after packet authentication succeeds.
    accepted_routes: endpoint.AcceptedInitialRouteResult,
    /// Number of protected long packets processed from the datagram.
    processed_packets: usize,
};

/// Endpoint result after routing and processing protected long packets.
pub const EndpointProtectedLongDatagramResult = struct {
    /// Endpoint route selected for the triggering datagram.
    route: endpoint.RouteResult,
    /// Number of protected long packets processed from the datagram.
    processed_packets: usize,
};

/// Endpoint result after routing caller-keyed long input through backend drive.
pub const EndpointRoutedCryptoBackendDriveProtectedLongDatagramResult = struct {
    /// Endpoint route selected for the triggering datagram.
    route: endpoint.RouteResult,
    /// Backend drive and caller-keyed long-header output poll result.
    backend: EndpointCryptoBackendDriveProtectedLongDatagramResult,
};

/// Endpoint result after routing caller-keyed long input through backend drive.
pub const EndpointRoutedCryptoBackendDriveProtectedLongDatagramDrainResult = struct {
    /// Endpoint route selected for the triggering datagram.
    route: endpoint.RouteResult,
    /// Backend drive and bounded caller-keyed long-header output drain result.
    backend: EndpointCryptoBackendDriveProtectedLongDatagramDrainResult,
};

/// Endpoint result after routing installed-key input through backend drive.
pub const EndpointRoutedCryptoBackendDriveDatagramResult = struct {
    /// Endpoint route selected for the triggering datagram.
    route: endpoint.RouteResult,
    /// Backend drive and installed-key output poll result.
    backend: EndpointCryptoBackendDriveDatagramResult,
};

/// Endpoint result after routing installed-key input through backend drive.
pub const EndpointRoutedCryptoBackendDriveDatagramDrainResult = struct {
    /// Endpoint route selected for the triggering datagram.
    route: endpoint.RouteResult,
    /// Backend drive and bounded installed-key output drain result.
    backend: EndpointCryptoBackendDriveDatagramDrainResult,
};

/// Endpoint result after routing installed-key input through backend drive.
pub const EndpointRoutedCryptoBackendDriveNextDeadlineResult = struct {
    /// Endpoint route selected for the triggering datagram.
    route: endpoint.RouteResult,
    /// Backend drive and next wakeup selection result.
    backend: EndpointCryptoBackendDriveNextDeadlineResult,
};

/// Endpoint result after routing input and polling installed-key output.
pub const EndpointRoutedDatagramResult = struct {
    /// Endpoint route selected for the triggering datagram.
    route: endpoint.RouteResult,
    /// Installed-key output emitted after receive processing, if any.
    datagram: ?EndpointPolledDatagramResult = null,
};

/// Endpoint result after routing input and draining installed-key output.
pub const EndpointRoutedDatagramDrainResult = struct {
    /// Endpoint route selected for the triggering datagram.
    route: endpoint.RouteResult,
    /// Bounded installed-key output drain result after receive processing.
    drain: EndpointDatagramDrainResult,
};

/// Endpoint result after routing input and selecting the next wakeup.
pub const EndpointRoutedNextDeadlineResult = struct {
    /// Endpoint route selected for the triggering datagram.
    route: endpoint.RouteResult,
    /// Earliest endpoint-visible deadline after receive processing.
    next_deadline: ?EndpointConnectionDeadline,
};

/// Endpoint result after processing a path-validation protected short datagram.
pub const EndpointPathValidatedShortDatagramResult = struct {
    /// Endpoint route selected before packet protection was removed.
    route: endpoint.RouteResult,
    /// Route after endpoint path update, present only when validation completed.
    updated_route: ?endpoint.RouteResult,
};

/// Endpoint result from servicing a 1-RTT recovery timer and polling a probe.
pub const EndpointProtectedShortRecoveryPollResult = struct {
    /// Due recovery timer that was serviced, or null when called before deadline.
    serviced: ?EndpointLossDetectionTimerDeadline,
    /// Protected short-header datagram emitted after servicing, if any.
    datagram: ?[]u8,
};

/// Endpoint result from servicing an Initial/Handshake timer and polling a probe.
pub const EndpointProtectedLongRecoveryPollResult = struct {
    /// Due recovery timer that was serviced, or null when called before deadline.
    serviced: ?EndpointLossDetectionTimerDeadline,
    /// Protected long-header datagram emitted after servicing, if any.
    datagram: ?[]u8,
};

/// Endpoint-owned scheduled loss detection timer for one connection handle.
pub const EndpointLossDetectionTimerDeadline = struct {
    /// Caller-owned connection handle used by endpoint routing and event loops.
    connection_id: u64,
    /// Connection-level aggregate loss/PTO timer snapshot.
    timer: LossDetectionTimerDeadline,
};

/// Endpoint timer kind a socket loop can wait on for one connection handle.
pub const EndpointConnectionDeadlineKind = enum {
    /// Connection idle timeout should be checked at the deadline.
    idle_timeout,
    /// Closing or draining timeout should be checked at the deadline.
    close_timeout,
    /// QUIC loss/PTO recovery timer should be serviced at the deadline.
    recovery,
    /// Retained 1-RTT keys should be discarded after their PTO retain window.
    key_discard,
};

/// Earliest endpoint-visible deadline for one caller-owned connection.
pub const EndpointConnectionDeadline = struct {
    /// Caller-owned connection handle used by endpoint routing and timers.
    connection_id: u64,
    /// Absolute deadline in the connection's caller-controlled millisecond clock.
    deadline_millis: i64,
    /// Timer class that owns the deadline.
    kind: EndpointConnectionDeadlineKind,
    /// Recovery timer detail, present only when `kind` is `.recovery`.
    recovery: ?LossDetectionTimerDeadline = null,

    /// Derive installed-key poll options for a recovery deadline.
    ///
    /// Initial recovery cannot use installed-key packetization. Application
    /// recovery maps to the 1-RTT short-packet path; callers that are still
    /// servicing 0-RTT PTO should pass explicit `.zero_rtt` options instead.
    pub fn installedKeyPollOptions(
        self: EndpointConnectionDeadline,
        destination_connection_id: []const u8,
        source_connection_id: []const u8,
    ) ?EndpointPollInstalledKeyDatagramOptions {
        if (self.kind != .recovery) return null;
        const timer = self.recovery orelse return null;
        return EndpointPollInstalledKeyDatagramOptions.fromRecoveryDeadline(
            timer,
            destination_connection_id,
            source_connection_id,
        );
    }
};

/// Packet-number-space choice for endpoint installed-key datagram polling.
pub const EndpointInstalledKeyDatagramSpace = enum {
    /// Poll a Handshake long-header datagram with connection-installed keys.
    handshake,
    /// Poll a 0-RTT long-header datagram with connection-installed keys.
    zero_rtt,
    /// Poll a 1-RTT short-header datagram with connection-installed keys.
    application,
};

/// Options for polling a datagram after the connection owns packet-protection keys.
pub const EndpointPollInstalledKeyDatagramOptions = struct {
    /// Packet-number-space/header family to poll.
    space: EndpointInstalledKeyDatagramSpace,
    /// Destination connection ID to encode in the emitted packet.
    destination_connection_id: []const u8,
    /// Source connection ID for long-header Handshake/0-RTT packets.
    source_connection_id: []const u8 = &[_]u8{},

    /// Build installed-key poll options from a loss/PTO recovery deadline.
    ///
    /// Initial recovery returns null because Initial packetization does not use
    /// installed TLS traffic secrets. Application recovery maps to 1-RTT; use
    /// explicit `.zero_rtt` options when servicing accepted early data.
    pub fn fromRecoveryDeadline(
        timer: LossDetectionTimerDeadline,
        destination_connection_id: []const u8,
        source_connection_id: []const u8,
    ) ?EndpointPollInstalledKeyDatagramOptions {
        return switch (timer.space) {
            .initial => null,
            .handshake => .{
                .space = .handshake,
                .destination_connection_id = destination_connection_id,
                .source_connection_id = source_connection_id,
            },
            .application => .{
                .space = .application,
                .destination_connection_id = destination_connection_id,
            },
        };
    }

    /// Packet-number-space whose recovery deadline can emit these options.
    ///
    /// 0-RTT and 1-RTT share Application recovery state even though they use
    /// different installed-key packetization paths.
    pub fn recoveryPacketNumberSpace(self: EndpointPollInstalledKeyDatagramOptions) PacketNumberSpace {
        return switch (self.space) {
            .handshake => .handshake,
            .zero_rtt, .application => .application,
        };
    }
};

/// Options for feeding a datagram after the connection owns packet-protection keys.
pub const EndpointFeedInstalledKeyDatagramOptions = struct {
    /// Packet-number-space/header family expected for routed datagram processing.
    space: EndpointInstalledKeyDatagramSpace,
    /// Scratch output buffer for Version Negotiation or stateless reset actions.
    out: []u8,
    /// Endpoint entropy used when constructing stateless reset datagrams.
    unpredictable_prefix: []const u8,
    /// Versions supported by this endpoint for Initial accept/VN classification.
    supported_versions: []const packet.Version,
    /// Optional PATH_CHALLENGE payload to queue after receiving from a changed path.
    path_challenge_data: ?[8]u8 = null,
};

/// Result from one socket-loop pending-work pass for a connection handle.
pub const EndpointPendingWorkResult = struct {
    /// Endpoint state retired because idle timeout closed the connection.
    idle_retired: ?EndpointConnectionRetireResult = null,
    /// Endpoint state retired because close/drain timeout closed the connection.
    close_retired: ?EndpointConnectionRetireResult = null,
    /// Loss/PTO timer serviced for the connection, if due.
    recovery_serviced: ?EndpointLossDetectionTimerDeadline = null,
};

/// Result from processing pending endpoint work and polling a recovery datagram.
pub const EndpointPendingWorkDatagramResult = struct {
    /// Pending-work actions applied before polling output.
    pending_work: EndpointPendingWorkResult,
    /// Protected datagram emitted after a due recovery timer, if any.
    datagram: ?[]u8 = null,
    /// Next endpoint-visible deadline after pending work and optional output poll.
    next_deadline: ?EndpointConnectionDeadline = null,
};

/// Result from processing pending endpoint work and draining recovery output.
pub const EndpointPendingWorkDatagramDrainResult = struct {
    /// Pending-work actions applied before draining output.
    pending_work: EndpointPendingWorkResult,
    /// Bounded output drain result after a due recovery timer.
    drain: EndpointDatagramDrainResult,
    /// Next endpoint-visible deadline after pending work and output drain.
    next_deadline: ?EndpointConnectionDeadline = null,
};

/// Summary from sweeping pending work across caller-owned connections.
pub const EndpointPendingWorkSweepResult = struct {
    /// Number of connection handles retired by idle timeout.
    idle_retired_count: usize = 0,
    /// Number of connection handles retired by close/drain timeout.
    close_retired_count: usize = 0,
    /// Number of due loss/PTO timers serviced.
    recovery_serviced_count: usize = 0,
};

/// Result from a pending-work sweep followed by next wakeup selection.
pub const EndpointPendingWorkNextDeadlineResult = struct {
    /// Pending-work actions applied before selecting the next deadline.
    pending_work: EndpointPendingWorkSweepResult,
    /// Next endpoint-visible deadline after pending work has been applied.
    next_deadline: ?EndpointConnectionDeadline = null,
};

/// Result from a pending-work sweep followed by output polling.
pub const EndpointPendingWorkSweepDatagramResult = struct {
    /// Pending-work actions applied before output processing.
    pending_work: EndpointPendingWorkSweepResult,
    /// Protected datagram emitted after pending recovery work, if any.
    datagram: ?EndpointPolledDatagramResult = null,
    /// Next endpoint-visible deadline after pending work and optional output poll.
    next_deadline: ?EndpointConnectionDeadline = null,
};

/// Result from a pending-work sweep followed by bounded output draining.
pub const EndpointPendingWorkSweepDatagramDrainResult = struct {
    /// Pending-work actions applied before output processing.
    pending_work: EndpointPendingWorkSweepResult,
    /// Bounded output drain result after pending recovery work.
    drain: EndpointDatagramDrainResult,
    /// Next endpoint-visible deadline after pending work and output drain.
    next_deadline: ?EndpointConnectionDeadline = null,
};

/// Result from pending-work sweep followed by backend drive and output polling.
pub const EndpointPendingWorkCryptoBackendDatagramResult = struct {
    /// Pending-work actions applied before backend/output processing.
    pending_work: EndpointPendingWorkSweepResult,
    /// Backend drive and output polling result.
    backend: EndpointCryptoBackendDriveDatagramResult,
};

/// Result from pending-work sweep followed by backend drive and output draining.
pub const EndpointPendingWorkCryptoBackendDatagramDrainResult = struct {
    /// Pending-work actions applied before backend/output processing.
    pending_work: EndpointPendingWorkSweepResult,
    /// Backend drive and bounded output drain result.
    backend: EndpointCryptoBackendDriveDatagramDrainResult,
};

/// Result from pending-work sweep followed by backend drive and deadline selection.
pub const EndpointPendingWorkCryptoBackendNextDeadlineResult = struct {
    /// Pending-work actions applied before backend/deadline processing.
    pending_work: EndpointPendingWorkSweepResult,
    /// Backend drive result and next endpoint-visible deadline.
    backend: EndpointCryptoBackendDriveNextDeadlineResult,
};

/// Summary from driving crypto backends across caller-owned connections.
pub const EndpointCryptoBackendDriveSweepResult = struct {
    /// Number of connection/backend pairs driven.
    connections_driven: usize = 0,
    /// Aggregated backend progress across all successfully driven connections.
    progress: CryptoBackendProgress = .{},
};

/// Result from one TLS backend sweep followed by next wakeup selection.
pub const EndpointCryptoBackendDriveNextDeadlineResult = struct {
    /// Backend drive progress collected before selecting the next deadline.
    backend: EndpointCryptoBackendDriveSweepResult,
    /// Next endpoint-visible deadline after backend progress has been applied.
    next_deadline: ?EndpointConnectionDeadline = null,
};

/// Result from one TLS backend sweep followed by installed-key datagram polling.
pub const EndpointCryptoBackendDriveDatagramResult = struct {
    /// Backend drive progress collected before polling output.
    backend: EndpointCryptoBackendDriveSweepResult,
    /// Protected datagram emitted after backend progress, if any.
    datagram: ?EndpointPolledDatagramResult = null,
};

/// Result from one backend drive followed by caller-keyed long-packet polling.
pub const EndpointCryptoBackendDriveProtectedLongDatagramResult = struct {
    /// Backend progress collected before polling output.
    backend: CryptoBackendProgress,
    /// Caller-keyed Initial/Handshake CRYPTO datagram emitted after backend progress, if any.
    datagram: ?EndpointPolledDatagramResult = null,
};

/// Result from one TLS backend sweep followed by bounded output draining.
pub const EndpointCryptoBackendDriveDatagramDrainResult = struct {
    /// Backend drive progress collected before draining output.
    backend: EndpointCryptoBackendDriveSweepResult,
    /// Bounded output drain result after backend progress.
    drain: EndpointDatagramDrainResult,
};

/// Result from one backend drive followed by caller-keyed long-packet draining.
pub const EndpointCryptoBackendDriveProtectedLongDatagramDrainResult = struct {
    /// Backend progress collected before draining output.
    backend: CryptoBackendProgress,
    /// Bounded caller-keyed Initial/Handshake CRYPTO output drain result.
    drain: EndpointDatagramDrainResult,
};

/// Result from polling installed-key output across caller-owned connections.
pub const EndpointPolledDatagramResult = struct {
    /// Caller-owned connection handle that produced `datagram`.
    connection_id: u64,
    /// Protected datagram emitted by the selected connection.
    datagram: []u8,
};

/// Result from draining installed-key datagrams into caller-owned result slots.
pub const EndpointDatagramDrainResult = struct {
    /// Number of initialized entries written to the caller-provided output slice.
    datagrams_written: usize = 0,
    /// First polling error observed after any earlier entries were written.
    ///
    /// Callers still own and must release `datagrams_written` entries even when
    /// this field is set.
    first_error: ?Error = null,
};

/// Result from servicing one due endpoint-visible deadline.
pub const EndpointDueWorkDatagramResult = struct {
    /// Deadline that was due when this pending-work pass started.
    deadline: EndpointConnectionDeadline,
    /// Pending-work actions applied for the due deadline.
    pending_work: EndpointPendingWorkResult,
    /// Protected datagram emitted after a due recovery timer, if any.
    datagram: ?[]u8 = null,
};

/// Result from servicing one due endpoint-visible deadline and draining output.
pub const EndpointDueWorkDatagramDrainResult = struct {
    /// Deadline that was due when this pending-work pass started.
    deadline: EndpointConnectionDeadline,
    /// Pending-work actions applied for the due deadline.
    pending_work: EndpointPendingWorkResult,
    /// Bounded output drain after a due recovery timer, if any.
    drain: EndpointDatagramDrainResult,
    /// Next endpoint-visible deadline after due work and output drain.
    next_deadline: ?EndpointConnectionDeadline = null,
};

/// Result from servicing one due deadline and selecting the next wakeup.
pub const EndpointDueWorkNextDeadlineResult = struct {
    /// Deadline that was due when this pending-work pass started.
    deadline: EndpointConnectionDeadline,
    /// Pending-work actions applied for the due deadline.
    pending_work: EndpointPendingWorkResult,
    /// Next endpoint-visible deadline after due work has been applied.
    next_deadline: ?EndpointConnectionDeadline = null,
};

/// Result from due-deadline work followed by backend drive and deadline selection.
pub const EndpointDueWorkCryptoBackendNextDeadlineResult = struct {
    /// Due-deadline work applied before optional backend/deadline processing.
    due_work: EndpointDueWorkNextDeadlineResult,
    /// Backend drive result and next endpoint-visible deadline when the due
    /// step left the selected connection live.
    backend: ?EndpointCryptoBackendDriveNextDeadlineResult = null,
};

/// Result from due-deadline work followed by optional backend/output processing.
pub const EndpointDueWorkCryptoBackendDatagramResult = struct {
    /// Due deadline work applied before backend/output processing.
    due_work: EndpointDueWorkDatagramResult,
    /// Backend drive and output polling result when the due step did not
    /// already emit a datagram.
    backend: ?EndpointCryptoBackendDriveDatagramResult = null,
};

/// Result from due-deadline work followed by optional backend/output draining.
pub const EndpointDueWorkCryptoBackendDatagramDrainResult = struct {
    /// Due deadline work applied before backend/output processing.
    due_work: EndpointDueWorkDatagramResult,
    /// Backend drive and bounded output drain result when the due step did not
    /// already emit a datagram.
    backend: ?EndpointCryptoBackendDriveDatagramDrainResult = null,
    /// Next endpoint-visible deadline after due work, backend progress, and drain.
    next_deadline: ?EndpointConnectionDeadline = null,
};

/// Result from feeding one socket datagram through installed-key receive paths.
pub const EndpointFeedInstalledKeyDatagramResult = union(enum) {
    /// Datagram was routed to and processed by the caller-owned connection.
    routed: endpoint.RouteResult,
    /// Datagram is a supported-version Initial for a new server connection.
    accept_initial: endpoint.InitialAcceptResult,
    /// Caller should send this Version Negotiation datagram on the same UDP path.
    version_negotiation: []const u8,
    /// Caller should send this stateless reset datagram on the same UDP path.
    stateless_reset: []const u8,
    /// Datagram should be dropped without connection delivery.
    dropped,
};

/// Result from feeding one socket datagram and optionally committing path migration.
pub const EndpointFeedInstalledKeyPathUpdateResult = struct {
    /// Receive classification and processing result.
    feed: EndpointFeedInstalledKeyDatagramResult,
    /// Route after endpoint path update, present only when validation completed.
    updated_route: ?endpoint.RouteResult = null,
    /// Whether a PATH_CHALLENGE was queued for a changed path.
    path_challenge_queued: bool = false,
    /// UDP tuple selected for immediate path-validation-related output.
    selected_output_path: ?endpoint.Udp4Tuple = null,
};

/// Result from feeding with path update, then polling installed-key output.
pub const EndpointFeedPathUpdateDatagramPollResult = struct {
    /// Receive, path-validation, and route-update result.
    feed: EndpointFeedInstalledKeyPathUpdateResult,
    /// Feed error surfaced as data after a close-propagating receive path.
    feed_error: ?EndpointProtectedDatagramError = null,
    /// Protected datagram emitted after receive processing, if any.
    datagram: ?EndpointPolledDatagramResult = null,
    /// UDP tuple selected for `datagram`.
    ///
    /// Path-validation probes use the candidate tuple; other output uses the
    /// current committed route.
    output_path: ?endpoint.Udp4Tuple = null,
    /// Next endpoint-visible deadline for the selected connection after feed and poll.
    next_deadline: ?EndpointConnectionDeadline = null,
};

/// Result from feeding one installed-key datagram, then selecting a wakeup.
pub const EndpointFeedInstalledKeyDatagramNextDeadlineResult = struct {
    /// Receive classification and processing result.
    feed: EndpointFeedInstalledKeyDatagramResult,
    /// Next endpoint-visible deadline after receive processing.
    next_deadline: ?EndpointConnectionDeadline = null,
};

/// Result from feeding one installed-key datagram, processing pending work, then selecting a wakeup.
pub const EndpointFeedPendingWorkNextDeadlineResult = struct {
    /// Receive classification and processing result.
    feed: EndpointFeedInstalledKeyDatagramResult,
    /// Pending-work actions applied after receive processing.
    pending_work: EndpointPendingWorkSweepResult,
    /// Next endpoint-visible deadline after receive and pending work.
    next_deadline: ?EndpointConnectionDeadline = null,
};

/// Result from feeding one installed-key datagram, processing pending work, then polling output.
pub const EndpointFeedPendingWorkDatagramPollResult = struct {
    /// Receive classification and processing result.
    feed: EndpointFeedInstalledKeyDatagramResult,
    /// Pending-work actions applied after receive processing.
    pending_work: EndpointPendingWorkSweepResult,
    /// Installed-key output emitted after receive and pending work, if any.
    datagram: ?EndpointPolledDatagramResult = null,
};

/// Result from feeding one installed-key datagram, processing pending work, then draining output.
pub const EndpointFeedPendingWorkDatagramDrainResult = struct {
    /// Receive classification and processing result.
    feed: EndpointFeedInstalledKeyDatagramResult,
    /// Pending-work actions applied after receive processing.
    pending_work: EndpointPendingWorkSweepResult,
    /// Bounded output drain after receive and pending work.
    drain: EndpointDatagramDrainResult,
};

/// Result from feeding one installed-key datagram, processing pending work, driving backend, then selecting a wakeup.
pub const EndpointFeedPendingWorkCryptoBackendNextDeadlineResult = struct {
    /// Receive classification and processing result.
    feed: EndpointFeedInstalledKeyDatagramResult,
    /// Pending-work actions applied after receive processing.
    pending_work: EndpointPendingWorkSweepResult,
    /// Backend drive progress when `feed` routed and pending work kept connections live.
    backend: ?EndpointCryptoBackendDriveSweepResult = null,
    /// Next endpoint-visible deadline after receive, pending work, and optional backend progress.
    next_deadline: ?EndpointConnectionDeadline = null,
};

/// Result from feeding one installed-key datagram, processing pending work, driving backend, then polling output.
pub const EndpointFeedPendingWorkCryptoBackendDatagramResult = struct {
    /// Receive classification and processing result.
    feed: EndpointFeedInstalledKeyDatagramResult,
    /// Pending-work actions applied after receive processing.
    pending_work: EndpointPendingWorkSweepResult,
    /// Backend drive and output result when `feed` routed and pending work kept connections live.
    backend: ?EndpointCryptoBackendDriveDatagramResult = null,
};

/// Result from feeding one installed-key datagram, processing pending work, driving backend, then draining output.
pub const EndpointFeedPendingWorkCryptoBackendDatagramDrainResult = struct {
    /// Receive classification and processing result.
    feed: EndpointFeedInstalledKeyDatagramResult,
    /// Pending-work actions applied after receive processing.
    pending_work: EndpointPendingWorkSweepResult,
    /// Backend drive and bounded output drain when `feed` routed and pending work kept connections live.
    backend: ?EndpointCryptoBackendDriveDatagramDrainResult = null,
};

/// Result from feeding one installed-key datagram, then polling output.
pub const EndpointFeedInstalledKeyDatagramPollResult = struct {
    /// Receive classification and processing result.
    feed: EndpointFeedInstalledKeyDatagramResult,
    /// Protected datagram emitted after receive processing, if any.
    datagram: ?EndpointPolledDatagramResult = null,
};

/// Result from feeding one installed-key datagram, then draining output.
pub const EndpointFeedInstalledKeyDatagramDrainResult = struct {
    /// Receive classification and processing result.
    feed: EndpointFeedInstalledKeyDatagramResult,
    /// Bounded output drain when `feed` routed to a connection.
    drain: ?EndpointDatagramDrainResult = null,
};

/// Result from feeding one installed-key datagram, then driving backend and selecting a wakeup.
pub const EndpointFeedCryptoBackendDriveNextDeadlineResult = struct {
    /// Receive classification and processing result.
    feed: EndpointFeedInstalledKeyDatagramResult,
    /// Backend drive and deadline selection result when `feed` routed to a connection.
    backend: ?EndpointCryptoBackendDriveNextDeadlineResult = null,
};

/// Result from feeding one installed-key datagram, then driving backend output.
pub const EndpointFeedCryptoBackendDriveDatagramResult = struct {
    /// Receive classification and processing result.
    feed: EndpointFeedInstalledKeyDatagramResult,
    /// Backend drive and output result when `feed` routed to a connection.
    backend: ?EndpointCryptoBackendDriveDatagramResult = null,
};

/// Result from feeding one installed-key datagram, then draining backend output.
pub const EndpointFeedCryptoBackendDriveDatagramDrainResult = struct {
    /// Receive classification and processing result.
    feed: EndpointFeedInstalledKeyDatagramResult,
    /// Backend drive and bounded output drain when `feed` routed to a connection.
    backend: ?EndpointCryptoBackendDriveDatagramDrainResult = null,
};

/// Endpoint result after accepting a protected Initial and emitting a response.
pub const EndpointAcceptedProtectedInitialResponseResult = struct {
    /// Authentication, packet processing, and route installation result.
    accepted_initial: EndpointAcceptedProtectedInitialResult,
    /// Caller-keyed protected server Initial response datagram.
    ///
    /// The caller owns these bytes and must free them with the same allocator
    /// used by `connection`.
    response_datagram: []u8,
};

/// Endpoint result after accepting a protected Initial and selecting a wakeup deadline.
pub const EndpointAcceptedInitialCryptoBackendNextDeadlineResult = struct {
    /// Authentication, packet processing, and route installation result.
    accepted_initial: EndpointAcceptedProtectedInitialResult,
    /// Initial-space backend progress after consuming received client CRYPTO.
    backend: CryptoBackendProgress,
    /// Next endpoint-visible deadline after backend progress has been applied.
    next_deadline: ?EndpointConnectionDeadline = null,
};

/// Endpoint result after accepting a protected Initial and driving a TLS backend.
pub const EndpointAcceptedInitialCryptoBackendDatagramResult = struct {
    /// Authentication, packet processing, and route installation result.
    accepted_initial: EndpointAcceptedProtectedInitialResult,
    /// Initial-space backend progress after consuming received client CRYPTO.
    backend: CryptoBackendProgress,
    /// Protected server Initial datagram emitted from backend-produced CRYPTO.
    ///
    /// The caller owns these bytes and must free them with the same allocator
    /// used by `connection`.
    response_datagram: ?[]u8 = null,
};

/// Endpoint result after accepting a protected Initial and draining TLS output.
pub const EndpointAcceptedInitialCryptoBackendDatagramDrainResult = struct {
    /// Authentication, packet processing, and route installation result.
    accepted_initial: EndpointAcceptedProtectedInitialResult,
    /// Initial-space backend progress after consuming received client CRYPTO.
    backend: CryptoBackendProgress,
    /// Bounded protected server Initial output drain result.
    drain: EndpointDatagramDrainResult,
};

/// Endpoint result after accepting a Retry follow-up protected Initial.
pub const EndpointRetryProtectedInitialResult = struct {
    /// Endpoint route selected by the Retry Source CID.
    route: endpoint.RouteResult,
    /// Initial accept metadata borrowed from the follow-up datagram.
    initial_accept: endpoint.InitialAcceptResult,
    /// Authenticated Retry token metadata returned by endpoint policy.
    token_validation: EndpointAddressValidationResult,
};

/// Endpoint result after validating an address token for one connection.
pub const EndpointAddressValidationResult = struct {
    /// Authenticated token metadata returned by endpoint policy.
    validation: address_validation_token.Validation,
    /// Current aggregate recovery timer after address validation unblocks sends.
    recovery_timer: ?LossDetectionTimerDeadline,
};
