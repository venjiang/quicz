//! Bounded, endpoint-owned storage for caller-defined connection records.
//!
//! The registry owns record allocation and retirement while the record type
//! retains protocol-specific state such as the TLS backend and peer address.
//! This keeps connection identity, lifecycle scheduling views, and record
//! destruction together without making the endpoint own a UDP socket.

const std = @import("std");
const root = @import("../lib.zig");

/// Build an endpoint-owned registry for one connection record type.
///
/// `connection_of` returns the embedded QUIC connection used to construct
/// lifecycle scheduling and receive views. `deinit_record` releases record
/// resources immediately before the registry frees its allocation.
pub fn EndpointConnectionRegistry(
    comptime Record: type,
    comptime connection_of: *const fn (*Record) *root.Connection,
    comptime deinit_record: *const fn (*Record) void,
) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        records: std.AutoHashMap(u64, *Record),
        max_records: usize,
        deadline_view_scratch: ?[]root.EndpointConnectionView,
        receive_view_scratch: ?[]root.EndpointConnectionReceiveView,
        poll_view_scratch: ?[]root.EndpointConnectionPollView,
        next_poll_index: usize,

        /// Create an empty registry. Record handles must be unique while active.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .records = std.AutoHashMap(u64, *Record).init(allocator),
                .max_records = std.math.maxInt(usize),
                .deadline_view_scratch = null,
                .receive_view_scratch = null,
                .poll_view_scratch = null,
                .next_poll_index = 0,
            };
        }

        /// Create a registry that rejects new records once `max_records` are active.
        ///
        /// Fixed-capacity registries allocate lifecycle view scratch space once,
        /// so receive and deadline paths do not allocate per datagram.
        pub fn initWithCapacity(allocator: std.mem.Allocator, max_records: usize) !Self {
            const record_capacity = std.math.cast(u32, max_records) orelse return error.CapacityOverflow;
            const deadline_view_scratch = try allocator.alloc(root.EndpointConnectionView, max_records);
            errdefer allocator.free(deadline_view_scratch);
            const receive_view_scratch = try allocator.alloc(root.EndpointConnectionReceiveView, max_records);
            errdefer allocator.free(receive_view_scratch);
            const poll_view_scratch = try allocator.alloc(root.EndpointConnectionPollView, max_records);
            errdefer allocator.free(poll_view_scratch);
            var records = std.AutoHashMap(u64, *Record).init(allocator);
            errdefer records.deinit();
            try records.ensureTotalCapacity(record_capacity);
            return .{
                .allocator = allocator,
                .records = records,
                .max_records = max_records,
                .deadline_view_scratch = deadline_view_scratch,
                .receive_view_scratch = receive_view_scratch,
                .poll_view_scratch = poll_view_scratch,
                .next_poll_index = 0,
            };
        }

        /// Release every active record and the registry index.
        pub fn deinit(self: *Self) void {
            var iterator = self.records.valueIterator();
            while (iterator.next()) |record| {
                deinit_record(record.*);
                self.allocator.destroy(record.*);
            }
            self.records.deinit();
            if (self.deadline_view_scratch) |views| self.allocator.free(views);
            if (self.receive_view_scratch) |views| self.allocator.free(views);
            if (self.poll_view_scratch) |views| self.allocator.free(views);
        }

        /// Return the number of active records.
        pub fn count(self: *const Self) usize {
            return self.records.count();
        }

        /// Return the number of records that have not reached the closed state.
        pub fn activeCount(self: *const Self) usize {
            var active_count: usize = 0;
            var iterator = self.records.valueIterator();
            while (iterator.next()) |record| {
                if (connection_of(record.*).connectionState() != .closed) {
                    active_count += 1;
                }
            }
            return active_count;
        }

        /// Return the configured active-record limit.
        ///
        /// Dynamically sized registries report `std.math.maxInt(usize)`.
        pub fn capacityLimit(self: *const Self) usize {
            return self.max_records;
        }

        /// Return whether this registry can own one additional record.
        pub fn hasCapacity(self: *const Self) bool {
            return self.count() < self.max_records;
        }

        /// Return whether this registry can accept a new active record after
        /// already closed records are reclaimed.
        pub fn hasActiveCapacity(self: *const Self) bool {
            return self.activeCount() < self.max_records;
        }

        /// Write active endpoint connection handles into caller-owned storage.
        pub fn fillConnectionIds(self: *Self, out: []u64) root.Error![]u64 {
            if (out.len < self.count()) return error.BufferTooSmall;
            var iterator = self.records.keyIterator();
            var index: usize = 0;
            while (iterator.next()) |connection_id| : (index += 1) {
                out[index] = connection_id.*;
            }
            return out[0..index];
        }

        /// Write non-closed endpoint connection handles into caller-owned storage.
        pub fn fillActiveConnectionIds(self: *const Self, out: []u64) root.Error![]u64 {
            if (out.len < self.activeCount()) return error.BufferTooSmall;
            var iterator = self.records.iterator();
            var index: usize = 0;
            while (iterator.next()) |entry| {
                if (connection_of(entry.value_ptr.*).connectionState() == .closed) continue;
                out[index] = entry.key_ptr.*;
                index += 1;
            }
            return out[0..index];
        }

        /// Find one active record by its endpoint connection handle.
        pub fn get(self: *const Self, connection_id: u64) ?*Record {
            return self.records.get(connection_id);
        }

        /// Return an iterator over active records.
        pub fn valueIterator(self: *Self) std.AutoHashMap(u64, *Record).ValueIterator {
            return self.records.valueIterator();
        }

        /// Transfer a record allocated with this registry's allocator into endpoint ownership.
        ///
        /// On error the caller retains ownership of `record` and must destroy it.
        pub fn adopt(self: *Self, connection_id: u64, record: *Record) !void {
            if (self.records.contains(connection_id)) return error.DuplicateConnectionId;
            if (!self.hasCapacity()) return error.ConnectionLimitReached;
            if (self.max_records != std.math.maxInt(usize)) {
                self.records.putAssumeCapacityNoClobber(connection_id, record);
            } else {
                try self.records.put(connection_id, record);
            }
        }

        /// Retire and destroy one active record.
        pub fn remove(self: *Self, connection_id: u64) !void {
            const removed = self.records.fetchRemove(connection_id) orelse return error.UnknownConnectionId;
            deinit_record(removed.value);
            self.allocator.destroy(removed.value);
        }

        /// Retire lifecycle state and destroy one active endpoint-owned record.
        ///
        /// Production endpoint owners should use this when explicitly closing or
        /// evicting a connection handle so routes, recovery timers, ECN path
        /// state, and record storage are retired as one operation.
        pub fn retire(
            self: *Self,
            lifecycle: *root.EndpointConnectionLifecycle,
            connection_id: u64,
        ) error{ Internal, UnknownConnectionId }!root.EndpointConnectionRetireResult {
            if (self.records.get(connection_id) == null) return error.UnknownConnectionId;
            const retired = lifecycle.retireConnection(connection_id);
            self.remove(connection_id) catch return error.Internal;
            return retired;
        }

        /// Build caller-owned lifecycle deadline views for all active records.
        pub fn deadlineViews(self: *Self, allocator: std.mem.Allocator) ![]root.EndpointConnectionView {
            const views = try allocator.alloc(root.EndpointConnectionView, self.count());
            errdefer allocator.free(views);
            return self.fillDeadlineViews(views);
        }

        /// Build caller-owned lifecycle receive views for all active records.
        pub fn receiveViews(self: *Self, allocator: std.mem.Allocator) ![]root.EndpointConnectionReceiveView {
            const views = try allocator.alloc(root.EndpointConnectionReceiveView, self.count());
            errdefer allocator.free(views);
            return self.fillReceiveViews(views);
        }

        /// Build lifecycle recovery-poll views using record-specific connection IDs.
        pub fn pollViews(
            self: *Self,
            allocator: std.mem.Allocator,
            comptime destination_connection_id: *const fn (*const Record) []const u8,
            comptime source_connection_id: *const fn (*const Record) []const u8,
        ) ![]root.EndpointConnectionPollView {
            const views = try allocator.alloc(root.EndpointConnectionPollView, self.count());
            errdefer allocator.free(views);
            return self.fillPollViews(views, destination_connection_id, source_connection_id);
        }

        /// Populate caller-owned deadline views without allocating.
        pub fn fillDeadlineViews(
            self: *Self,
            out: []root.EndpointConnectionView,
        ) root.Error![]root.EndpointConnectionView {
            if (out.len < self.count()) return error.BufferTooSmall;
            var iterator = self.records.iterator();
            var index: usize = 0;
            while (iterator.next()) |entry| : (index += 1) {
                out[index] = .{
                    .connection_id = entry.key_ptr.*,
                    .connection = connection_of(entry.value_ptr.*),
                };
            }
            return out[0..index];
        }

        /// Populate caller-owned receive views without allocating.
        pub fn fillReceiveViews(
            self: *Self,
            out: []root.EndpointConnectionReceiveView,
        ) root.Error![]root.EndpointConnectionReceiveView {
            if (out.len < self.count()) return error.BufferTooSmall;
            var iterator = self.records.iterator();
            var index: usize = 0;
            while (iterator.next()) |entry| : (index += 1) {
                out[index] = .{
                    .connection_id = entry.key_ptr.*,
                    .connection = connection_of(entry.value_ptr.*),
                };
            }
            return out[0..index];
        }

        /// Populate caller-owned recovery-poll views without allocating.
        pub fn fillPollViews(
            self: *Self,
            out: []root.EndpointConnectionPollView,
            comptime destination_connection_id: *const fn (*const Record) []const u8,
            comptime source_connection_id: *const fn (*const Record) []const u8,
        ) root.Error![]root.EndpointConnectionPollView {
            if (out.len < self.count()) return error.BufferTooSmall;
            var iterator = self.records.iterator();
            var index: usize = 0;
            while (iterator.next()) |entry| : (index += 1) {
                out[index] = .{
                    .connection_id = entry.key_ptr.*,
                    .connection = connection_of(entry.value_ptr.*),
                    .destination_connection_id = destination_connection_id(entry.value_ptr.*),
                    .source_connection_id = source_connection_id(entry.value_ptr.*),
                };
            }
            return out[0..index];
        }

        /// Select the earliest lifecycle deadline from the records owned by this registry.
        pub fn nextDeadline(
            self: *Self,
            lifecycle: *root.EndpointConnectionLifecycle,
            allocator: std.mem.Allocator,
        ) !?root.EndpointConnectionDeadline {
            _ = try self.removeClosedRecords(lifecycle);
            if (self.deadline_view_scratch) |views| {
                return lifecycle.nextDeadlineAcrossConnections(try self.fillDeadlineViews(views));
            }
            const views = try self.deadlineViews(allocator);
            defer allocator.free(views);
            return lifecycle.nextDeadlineAcrossConnections(views);
        }

        /// Retire lifecycle state and remove every record whose connection has reached the closed state.
        pub fn removeClosedRecords(
            self: *Self,
            lifecycle: *root.EndpointConnectionLifecycle,
        ) root.Error!usize {
            var removed_count: usize = 0;
            while (true) {
                var closed_connection_id: ?u64 = null;
                var iterator = self.records.iterator();
                while (iterator.next()) |entry| {
                    if (connection_of(entry.value_ptr.*).connectionState() == .closed) {
                        closed_connection_id = entry.key_ptr.*;
                        break;
                    }
                }
                const connection_id = closed_connection_id orelse break;
                _ = lifecycle.retireConnection(connection_id);
                self.remove(connection_id) catch return error.Internal;
                removed_count += 1;
            }
            return removed_count;
        }

        /// Sweep endpoint-owned pending work and destroy records closed by it.
        ///
        /// Terminal idle/close transitions retire lifecycle state first, then
        /// this registry destroys the matching endpoint-owned records.
        pub fn processPendingWork(
            self: *Self,
            lifecycle: *root.EndpointConnectionLifecycle,
            allocator: std.mem.Allocator,
            now_millis: i64,
        ) root.Error!root.EndpointPendingWorkSweepResult {
            _ = try self.removeClosedRecords(lifecycle);
            const pending_work = if (self.receive_view_scratch) |views|
                try lifecycle.processPendingWorkAcrossConnections(
                    try self.fillReceiveViews(views),
                    now_millis,
                )
            else pending: {
                const views = try self.receiveViews(allocator);
                defer allocator.free(views);
                break :pending try lifecycle.processPendingWorkAcrossConnections(
                    views,
                    now_millis,
                );
            };
            _ = try self.removeClosedRecords(lifecycle);
            return pending_work;
        }

        /// Sweep pending work, destroy closed records, and drain installed-key output.
        ///
        /// Output is only drained when at least one recovery timer was serviced.
        pub fn processPendingWorkAndDrainDatagrams(
            self: *Self,
            lifecycle: *root.EndpointConnectionLifecycle,
            allocator: std.mem.Allocator,
            now_millis: i64,
            space: root.EndpointInstalledKeyDatagramSpace,
            out: []root.EndpointPolledDatagramResult,
            comptime destination_connection_id: *const fn (*const Record) []const u8,
            comptime source_connection_id: *const fn (*const Record) []const u8,
        ) root.Error!root.EndpointPendingWorkSweepDatagramDrainResult {
            const pending_work = try self.processPendingWork(
                lifecycle,
                allocator,
                now_millis,
            );
            if (pending_work.recovery_serviced_count == 0) {
                return .{
                    .pending_work = pending_work,
                    .drain = .{},
                };
            }

            const drain = if (self.poll_view_scratch) |views|
                self.drainDatagramsAcrossConnectionViews(
                    lifecycle,
                    try self.fillPollViews(views, destination_connection_id, source_connection_id),
                    now_millis,
                    space,
                    out,
                )
            else drain: {
                const views = try self.pollViews(
                    allocator,
                    destination_connection_id,
                    source_connection_id,
                );
                defer allocator.free(views);
                break :drain self.drainDatagramsAcrossConnectionViews(
                    lifecycle,
                    views,
                    now_millis,
                    space,
                    out,
                );
            };
            return .{
                .pending_work = pending_work,
                .drain = drain,
            };
        }

        fn drainDatagramsAcrossConnectionViews(
            self: *Self,
            lifecycle: *root.EndpointConnectionLifecycle,
            views: []const root.EndpointConnectionPollView,
            now_millis: i64,
            space: root.EndpointInstalledKeyDatagramSpace,
            out: []root.EndpointPolledDatagramResult,
        ) root.EndpointDatagramDrainResult {
            var result = root.EndpointDatagramDrainResult{};
            while (result.datagrams_written < out.len) {
                const polled = self.pollDatagramAcrossConnectionViews(
                    lifecycle,
                    views,
                    now_millis,
                    space,
                ) catch |err| {
                    result.first_error = err;
                    return result;
                };
                out[result.datagrams_written] = polled orelse return result;
                result.datagrams_written += 1;
            }
            return result;
        }

        /// Sweep endpoint-owned pending work and return the next live deadline.
        ///
        /// Terminal idle/close transitions retire lifecycle state first, then
        /// this registry destroys the matching endpoint-owned records before
        /// selecting the next deadline.
        pub fn processPendingWorkAndSelectNextDeadline(
            self: *Self,
            lifecycle: *root.EndpointConnectionLifecycle,
            allocator: std.mem.Allocator,
            now_millis: i64,
        ) root.Error!root.EndpointPendingWorkNextDeadlineResult {
            return .{
                .pending_work = try self.processPendingWork(lifecycle, allocator, now_millis),
                .next_deadline = try self.nextDeadline(lifecycle, allocator),
            };
        }

        /// Service the earliest due lifecycle deadline using this registry's records.
        ///
        /// The returned datagrams remain caller-owned and retain the existing
        /// lifecycle allocation contract.
        pub fn processDueDeadlineAndDrainDatagrams(
            self: *Self,
            lifecycle: *root.EndpointConnectionLifecycle,
            allocator: std.mem.Allocator,
            now_millis: i64,
            out: []root.EndpointPolledDatagramResult,
            comptime destination_connection_id: *const fn (*const Record) []const u8,
            comptime source_connection_id: *const fn (*const Record) []const u8,
        ) root.Error!?root.EndpointDueWorkDatagramDrainResult {
            _ = try self.removeClosedRecords(lifecycle);
            var result: ?root.EndpointDueWorkDatagramDrainResult = null;
            if (self.poll_view_scratch) |views| {
                result = try lifecycle.processDueDeadlineAcrossConnectionsAndDrainDatagrams(
                    try self.fillPollViews(views, destination_connection_id, source_connection_id),
                    now_millis,
                    out,
                );
            } else {
                const views = try self.pollViews(
                    allocator,
                    destination_connection_id,
                    source_connection_id,
                );
                defer allocator.free(views);
                result = try lifecycle.processDueDeadlineAcrossConnectionsAndDrainDatagrams(
                    views,
                    now_millis,
                    out,
                );
            }
            if (result) |due_work| {
                if (due_work.pending_work.idle_retired != null or due_work.pending_work.close_retired != null) {
                    self.remove(due_work.deadline.connection_id) catch return error.Internal;
                }
            }
            return result;
        }

        /// Poll one installed-key datagram from endpoint-owned records.
        ///
        /// Repeated calls resume after the last record that produced output so
        /// one busy connection does not permanently starve later records.
        pub fn pollDatagramAcrossConnections(
            self: *Self,
            lifecycle: *root.EndpointConnectionLifecycle,
            allocator: std.mem.Allocator,
            now_millis: i64,
            space: root.EndpointInstalledKeyDatagramSpace,
            comptime destination_connection_id: *const fn (*const Record) []const u8,
            comptime source_connection_id: *const fn (*const Record) []const u8,
        ) root.Error!?root.EndpointPolledDatagramResult {
            _ = try self.removeClosedRecords(lifecycle);
            if (self.poll_view_scratch) |views| {
                return self.pollDatagramAcrossConnectionViews(
                    lifecycle,
                    try self.fillPollViews(views, destination_connection_id, source_connection_id),
                    now_millis,
                    space,
                );
            }
            const views = try self.pollViews(
                allocator,
                destination_connection_id,
                source_connection_id,
            );
            defer allocator.free(views);
            return self.pollDatagramAcrossConnectionViews(
                lifecycle,
                views,
                now_millis,
                space,
            );
        }

        fn pollDatagramAcrossConnectionViews(
            self: *Self,
            lifecycle: *root.EndpointConnectionLifecycle,
            views: []const root.EndpointConnectionPollView,
            now_millis: i64,
            space: root.EndpointInstalledKeyDatagramSpace,
        ) root.Error!?root.EndpointPolledDatagramResult {
            if (views.len == 0) {
                self.next_poll_index = 0;
                return null;
            }
            const start = self.next_poll_index % views.len;
            var offset: usize = 0;
            while (offset < views.len) : (offset += 1) {
                const index = (start + offset) % views.len;
                const view = views[index];
                const datagram = lifecycle.pollDatagram(
                    view.connection_id,
                    view.connection,
                    now_millis,
                    .{
                        .space = space,
                        .destination_connection_id = view.destination_connection_id,
                        .source_connection_id = view.source_connection_id,
                    },
                ) catch |err| switch (err) {
                    error.ConnectionClosed => {
                        if (view.connection.connectionState() == .closed) {
                            _ = lifecycle.retireConnection(view.connection_id);
                            self.remove(view.connection_id) catch return error.Internal;
                        }
                        continue;
                    },
                    else => return err,
                };
                if (datagram) |bytes| {
                    self.next_poll_index = (index + 1) % views.len;
                    return .{
                        .connection_id = view.connection_id,
                        .datagram = bytes,
                    };
                }
            }
            self.next_poll_index = start;
            return null;
        }

        /// Classify and process one installed-key datagram against the owned records.
        ///
        /// This retains the lifecycle's packet-space and close-propagation
        /// behavior while eliminating caller-managed receive-view snapshots.
        pub fn feedDatagramWithInstalledKeys(
            self: *Self,
            lifecycle: *root.EndpointConnectionLifecycle,
            allocator: std.mem.Allocator,
            path: root.endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            options: root.EndpointFeedInstalledKeyDatagramOptions,
        ) root.EndpointProtectedDatagramError!root.EndpointFeedInstalledKeyDatagramResult {
            _ = try self.removeClosedRecords(lifecycle);
            if (self.receive_view_scratch) |views| {
                return lifecycle.feedDatagramWithInstalledKeysAcrossConnections(
                    try self.fillReceiveViews(views),
                    path,
                    now_millis,
                    datagram,
                    options,
                );
            }
            const views = try self.receiveViews(allocator);
            defer allocator.free(views);
            return lifecycle.feedDatagramWithInstalledKeysAcrossConnections(
                views,
                path,
                now_millis,
                datagram,
                options,
            );
        }
    };
}

test "EndpointConnectionRegistry owns records and exposes lifecycle views" {
    const TestRecord = struct {
        handle: u64,
        connection: root.Connection,

        fn connectionRef(self: *@This()) *root.Connection {
            return &self.connection;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const Registry = EndpointConnectionRegistry(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.deinit,
    );

    var registry = try Registry.initWithCapacity(std.testing.allocator, 1);
    defer registry.deinit();
    try std.testing.expectEqual(@as(usize, 1), registry.capacityLimit());
    try std.testing.expect(registry.records.capacity() >= 1);
    var empty_ids: [1]u64 = undefined;
    try std.testing.expectEqual(@as(usize, 0), (try registry.fillConnectionIds(&empty_ids)).len);
    var connection = try root.Connection.init(std.testing.allocator, .client, .{});
    var connection_owned = true;
    errdefer if (connection_owned) connection.deinit();
    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var adopted = false;
    errdefer if (!adopted) {
        if (record_initialized) record.deinit();
        std.testing.allocator.destroy(record);
    };
    record.* = .{
        .handle = 7,
        .connection = connection,
    };
    record_initialized = true;
    connection_owned = false;
    try registry.adopt(record.handle, record);
    adopted = true;

    const views = try registry.deadlineViews(std.testing.allocator);
    defer std.testing.allocator.free(views);
    try std.testing.expectEqual(@as(usize, 1), registry.count());
    try std.testing.expectEqual(@as(usize, 1), registry.capacityLimit());
    try std.testing.expect(!registry.hasCapacity());
    var ids: [1]u64 = undefined;
    const active_ids = try registry.fillConnectionIds(&ids);
    try std.testing.expectEqual(@as(usize, 1), active_ids.len);
    try std.testing.expectEqual(@as(u64, 7), active_ids[0]);
    var no_ids: [0]u64 = .{};
    try std.testing.expectError(error.BufferTooSmall, registry.fillConnectionIds(&no_ids));
    try std.testing.expectEqual(@as(usize, 1), views.len);
    try std.testing.expectEqual(@as(u64, 7), views[0].connection_id);
    try std.testing.expect(views[0].connection == &record.connection);

    var lifecycle = root.EndpointConnectionLifecycle.init(std.testing.allocator);
    defer lifecycle.deinit();
    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    try std.testing.expect((try registry.nextDeadline(&lifecycle, no_allocation_allocator.allocator())) == null);

    var endpoint_output: [64]u8 = undefined;
    const feed = try registry.feedDatagramWithInstalledKeys(
        &lifecycle,
        no_allocation_allocator.allocator(),
        .{
            .local = root.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
            .remote = root.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4434),
        },
        0,
        &.{0x40},
        .{
            .space = .application,
            .out = &endpoint_output,
            .unpredictable_prefix = &.{},
            .supported_versions = &.{.v1},
        },
    );
    try std.testing.expect(feed == .dropped);

    var due_datagrams: [1]root.EndpointPolledDatagramResult = undefined;
    try std.testing.expect((try registry.processDueDeadlineAndDrainDatagrams(
        &lifecycle,
        no_allocation_allocator.allocator(),
        0,
        &due_datagrams,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
    )) == null);
    const pending_drain = try registry.processPendingWorkAndDrainDatagrams(
        &lifecycle,
        no_allocation_allocator.allocator(),
        0,
        .application,
        &due_datagrams,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
    );
    try std.testing.expectEqual(@as(usize, 0), pending_drain.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), pending_drain.pending_work.close_retired_count);
    try std.testing.expectEqual(@as(usize, 0), pending_drain.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), pending_drain.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), pending_drain.drain.first_error);

    const second_record = try std.testing.allocator.create(TestRecord);
    var second_initialized = false;
    var second_adopted = false;
    defer if (!second_adopted) {
        if (second_initialized) second_record.deinit();
        std.testing.allocator.destroy(second_record);
    };
    second_record.* = .{
        .handle = 8,
        .connection = try root.Connection.init(std.testing.allocator, .client, .{}),
    };
    second_initialized = true;
    if (registry.adopt(second_record.handle, second_record)) |_| {
        second_adopted = true;
    } else |err| {
        try std.testing.expectEqual(error.ConnectionLimitReached, err);
    }
    try std.testing.expect(!second_adopted);

    try registry.remove(7);
    try std.testing.expectEqual(@as(usize, 0), registry.count());
    try std.testing.expect(registry.hasCapacity());
    try registry.adopt(second_record.handle, second_record);
    second_adopted = true;
    try std.testing.expectEqual(@as(usize, 1), registry.count());
    try std.testing.expect(!registry.hasCapacity());
}

test "EndpointConnectionRegistry lifecycle views use registry connection handle" {
    const TestRecord = struct {
        handle: u64,
        connection: root.Connection,

        fn connectionRef(self: *@This()) *root.Connection {
            return &self.connection;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const Registry = EndpointConnectionRegistry(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.deinit,
    );

    var registry = try Registry.initWithCapacity(std.testing.allocator, 1);
    defer registry.deinit();

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 99,
        .connection = try root.Connection.init(std.testing.allocator, .client, .{}),
    };
    record_initialized = true;
    try registry.adopt(7, record);
    record_owned = false;

    var deadline_views: [1]root.EndpointConnectionView = undefined;
    const deadlines = try registry.fillDeadlineViews(&deadline_views);
    try std.testing.expectEqual(@as(usize, 1), deadlines.len);
    try std.testing.expectEqual(@as(u64, 7), deadlines[0].connection_id);
    try std.testing.expect(deadlines[0].connection == &record.connection);

    var receive_views: [1]root.EndpointConnectionReceiveView = undefined;
    const receives = try registry.fillReceiveViews(&receive_views);
    try std.testing.expectEqual(@as(usize, 1), receives.len);
    try std.testing.expectEqual(@as(u64, 7), receives[0].connection_id);
    try std.testing.expect(receives[0].connection == &record.connection);

    var poll_views: [1]root.EndpointConnectionPollView = undefined;
    const polls = try registry.fillPollViews(
        &poll_views,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
    );
    try std.testing.expectEqual(@as(usize, 1), polls.len);
    try std.testing.expectEqual(@as(u64, 7), polls[0].connection_id);
    try std.testing.expect(polls[0].connection == &record.connection);
    try std.testing.expectEqualStrings("peer", polls[0].destination_connection_id);
    try std.testing.expectEqualStrings("local", polls[0].source_connection_id);
}

test "EndpointConnectionRegistry removes record after due idle retirement" {
    const TestRecord = struct {
        handle: u64,
        connection: root.Connection,

        fn connectionRef(self: *@This()) *root.Connection {
            return &self.connection;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const Registry = EndpointConnectionRegistry(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.deinit,
    );

    var registry = try Registry.initWithCapacity(std.testing.allocator, 1);
    defer registry.deinit();
    var lifecycle = root.EndpointConnectionLifecycle.init(std.testing.allocator);
    defer lifecycle.deinit();

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer if (record_owned) {
        if (record_initialized) record.deinit();
        std.testing.allocator.destroy(record);
    };
    record.* = .{
        .handle = 42,
        .connection = try root.Connection.init(std.testing.allocator, .server, .{ .max_idle_timeout_ms = 10 }),
    };
    record_initialized = true;
    record.connection.last_packet_activity_millis = 10;

    const path = root.endpoint.Udp4Tuple{
        .local = root.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = root.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4434),
    };
    try lifecycle.registerConnectionId(record.handle, TestRecord.sourceConnectionId(record), path, .{});
    errdefer _ = lifecycle.retireConnection(record.handle);
    try registry.adopt(record.handle, record);
    record_owned = false;

    const idle_deadline = (try registry.nextDeadline(&lifecycle, std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.idle_timeout, idle_deadline.kind);
    try std.testing.expectEqual(@as(u64, 42), idle_deadline.connection_id);
    try std.testing.expectEqual(@as(i64, 20), idle_deadline.deadline_millis);

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    var out: [1]root.EndpointPolledDatagramResult = undefined;
    try std.testing.expect((try registry.processDueDeadlineAndDrainDatagrams(
        &lifecycle,
        no_allocation_allocator.allocator(),
        19,
        &out,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
    )) == null);
    try std.testing.expectEqual(@as(usize, 1), registry.count());
    try std.testing.expectEqual(@as(usize, 1), lifecycle.routeCount());

    const due = (try registry.processDueDeadlineAndDrainDatagrams(
        &lifecycle,
        no_allocation_allocator.allocator(),
        20,
        &out,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.idle_timeout, due.deadline.kind);
    try std.testing.expect(due.pending_work.idle_retired != null);
    try std.testing.expectEqual(@as(?root.EndpointConnectionRetireResult, null), due.pending_work.close_retired);
    try std.testing.expectEqual(@as(usize, 0), due.drain.datagrams_written);
    try std.testing.expectEqual(@as(usize, 0), registry.count());
    try std.testing.expect(registry.hasCapacity());
    try std.testing.expectEqual(@as(usize, 0), lifecycle.routeCount());
}

test "EndpointConnectionRegistry retire removes lifecycle state and record together" {
    const TestRecord = struct {
        handle: u64,
        connection: root.Connection,

        fn connectionRef(self: *@This()) *root.Connection {
            return &self.connection;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer-retire";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local-retire";
        }

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const Registry = EndpointConnectionRegistry(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.deinit,
    );

    var registry = try Registry.initWithCapacity(std.testing.allocator, 1);
    defer registry.deinit();
    var lifecycle = root.EndpointConnectionLifecycle.init(std.testing.allocator);
    defer lifecycle.deinit();

    const record_handle: u64 = 51;
    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer if (record_owned) {
        if (record_initialized) record.deinit();
        std.testing.allocator.destroy(record);
    };
    record.* = .{
        .handle = record_handle,
        .connection = try root.Connection.init(std.testing.allocator, .server, .{}),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    try record.connection.recordPeerAddressBytesReceived(1);

    const path = root.endpoint.Udp4Tuple{
        .local = root.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = root.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4434),
    };
    try lifecycle.registerConnectionId(record_handle, TestRecord.sourceConnectionId(record), path, .{ .sequence_number = 0 });
    var lifecycle_registered = true;
    errdefer if (lifecycle_registered) {
        _ = lifecycle.retireConnection(record_handle);
    };
    _ = try record.connection.recordPacketSentInSpace(.application, 10, 100);
    try lifecycle.armRecoveryTimerFromConnection(record_handle, &record.connection);
    try registry.adopt(record_handle, record);
    record_owned = false;

    try std.testing.expectEqual(@as(usize, 1), registry.count());
    try std.testing.expectEqual(@as(usize, 1), lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 1), lifecycle.recoveryTimerCount());

    const retired = try registry.retire(&lifecycle, record_handle);
    lifecycle_registered = false;
    try std.testing.expectEqual(@as(usize, 1), retired.routes_retired);
    try std.testing.expect(retired.recovery_timer_disarmed);
    try std.testing.expectEqual(@as(usize, 0), registry.count());
    try std.testing.expect(registry.hasCapacity());
    try std.testing.expectEqual(@as(usize, 0), lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), lifecycle.recoveryTimerCount());
    try std.testing.expectError(error.UnknownConnectionId, registry.retire(&lifecycle, record_handle));
}

test "EndpointConnectionRegistry pending sweep retires lifecycle for already closed records" {
    const TestRecord = struct {
        handle: u64,
        connection: root.Connection,

        fn connectionRef(self: *@This()) *root.Connection {
            return &self.connection;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer-closed";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local-closed";
        }

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const Registry = EndpointConnectionRegistry(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.deinit,
    );

    var registry = try Registry.initWithCapacity(std.testing.allocator, 1);
    defer registry.deinit();
    var lifecycle = root.EndpointConnectionLifecycle.init(std.testing.allocator);
    defer lifecycle.deinit();

    const record_handle: u64 = 61;
    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer if (record_owned) {
        if (record_initialized) record.deinit();
        std.testing.allocator.destroy(record);
    };
    record.* = .{
        .handle = record_handle,
        .connection = try root.Connection.init(std.testing.allocator, .server, .{}),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    try record.connection.recordPeerAddressBytesReceived(1);

    const path = root.endpoint.Udp4Tuple{
        .local = root.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = root.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4434),
    };
    try lifecycle.registerConnectionId(record_handle, TestRecord.sourceConnectionId(record), path, .{ .sequence_number = 0 });
    var lifecycle_registered = true;
    errdefer if (lifecycle_registered) {
        _ = lifecycle.retireConnection(record_handle);
    };
    _ = try record.connection.recordPacketSentInSpace(.application, 10, 100);
    try lifecycle.armRecoveryTimerFromConnection(record_handle, &record.connection);
    try registry.adopt(record_handle, record);
    record_owned = false;

    try std.testing.expectEqual(@as(usize, 1), registry.count());
    try std.testing.expectEqual(@as(usize, 1), lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 1), lifecycle.recoveryTimerCount());

    record.connection.state = .closed;
    record.connection.closed = true;

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const pending = try registry.processPendingWork(
        &lifecycle,
        no_allocation_allocator.allocator(),
        20,
    );
    lifecycle_registered = false;
    try std.testing.expectEqual(@as(usize, 0), pending.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), pending.close_retired_count);
    try std.testing.expectEqual(@as(usize, 0), pending.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), registry.count());
    try std.testing.expect(registry.hasCapacity());
    try std.testing.expectEqual(@as(usize, 0), lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), lifecycle.recoveryTimerCount());
}

test "EndpointConnectionRegistry output polling skips and retires closed records" {
    const TestRecord = struct {
        handle: u64,
        connection: root.Connection,

        fn connectionRef(self: *@This()) *root.Connection {
            return &self.connection;
        }

        fn destinationConnectionId(self: *const @This()) []const u8 {
            return if (self.handle == 71) "peer-closed-poll" else "peer-live-poll";
        }

        fn sourceConnectionId(self: *const @This()) []const u8 {
            return if (self.handle == 71) "local-closed-poll" else "local-live-poll";
        }

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const Registry = EndpointConnectionRegistry(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.deinit,
    );

    const secrets = try root.protection.deriveInitialSecrets(.v1, "registry-poll-closed");
    var registry = try Registry.initWithCapacity(std.testing.allocator, 2);
    defer registry.deinit();
    var lifecycle = root.EndpointConnectionLifecycle.init(std.testing.allocator);
    defer lifecycle.deinit();

    const closed_record = try std.testing.allocator.create(TestRecord);
    var closed_initialized = false;
    var closed_owned = true;
    errdefer {
        if (closed_owned) {
            if (closed_initialized) closed_record.deinit();
            std.testing.allocator.destroy(closed_record);
        }
    }
    closed_record.* = .{
        .handle = 71,
        .connection = try root.Connection.init(std.testing.allocator, .server, .{}),
    };
    closed_initialized = true;
    try closed_record.connection.validatePeerAddress();
    try closed_record.connection.confirmHandshake();
    try closed_record.connection.recordPeerAddressBytesReceived(1);

    const path = root.endpoint.Udp4Tuple{
        .local = root.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = root.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4434),
    };
    try lifecycle.registerConnectionId(closed_record.handle, TestRecord.sourceConnectionId(closed_record), path, .{ .sequence_number = 0 });
    var closed_lifecycle_registered = true;
    errdefer if (closed_lifecycle_registered) {
        _ = lifecycle.retireConnection(closed_record.handle);
    };
    _ = try closed_record.connection.recordPacketSentInSpace(.application, 10, 100);
    try lifecycle.armRecoveryTimerFromConnection(closed_record.handle, &closed_record.connection);
    try registry.adopt(closed_record.handle, closed_record);
    closed_owned = false;

    const live_record = try std.testing.allocator.create(TestRecord);
    var live_initialized = false;
    var live_owned = true;
    errdefer {
        if (live_owned) {
            if (live_initialized) live_record.deinit();
            std.testing.allocator.destroy(live_record);
        }
    }
    live_record.* = .{
        .handle = 72,
        .connection = try root.Connection.init(std.testing.allocator, .server, .{}),
    };
    live_initialized = true;
    try live_record.connection.validatePeerAddress();
    try live_record.connection.confirmHandshake();
    try live_record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try live_record.connection.sendPing();
    try registry.adopt(live_record.handle, live_record);
    live_owned = false;

    try std.testing.expectEqual(@as(usize, 2), registry.count());
    try std.testing.expectEqual(@as(usize, 1), lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 1), lifecycle.recoveryTimerCount());

    closed_record.connection.state = .closed;
    closed_record.connection.closed = true;

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const polled = (try registry.pollDatagramAcrossConnections(
        &lifecycle,
        no_allocation_allocator.allocator(),
        20,
        .application,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(polled.datagram);
    closed_lifecycle_registered = false;
    try std.testing.expectEqual(@as(u64, live_record.handle), polled.connection_id);
    try std.testing.expectEqual(@as(usize, 1), registry.count());
    try std.testing.expect(registry.get(closed_record.handle) == null);
    try std.testing.expect(registry.get(live_record.handle) != null);
    try std.testing.expectEqual(@as(usize, 0), lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 1), lifecycle.recoveryTimerCount());
}

test "EndpointConnectionRegistry output polling skips closing records without output" {
    const TestRecord = struct {
        handle: u64,
        connection: root.Connection,

        fn connectionRef(self: *@This()) *root.Connection {
            return &self.connection;
        }

        fn destinationConnectionId(self: *const @This()) []const u8 {
            return if (self.handle == 75) "closing-peer" else "live-peer";
        }

        fn sourceConnectionId(self: *const @This()) []const u8 {
            return if (self.handle == 75) "closing-local" else "live-local";
        }

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const Registry = EndpointConnectionRegistry(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.deinit,
    );

    const secrets = try root.protection.deriveInitialSecrets(.v1, "skip-close");
    var registry = try Registry.initWithCapacity(std.testing.allocator, 2);
    defer registry.deinit();
    var lifecycle = root.EndpointConnectionLifecycle.init(std.testing.allocator);
    defer lifecycle.deinit();

    const closing_record = try std.testing.allocator.create(TestRecord);
    var closing_initialized = false;
    var closing_owned = true;
    errdefer {
        if (closing_owned) {
            if (closing_initialized) closing_record.deinit();
            std.testing.allocator.destroy(closing_record);
        }
    }
    closing_record.* = .{
        .handle = 75,
        .connection = try root.Connection.init(std.testing.allocator, .server, .{}),
    };
    closing_initialized = true;
    try closing_record.connection.validatePeerAddress();
    try closing_record.connection.confirmHandshake();
    try closing_record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    closing_record.connection.state = .closing;
    try registry.adopt(closing_record.handle, closing_record);
    closing_owned = false;

    const live_record = try std.testing.allocator.create(TestRecord);
    var live_initialized = false;
    var live_owned = true;
    errdefer {
        if (live_owned) {
            if (live_initialized) live_record.deinit();
            std.testing.allocator.destroy(live_record);
        }
    }
    live_record.* = .{
        .handle = 76,
        .connection = try root.Connection.init(std.testing.allocator, .server, .{}),
    };
    live_initialized = true;
    try live_record.connection.validatePeerAddress();
    try live_record.connection.confirmHandshake();
    try live_record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try live_record.connection.sendPing();
    try registry.adopt(live_record.handle, live_record);
    live_owned = false;

    try std.testing.expectEqual(@as(usize, 2), registry.count());
    var poll_views: [2]root.EndpointConnectionPollView = undefined;
    const views = try registry.fillPollViews(
        &poll_views,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
    );
    for (views, 0..) |view, index| {
        if (view.connection_id == closing_record.handle) {
            registry.next_poll_index = index;
            break;
        }
    }

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const polled = (try registry.pollDatagramAcrossConnections(
        &lifecycle,
        no_allocation_allocator.allocator(),
        20,
        .application,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(polled.datagram);
    try std.testing.expectEqual(@as(u64, live_record.handle), polled.connection_id);
    try std.testing.expectEqual(root.ConnectionState.closing, closing_record.connection.connectionState());
    try std.testing.expect(registry.get(closing_record.handle) != null);
    try std.testing.expect(registry.get(live_record.handle) != null);
    try std.testing.expectEqual(@as(usize, 2), registry.count());
}

test "EndpointConnectionRegistry output polling retires records closed by poll timeout" {
    const TestRecord = struct {
        handle: u64,
        connection: root.Connection,

        fn connectionRef(self: *@This()) *root.Connection {
            return &self.connection;
        }

        fn destinationConnectionId(self: *const @This()) []const u8 {
            return if (self.handle == 77) "expired-peer" else "live-after-expired";
        }

        fn sourceConnectionId(self: *const @This()) []const u8 {
            return if (self.handle == 77) "expired-local" else "live-exp-local";
        }

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const Registry = EndpointConnectionRegistry(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.deinit,
    );

    const secrets = try root.protection.deriveInitialSecrets(.v1, "poll-expire");
    var registry = try Registry.initWithCapacity(std.testing.allocator, 2);
    defer registry.deinit();
    var lifecycle = root.EndpointConnectionLifecycle.init(std.testing.allocator);
    defer lifecycle.deinit();

    const expired_record = try std.testing.allocator.create(TestRecord);
    var expired_initialized = false;
    var expired_owned = true;
    errdefer {
        if (expired_owned) {
            if (expired_initialized) expired_record.deinit();
            std.testing.allocator.destroy(expired_record);
        }
    }
    expired_record.* = .{
        .handle = 77,
        .connection = try root.Connection.init(std.testing.allocator, .server, .{}),
    };
    expired_initialized = true;
    try expired_record.connection.validatePeerAddress();
    try expired_record.connection.confirmHandshake();
    try expired_record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    const path = root.endpoint.Udp4Tuple{
        .local = root.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = root.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4434),
    };
    try lifecycle.registerConnectionId(expired_record.handle, TestRecord.sourceConnectionId(expired_record), path, .{ .sequence_number = 0 });
    var expired_lifecycle_registered = true;
    errdefer if (expired_lifecycle_registered) {
        _ = lifecycle.retireConnection(expired_record.handle);
    };
    _ = try expired_record.connection.recordPacketSentInSpace(.application, 10, 100);
    try lifecycle.armRecoveryTimerFromConnection(expired_record.handle, &expired_record.connection);
    expired_record.connection.state = .closing;
    expired_record.connection.close_deadline_millis = 10;
    try registry.adopt(expired_record.handle, expired_record);
    expired_owned = false;

    const live_record = try std.testing.allocator.create(TestRecord);
    var live_initialized = false;
    var live_owned = true;
    errdefer {
        if (live_owned) {
            if (live_initialized) live_record.deinit();
            std.testing.allocator.destroy(live_record);
        }
    }
    live_record.* = .{
        .handle = 78,
        .connection = try root.Connection.init(std.testing.allocator, .server, .{}),
    };
    live_initialized = true;
    try live_record.connection.validatePeerAddress();
    try live_record.connection.confirmHandshake();
    try live_record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try live_record.connection.sendPing();
    try registry.adopt(live_record.handle, live_record);
    live_owned = false;

    var poll_views: [2]root.EndpointConnectionPollView = undefined;
    const views = try registry.fillPollViews(
        &poll_views,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
    );
    for (views, 0..) |view, index| {
        if (view.connection_id == expired_record.handle) {
            registry.next_poll_index = index;
            break;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), registry.count());
    try std.testing.expectEqual(@as(usize, 1), lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 1), lifecycle.recoveryTimerCount());

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const polled = (try registry.pollDatagramAcrossConnections(
        &lifecycle,
        no_allocation_allocator.allocator(),
        20,
        .application,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(polled.datagram);
    expired_lifecycle_registered = false;
    try std.testing.expectEqual(@as(u64, live_record.handle), polled.connection_id);
    try std.testing.expect(registry.get(expired_record.handle) == null);
    try std.testing.expect(registry.get(live_record.handle) != null);
    try std.testing.expectEqual(@as(usize, 1), registry.count());
    try std.testing.expectEqual(@as(usize, 0), lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 1), lifecycle.recoveryTimerCount());
}

test "EndpointConnectionRegistry next deadline retires closed records before selecting live work" {
    const TestRecord = struct {
        handle: u64,
        connection: root.Connection,

        fn connectionRef(self: *@This()) *root.Connection {
            return &self.connection;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer-deadline";
        }

        fn sourceConnectionId(self: *const @This()) []const u8 {
            return if (self.handle == 81) "closed-deadline" else "live-deadline";
        }

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const Registry = EndpointConnectionRegistry(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.deinit,
    );

    var registry = try Registry.initWithCapacity(std.testing.allocator, 2);
    defer registry.deinit();
    var lifecycle = root.EndpointConnectionLifecycle.init(std.testing.allocator);
    defer lifecycle.deinit();

    const closed_record = try std.testing.allocator.create(TestRecord);
    var closed_initialized = false;
    var closed_owned = true;
    errdefer {
        if (closed_owned) {
            if (closed_initialized) closed_record.deinit();
            std.testing.allocator.destroy(closed_record);
        }
    }
    closed_record.* = .{
        .handle = 81,
        .connection = try root.Connection.init(std.testing.allocator, .server, .{}),
    };
    closed_initialized = true;
    try closed_record.connection.validatePeerAddress();
    try closed_record.connection.confirmHandshake();
    try closed_record.connection.recordPeerAddressBytesReceived(1);
    const path = root.endpoint.Udp4Tuple{
        .local = root.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = root.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4434),
    };
    try lifecycle.registerConnectionId(closed_record.handle, TestRecord.sourceConnectionId(closed_record), path, .{ .sequence_number = 0 });
    var closed_lifecycle_registered = true;
    errdefer if (closed_lifecycle_registered) {
        _ = lifecycle.retireConnection(closed_record.handle);
    };
    _ = try closed_record.connection.recordPacketSentInSpace(.application, 10, 100);
    try lifecycle.armRecoveryTimerFromConnection(closed_record.handle, &closed_record.connection);
    try registry.adopt(closed_record.handle, closed_record);
    closed_owned = false;

    const live_record = try std.testing.allocator.create(TestRecord);
    var live_initialized = false;
    var live_owned = true;
    errdefer {
        if (live_owned) {
            if (live_initialized) live_record.deinit();
            std.testing.allocator.destroy(live_record);
        }
    }
    live_record.* = .{
        .handle = 82,
        .connection = try root.Connection.init(std.testing.allocator, .server, .{ .max_idle_timeout_ms = 30 }),
    };
    live_initialized = true;
    live_record.connection.last_packet_activity_millis = 5;
    try registry.adopt(live_record.handle, live_record);
    live_owned = false;

    closed_record.connection.state = .closed;
    closed_record.connection.closed = true;

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const deadline = (try registry.nextDeadline(
        &lifecycle,
        no_allocation_allocator.allocator(),
    )) orelse return error.TestUnexpectedResult;
    closed_lifecycle_registered = false;
    try std.testing.expectEqual(@as(u64, live_record.handle), deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.idle_timeout, deadline.kind);
    try std.testing.expectEqual(@as(i64, 35), deadline.deadline_millis);
    try std.testing.expectEqual(@as(usize, 1), registry.count());
    try std.testing.expect(registry.get(closed_record.handle) == null);
    try std.testing.expect(registry.get(live_record.handle) != null);
    try std.testing.expectEqual(@as(usize, 0), lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), lifecycle.recoveryTimerCount());
}

test "EndpointConnectionRegistry due drain retires closed records before servicing live work" {
    const TestRecord = struct {
        handle: u64,
        connection: root.Connection,

        fn connectionRef(self: *@This()) *root.Connection {
            return &self.connection;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer-due";
        }

        fn sourceConnectionId(self: *const @This()) []const u8 {
            return if (self.handle == 91) "closed-due" else "live-due";
        }

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const Registry = EndpointConnectionRegistry(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.deinit,
    );

    var registry = try Registry.initWithCapacity(std.testing.allocator, 2);
    defer registry.deinit();
    var lifecycle = root.EndpointConnectionLifecycle.init(std.testing.allocator);
    defer lifecycle.deinit();

    const closed_record = try std.testing.allocator.create(TestRecord);
    var closed_initialized = false;
    var closed_owned = true;
    errdefer {
        if (closed_owned) {
            if (closed_initialized) closed_record.deinit();
            std.testing.allocator.destroy(closed_record);
        }
    }
    closed_record.* = .{
        .handle = 91,
        .connection = try root.Connection.init(std.testing.allocator, .server, .{}),
    };
    const closed_handle = closed_record.handle;
    closed_initialized = true;
    try closed_record.connection.validatePeerAddress();
    try closed_record.connection.confirmHandshake();
    try closed_record.connection.recordPeerAddressBytesReceived(1);
    const closed_path = root.endpoint.Udp4Tuple{
        .local = root.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = root.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4434),
    };
    try lifecycle.registerConnectionId(closed_handle, TestRecord.sourceConnectionId(closed_record), closed_path, .{ .sequence_number = 0 });
    var closed_lifecycle_registered = true;
    errdefer if (closed_lifecycle_registered) {
        _ = lifecycle.retireConnection(closed_handle);
    };
    _ = try closed_record.connection.recordPacketSentInSpace(.application, 10, 100);
    try lifecycle.armRecoveryTimerFromConnection(closed_handle, &closed_record.connection);
    try registry.adopt(closed_handle, closed_record);
    closed_owned = false;

    const live_record = try std.testing.allocator.create(TestRecord);
    var live_initialized = false;
    var live_owned = true;
    errdefer {
        if (live_owned) {
            if (live_initialized) live_record.deinit();
            std.testing.allocator.destroy(live_record);
        }
    }
    live_record.* = .{
        .handle = 92,
        .connection = try root.Connection.init(std.testing.allocator, .server, .{ .max_idle_timeout_ms = 30 }),
    };
    const live_handle = live_record.handle;
    live_initialized = true;
    live_record.connection.last_packet_activity_millis = 5;
    try registry.adopt(live_handle, live_record);
    live_owned = false;

    closed_record.connection.state = .closed;
    closed_record.connection.closed = true;

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    var out: [1]root.EndpointPolledDatagramResult = undefined;
    const due = (try registry.processDueDeadlineAndDrainDatagrams(
        &lifecycle,
        no_allocation_allocator.allocator(),
        35,
        &out,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
    )) orelse return error.TestUnexpectedResult;
    closed_lifecycle_registered = false;
    try std.testing.expectEqual(@as(u64, live_handle), due.deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.idle_timeout, due.deadline.kind);
    try std.testing.expect(due.pending_work.idle_retired != null);
    try std.testing.expectEqual(@as(usize, 0), due.drain.datagrams_written);
    try std.testing.expect(registry.get(closed_handle) == null);
    try std.testing.expect(registry.get(live_handle) == null);
    try std.testing.expectEqual(@as(usize, 0), registry.count());
    try std.testing.expect(registry.hasCapacity());
    try std.testing.expectEqual(@as(usize, 0), lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), lifecycle.recoveryTimerCount());
}

test "EndpointConnectionRegistry installed-key feed retires closed records before routing" {
    const TestRecord = struct {
        handle: u64,
        connection: root.Connection,

        fn connectionRef(self: *@This()) *root.Connection {
            return &self.connection;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer-feed";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "closed-feed";
        }

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const Registry = EndpointConnectionRegistry(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.deinit,
    );

    var registry = try Registry.initWithCapacity(std.testing.allocator, 1);
    defer registry.deinit();
    var lifecycle = root.EndpointConnectionLifecycle.init(std.testing.allocator);
    defer lifecycle.deinit();

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 91,
        .connection = try root.Connection.init(std.testing.allocator, .server, .{}),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    try record.connection.recordPeerAddressBytesReceived(1);

    const path = root.endpoint.Udp4Tuple{
        .local = root.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = root.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4434),
    };
    try lifecycle.registerConnectionId(record.handle, TestRecord.sourceConnectionId(record), path, .{ .sequence_number = 0 });
    var lifecycle_registered = true;
    errdefer if (lifecycle_registered) {
        _ = lifecycle.retireConnection(record.handle);
    };
    _ = try record.connection.recordPacketSentInSpace(.application, 10, 100);
    try lifecycle.armRecoveryTimerFromConnection(record.handle, &record.connection);
    try registry.adopt(record.handle, record);
    record_owned = false;

    record.connection.state = .closed;
    record.connection.closed = true;

    const datagram = [_]u8{ 0x40, 'c', 'l', 'o', 's', 'e', 'd', '-', 'f', 'e', 'e', 'd', 0x01 };
    var out: [64]u8 = undefined;
    const reset_prefix = [_]u8{ 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde };
    const versions = [_]root.packet.Version{.v1};
    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const feed = try registry.feedDatagramWithInstalledKeys(
        &lifecycle,
        no_allocation_allocator.allocator(),
        path,
        20,
        &datagram,
        .{
            .space = .application,
            .out = &out,
            .unpredictable_prefix = &reset_prefix,
            .supported_versions = &versions,
        },
    );
    lifecycle_registered = false;
    try std.testing.expectEqual(root.EndpointFeedInstalledKeyDatagramResult.dropped, feed);
    try std.testing.expectEqual(@as(usize, 0), registry.count());
    try std.testing.expect(registry.hasCapacity());
    try std.testing.expectEqual(@as(usize, 0), lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), lifecycle.recoveryTimerCount());
}

test "EndpointConnectionRegistry rotates cross-record output polling" {
    const TestRecord = struct {
        handle: u64,
        connection: root.Connection,

        fn connectionRef(self: *@This()) *root.Connection {
            return &self.connection;
        }

        fn destinationConnectionId(self: *const @This()) []const u8 {
            return if (self.handle == 11) "peer-a" else "peer-b";
        }

        fn sourceConnectionId(self: *const @This()) []const u8 {
            return if (self.handle == 11) "local-a" else "local-b";
        }

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const Registry = EndpointConnectionRegistry(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.deinit,
    );

    const secrets = try root.protection.deriveInitialSecrets(.v1, "registry-fair");
    var registry = try Registry.initWithCapacity(std.testing.allocator, 2);
    defer registry.deinit();
    var lifecycle = root.EndpointConnectionLifecycle.init(std.testing.allocator);
    defer lifecycle.deinit();

    const first_record = try std.testing.allocator.create(TestRecord);
    var first_initialized = false;
    var first_owned = true;
    errdefer {
        if (first_owned) {
            if (first_initialized) first_record.deinit();
            std.testing.allocator.destroy(first_record);
        }
    }
    first_record.* = .{
        .handle = 11,
        .connection = try root.Connection.init(std.testing.allocator, .server, .{}),
    };
    first_initialized = true;
    try first_record.connection.validatePeerAddress();
    try first_record.connection.confirmHandshake();
    try first_record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try first_record.connection.sendPing();
    try registry.adopt(first_record.handle, first_record);
    first_owned = false;

    const second_record = try std.testing.allocator.create(TestRecord);
    var second_initialized = false;
    var second_owned = true;
    errdefer {
        if (second_owned) {
            if (second_initialized) second_record.deinit();
            std.testing.allocator.destroy(second_record);
        }
    }
    second_record.* = .{
        .handle = 12,
        .connection = try root.Connection.init(std.testing.allocator, .server, .{}),
    };
    second_initialized = true;
    try second_record.connection.validatePeerAddress();
    try second_record.connection.confirmHandshake();
    try second_record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try second_record.connection.sendPing();
    try registry.adopt(second_record.handle, second_record);
    second_owned = false;

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const first = (try registry.pollDatagramAcrossConnections(
        &lifecycle,
        no_allocation_allocator.allocator(),
        10,
        .application,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(first.datagram);
    try std.testing.expect(first.connection_id == first_record.handle or first.connection_id == second_record.handle);

    const second = (try registry.pollDatagramAcrossConnections(
        &lifecycle,
        no_allocation_allocator.allocator(),
        11,
        .application,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(second.datagram);
    try std.testing.expect(second.connection_id == first_record.handle or second.connection_id == second_record.handle);
    try std.testing.expect(second.connection_id != first.connection_id);

    try std.testing.expect((try registry.pollDatagramAcrossConnections(
        &lifecycle,
        no_allocation_allocator.allocator(),
        12,
        .application,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
    )) == null);
}
