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

        /// Create an empty registry. Record handles must be unique while active.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .records = std.AutoHashMap(u64, *Record).init(allocator),
                .max_records = std.math.maxInt(usize),
                .deadline_view_scratch = null,
                .receive_view_scratch = null,
                .poll_view_scratch = null,
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

        /// Return whether this registry can own one additional record.
        pub fn hasCapacity(self: *const Self) bool {
            return self.count() < self.max_records;
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
            var iterator = self.records.valueIterator();
            var index: usize = 0;
            while (iterator.next()) |record| : (index += 1) {
                out[index] = .{
                    .connection_id = record.*.handle,
                    .connection = connection_of(record.*),
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
            var iterator = self.records.valueIterator();
            var index: usize = 0;
            while (iterator.next()) |record| : (index += 1) {
                out[index] = .{
                    .connection_id = record.*.handle,
                    .connection = connection_of(record.*),
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
            var iterator = self.records.valueIterator();
            var index: usize = 0;
            while (iterator.next()) |record| : (index += 1) {
                out[index] = .{
                    .connection_id = record.*.handle,
                    .connection = connection_of(record.*),
                    .destination_connection_id = destination_connection_id(record.*),
                    .source_connection_id = source_connection_id(record.*),
                };
            }
            return out[0..index];
        }

        /// Select the earliest lifecycle deadline from the records owned by this registry.
        pub fn nextDeadline(
            self: *Self,
            lifecycle: *const root.EndpointConnectionLifecycle,
            allocator: std.mem.Allocator,
        ) !?root.EndpointConnectionDeadline {
            if (self.deadline_view_scratch) |views| {
                return lifecycle.nextDeadlineAcrossConnections(try self.fillDeadlineViews(views));
            }
            const views = try self.deadlineViews(allocator);
            defer allocator.free(views);
            return lifecycle.nextDeadlineAcrossConnections(views);
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
            if (self.poll_view_scratch) |views| {
                return lifecycle.processDueDeadlineAcrossConnectionsAndDrainDatagrams(
                    try self.fillPollViews(views, destination_connection_id, source_connection_id),
                    now_millis,
                    out,
                );
            }
            const views = try self.pollViews(
                allocator,
                destination_connection_id,
                source_connection_id,
            );
            defer allocator.free(views);
            return lifecycle.processDueDeadlineAcrossConnectionsAndDrainDatagrams(
                views,
                now_millis,
                out,
            );
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
    try std.testing.expect(registry.records.capacity() >= 1);
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
    try std.testing.expect(!registry.hasCapacity());
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
