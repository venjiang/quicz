//! Bounded connectivity candidates and RFC 8445 pair ordering.

const std = @import("std");

pub const max_candidates_per_peer = 8;
pub const max_candidate_pairs = max_candidates_per_peer * max_candidates_per_peer;

pub const Source = enum {
    host,
    server_reflexive,
    peer_reflexive,
    relay,
};

pub const Endpoint = union(enum) {
    ipv4: struct {
        address: [4]u8,
        port: u16,
    },
    ipv6: struct {
        address: [16]u8,
        port: u16,
    },

    pub fn family(endpoint: Endpoint) enum { ipv4, ipv6 } {
        return switch (endpoint) {
            .ipv4 => .ipv4,
            .ipv6 => .ipv6,
        };
    }

    pub fn eql(endpoint: Endpoint, other: Endpoint) bool {
        return std.meta.eql(endpoint, other);
    }
};

pub const Candidate = struct {
    id: u64,
    source: Source,
    endpoint: Endpoint,
    priority: u32,

    pub fn init(id: u64, source: Source, endpoint: Endpoint, priority: u32) !Candidate {
        // RFC 8445 candidate priorities must fit in 31 bits; pair arithmetic
        // relies on this bound to remain representable in u64.
        if (id == 0 or priority == 0 or priority > 0x7fffffff or !isPublishable(endpoint)) return error.InvalidCandidate;
        return .{ .id = id, .source = source, .endpoint = endpoint, .priority = priority };
    }
};

pub const CandidateSet = struct {
    candidates: [max_candidates_per_peer]Candidate = undefined,
    length: u8 = 0,

    pub fn add(set: *CandidateSet, candidate: Candidate) !void {
        for (set.slice()) |existing| {
            if (existing.id == candidate.id) return error.DuplicateCandidateId;
            if (existing.endpoint.eql(candidate.endpoint)) return error.DuplicateCandidateEndpoint;
        }
        if (set.length == max_candidates_per_peer) return error.TooManyCandidates;
        set.candidates[set.length] = candidate;
        set.length += 1;
    }

    pub fn slice(set: *const CandidateSet) []const Candidate {
        return set.candidates[0..set.length];
    }
};

pub const PairState = enum {
    waiting,
    probing,
    validated,
    failed,
};

pub const CandidatePair = struct {
    id: u64,
    local: Candidate,
    remote: Candidate,
    priority: u64,
    state: PairState = .waiting,
};

pub const PairScheduler = struct {
    pairs: [max_candidate_pairs]CandidatePair = undefined,
    length: u8 = 0,

    pub fn prepare(
        local: *const CandidateSet,
        remote: *const CandidateSet,
        local_is_controlling: bool,
        maximum_pairs: u8,
    ) !PairScheduler {
        if (maximum_pairs == 0 or maximum_pairs > max_candidate_pairs) return error.InvalidPairLimit;
        var scheduler = PairScheduler{};
        for (local.slice()) |local_candidate| {
            for (remote.slice()) |remote_candidate| {
                if (local_candidate.endpoint.family() != remote_candidate.endpoint.family()) continue;
                if (scheduler.length == max_candidate_pairs) return error.TooManyCandidatePairs;
                const controlling_priority = if (local_is_controlling) local_candidate.priority else remote_candidate.priority;
                const controlled_priority = if (local_is_controlling) remote_candidate.priority else local_candidate.priority;
                scheduler.pairs[scheduler.length] = .{
                    .id = @as(u64, scheduler.length) + 1,
                    .local = local_candidate,
                    .remote = remote_candidate,
                    .priority = pairPriority(controlling_priority, controlled_priority),
                };
                scheduler.length += 1;
            }
        }
        std.mem.sort(CandidatePair, scheduler.pairs[0..scheduler.length], {}, higherPriorityFirst);
        if (scheduler.length > maximum_pairs) scheduler.length = maximum_pairs;
        return scheduler;
    }

    pub fn next(scheduler: *PairScheduler) ?CandidatePair {
        for (scheduler.pairs[0..scheduler.length]) |*pair| {
            if (pair.state != .waiting) continue;
            pair.state = .probing;
            return pair.*;
        }
        return null;
    }

    pub fn recordValidated(scheduler: *PairScheduler, pair_id: u64) !void {
        const pair = scheduler.find(pair_id) orelse return error.UnknownCandidatePair;
        if (pair.state != .probing) return error.InvalidPairTransition;
        pair.state = .validated;
    }

    pub fn recordFailed(scheduler: *PairScheduler, pair_id: u64) !void {
        const pair = scheduler.find(pair_id) orelse return error.UnknownCandidatePair;
        if (pair.state != .probing) return error.InvalidPairTransition;
        pair.state = .failed;
    }

    fn find(scheduler: *PairScheduler, pair_id: u64) ?*CandidatePair {
        for (scheduler.pairs[0..scheduler.length]) |*pair| {
            if (pair.id == pair_id) return pair;
        }
        return null;
    }
};

pub fn defaultPriority(source: Source) u32 {
    return switch (source) {
        .host => 400,
        .peer_reflexive => 300,
        .server_reflexive => 200,
        .relay => 100,
    };
}

fn pairPriority(controlling: u32, controlled: u32) u64 {
    const lower = @min(controlling, controlled);
    const higher = @max(controlling, controlled);
    return (@as(u64, lower) << 32) + 2 * @as(u64, higher) + @intFromBool(controlling > controlled);
}

fn higherPriorityFirst(_: void, lhs: CandidatePair, rhs: CandidatePair) bool {
    if (lhs.priority != rhs.priority) return lhs.priority > rhs.priority;
    if (lhs.local.source != rhs.local.source) return @intFromEnum(lhs.local.source) < @intFromEnum(rhs.local.source);
    return lhs.id < rhs.id;
}

fn isPublishable(endpoint: Endpoint) bool {
    return switch (endpoint) {
        .ipv4 => |value| value.port != 0 and
            !std.mem.allEqual(u8, &value.address, 0) and
            !std.mem.allEqual(u8, &value.address, 0xff) and
            (value.address[0] & 0xf0) != 0xe0,
        .ipv6 => |value| value.port != 0 and
            !std.mem.allEqual(u8, &value.address, 0) and
            value.address[0] != 0xff,
    };
}

fn ipv4Candidate(id: u64, source: Source, address: [4]u8, port: u16) !Candidate {
    return Candidate.init(id, source, .{ .ipv4 = .{ .address = address, .port = port } }, defaultPriority(source));
}

test "wildcard multicast and zero-port candidates are rejected" {
    try std.testing.expectError(error.InvalidCandidate, ipv4Candidate(1, .host, .{ 0, 0, 0, 0 }, 443));
    try std.testing.expectError(error.InvalidCandidate, ipv4Candidate(1, .host, .{ 224, 0, 0, 1 }, 443));
    try std.testing.expectError(error.InvalidCandidate, ipv4Candidate(1, .host, .{ 192, 0, 2, 1 }, 0));
}

test "candidate set rejects duplicate identities and endpoints" {
    var set = CandidateSet{};
    try set.add(try ipv4Candidate(1, .host, .{ 192, 0, 2, 1 }, 443));
    try std.testing.expectError(
        error.DuplicateCandidateId,
        set.add(try ipv4Candidate(1, .host, .{ 192, 0, 2, 2 }, 443)),
    );
    try std.testing.expectError(
        error.DuplicateCandidateEndpoint,
        set.add(try ipv4Candidate(2, .server_reflexive, .{ 192, 0, 2, 1 }, 443)),
    );
}

test "pair scheduler filters address families and probes highest priority first" {
    var local = CandidateSet{};
    try local.add(try ipv4Candidate(1, .host, .{ 10, 0, 0, 1 }, 4000));
    try local.add(try ipv4Candidate(2, .server_reflexive, .{ 198, 51, 100, 1 }, 5000));
    var remote = CandidateSet{};
    try remote.add(try ipv4Candidate(3, .host, .{ 10, 0, 0, 2 }, 4001));
    try remote.add(try Candidate.init(4, .host, .{ .ipv6 = .{
        .address = .{ 0x20, 1, 0x0d, 0xb8 } ++ .{0} ** 12,
        .port = 4001,
    } }, defaultPriority(.host)));

    var scheduler = try PairScheduler.prepare(&local, &remote, true, 8);
    try std.testing.expectEqual(@as(u8, 2), scheduler.length);
    const first = scheduler.next().?;
    try std.testing.expectEqual(Source.host, first.local.source);
    try std.testing.expectEqual(Source.host, first.remote.source);
    try scheduler.recordValidated(first.id);
}

test "pair scheduler applies an explicit pair cap" {
    var local = CandidateSet{};
    var remote = CandidateSet{};
    try local.add(try ipv4Candidate(1, .host, .{ 10, 0, 0, 1 }, 4000));
    try local.add(try ipv4Candidate(2, .server_reflexive, .{ 198, 51, 100, 1 }, 5000));
    try remote.add(try ipv4Candidate(3, .host, .{ 10, 0, 0, 2 }, 4001));
    try remote.add(try ipv4Candidate(4, .server_reflexive, .{ 203, 0, 113, 1 }, 5001));
    const scheduler = try PairScheduler.prepare(&local, &remote, true, 2);
    try std.testing.expectEqual(@as(u8, 2), scheduler.length);
}

test "pair state transitions are explicit" {
    var local = CandidateSet{};
    var remote = CandidateSet{};
    try local.add(try ipv4Candidate(1, .host, .{ 10, 0, 0, 1 }, 4000));
    try remote.add(try ipv4Candidate(2, .host, .{ 10, 0, 0, 2 }, 4001));
    var scheduler = try PairScheduler.prepare(&local, &remote, true, 1);
    try std.testing.expectError(error.InvalidPairTransition, scheduler.recordFailed(1));
    const pair = scheduler.next().?;
    try scheduler.recordFailed(pair.id);
    try std.testing.expect(scheduler.next() == null);
}

test "candidate priority range protects pair arithmetic" {
    const endpoint = Endpoint{ .ipv4 = .{ .address = .{ 192, 0, 2, 1 }, .port = 443 } };
    for ([_]u32{ 0, 0x80000000, 0xffffffff }) |priority| {
        try std.testing.expectError(error.InvalidCandidate, Candidate.init(1, .host, endpoint, priority));
    }
    var local = CandidateSet{};
    var remote = CandidateSet{};
    try local.add(try Candidate.init(1, .host, endpoint, 0x7fffffff));
    try remote.add(try Candidate.init(2, .host, endpoint, 0x7fffffff));
    const scheduler = try PairScheduler.prepare(&local, &remote, true, 1);
    try std.testing.expectEqual(@as(u64, 0x7ffffffffffffffe), scheduler.pairs[0].priority);
    _ = try Candidate.init(3, .host, endpoint, 1);
}
