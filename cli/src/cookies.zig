//! Netscape cookie jar support for the `h3` subcommand.
//!
//! Implements curl-style `-b @file` (read request cookies from a Netscape
//! cookie jar) and `-c/--cookie-jar FILE` (persist `Set-Cookie` response
//! headers into a Netscape jar). Cookie selection follows RFC 6265
//! domain-match / path-match so jars interchange with curl.

const std = @import("std");

pub const Cookie = struct {
    domain: []const u8, // allocator-owned
    path: []const u8, // allocator-owned
    name: []const u8, // allocator-owned
    value: []const u8, // allocator-owned
    secure: bool,
    expires: i64, // unix seconds; 0 = session cookie
};

/// A mutable set of cookies plus an optional Netscape save target. All Cookie
/// strings are allocator-owned; `deinit` releases them.
pub const CookieJar = struct {
    allocator: std.mem.Allocator,
    cookies: std.ArrayList(Cookie),
    save_path: ?[]const u8 = null, // borrowed; set by the CLI when `-c` is given

    pub fn init(allocator: std.mem.Allocator) CookieJar {
        return .{
            .allocator = allocator,
            .cookies = std.ArrayList(Cookie).empty,
        };
    }

    pub fn deinit(self: *CookieJar) void {
        for (self.cookies.items) |c| freeCookie(self.allocator, c);
        self.cookies.deinit(self.allocator);
        self.* = undefined;
    }

    /// Read an existing Netscape jar into the jar. A missing file is treated
    /// as an empty jar. `save_path` is left untouched.
    pub fn loadFromFile(self: *CookieJar, io: std.Io, path: []const u8) !void {
        const data = readFileAll(self.allocator, io, path) catch |e| switch (e) {
            error.FileNotFound => return,
            else => return e,
        };
        defer self.allocator.free(data);
        const parsed = try parseNetscapeText(self.allocator, data);
        for (parsed) |c| {
            self.cookies.append(self.allocator, c) catch |e| {
                freeCookie(self.allocator, c);
                return e;
            };
        }
        self.allocator.free(parsed);
    }

    /// Write the jar back to `save_path` (Netscape format). No-op unless both
    /// a target path was set and at least one cookie changed.
    pub fn save(self: *CookieJar, io: std.Io) !void {
        const path = self.save_path orelse return;
        const text = try self.toText(self.allocator);
        defer self.allocator.free(text);
        const file = try std.Io.Dir.createFile(.cwd(), io, path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, text);
    }

    /// Parse one `Set-Cookie` response header and upsert it into the jar. The
    /// cookie's default domain (when the header omits `Domain=`) is the
    /// request host; the default path is `/`.
    pub fn addSetCookie(
        self: *CookieJar,
        allocator: std.mem.Allocator,
        now: i64,
        default_domain: []const u8,
        header: []const u8,
    ) !void {
        const c = try parseSetCookie(allocator, now, default_domain, header);
        for (self.cookies.items, 0..) |existing, i| {
            if (asciiEqualIgnoreCase(existing.domain, c.domain) and
                std.mem.eql(u8, existing.path, c.path) and
                std.mem.eql(u8, existing.name, c.name))
            {
                freeCookie(self.allocator, existing);
                self.cookies.items[i] = c;
                return;
            }
        }
        self.cookies.append(self.allocator, c) catch |e| {
            freeCookie(self.allocator, c);
            return e;
        };
    }

    /// Build a `name=value; name2=value2` header value for the cookies
    /// matching `host` / `path`, or null when none match. The result is
    /// allocator-owned and must be freed by the caller.
    pub fn headerFor(
        self: *const CookieJar,
        allocator: std.mem.Allocator,
        now: i64,
        host: []const u8,
        path: []const u8,
    ) !?[]u8 {
        var parts = std.ArrayList([]u8).empty;
        defer {
            for (parts.items) |p| allocator.free(p);
            parts.deinit(allocator);
        }
        for (self.cookies.items) |c| {
            if (c.expires > 0 and c.expires < now) continue; // expired
            if (!domainMatches(host, c.domain)) continue;
            if (!pathMatches(path, c.path)) continue;
            const part = try std.fmt.allocPrint(allocator, "{s}={s}", .{ c.name, c.value });
            parts.append(allocator, part) catch |e| {
                allocator.free(part);
                return e;
            };
        }
        if (parts.items.len == 0) return null;
        var out = std.ArrayList(u8).empty;
        defer out.deinit(allocator);
        for (parts.items, 0..) |p, i| {
            if (i > 0) try out.appendSlice(allocator, "; ");
            try out.appendSlice(allocator, p);
        }
        const owned = try out.toOwnedSlice(allocator);
        return owned;
    }

    /// Render the jar in Netscape cookie file format.
    pub fn toText(self: *const CookieJar, allocator: std.mem.Allocator) ![]u8 {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(allocator);
        try out.appendSlice(allocator, "# Netscape HTTP Cookie File\n");
        try out.appendSlice(allocator, "# https://curl.se/docs/http-cookies.html\n");
        try out.appendSlice(allocator, "# This file was generated by quicz! Edit at your own risk.\n");
        for (self.cookies.items) |c| {
            const include_sub = if (c.domain.len > 0 and c.domain[0] == '.') "TRUE" else "FALSE";
            const secure = if (c.secure) "TRUE" else "FALSE";
            const line = try std.fmt.allocPrint(
                allocator,
                "{s}\t{s}\t{s}\t{s}\t{d}\t{s}\t{s}\n",
                .{ c.domain, include_sub, c.path, secure, c.expires, c.name, c.value },
            );
            defer allocator.free(line);
            try out.appendSlice(allocator, line);
        }
        const owned = try out.toOwnedSlice(allocator);
        return owned;
    }
};

fn freeCookie(allocator: std.mem.Allocator, c: Cookie) void {
    allocator.free(c.domain);
    allocator.free(c.path);
    allocator.free(c.name);
    allocator.free(c.value);
}

fn readFileAll(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    const file = try std.Io.Dir.openFile(.cwd(), io, path, .{});
    defer file.close(io);
    const len = try file.length(io);
    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);
    const n = try file.readPositionalAll(io, buf, 0);
    return buf[0..n];
}

/// Parse the cookies of a Netscape cookie file into allocator-owned cookies.
/// Blank lines and `#` comments are ignored; malformed rows are skipped.
pub fn parseNetscapeText(allocator: std.mem.Allocator, text: []const u8) ![]Cookie {
    var list = std.ArrayList(Cookie).empty;
    errdefer {
        for (list.items) |c| freeCookie(allocator, c);
        list.deinit(allocator);
    }
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.splitScalar(u8, line, '\t');
        const domain = fields.next() orelse continue;
        _ = fields.next() orelse continue; // include_subdomains
        const path = fields.next() orelse continue;
        const secure_raw = fields.next() orelse continue;
        const expires_raw = fields.next() orelse continue;
        const name = fields.next() orelse continue;
        const value = fields.next() orelse continue;
        if (fields.next() != null) continue; // too many fields
        if (domain.len == 0 or name.len == 0) continue;
        const expires = std.fmt.parseInt(i64, expires_raw, 10) catch 0;
        try list.append(allocator, .{
            .domain = try allocator.dupe(u8, domain),
            .path = try allocator.dupe(u8, path),
            .name = try allocator.dupe(u8, name),
            .value = try allocator.dupe(u8, value),
            .secure = std.mem.eql(u8, secure_raw, "TRUE"),
            .expires = expires,
        });
    }
    return list.toOwnedSlice(allocator);
}

/// Parse a single `Set-Cookie` header into an allocator-owned cookie.
/// Unsupported or malformed attributes fall back to safe defaults
/// (no path -> `/`, no domain -> `default_domain`, unparseable expiry and no
/// Max-Age/Expires -> session cookie). RFC 6265 §4.1/§5.2.
pub fn parseSetCookie(
    allocator: std.mem.Allocator,
    now: i64,
    default_domain: []const u8,
    header: []const u8,
) !Cookie {
    var name: []const u8 = "";
    var value: []const u8 = "";
    var path: []const u8 = "/";
    var domain: []const u8 = default_domain;
    var secure = false;
    var expires: i64 = 0;
    var max_age: ?i64 = null;

    var first = true;
    var it = std.mem.splitScalar(u8, header, ';');
    while (it.next()) |raw_seg| {
        const seg = std.mem.trim(u8, raw_seg, " \t");
        if (seg.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, seg, '=');
        const key = std.mem.trim(u8, if (eq) |e| seg[0..e] else seg, " \t");
        const val = std.mem.trim(u8, if (eq) |e| seg[e + 1 ..] else "", " \t");
        if (first) {
            first = false;
            if (eq == null or key.len == 0) return error.InvalidCookie;
            name = key;
            value = val;
            continue;
        }
        if (asciiEqualIgnoreCase(key, "path")) {
            if (val.len > 0) path = val;
        } else if (asciiEqualIgnoreCase(key, "domain")) {
            if (val.len > 0) domain = val;
        } else if (asciiEqualIgnoreCase(key, "secure")) {
            secure = true;
        } else if (asciiEqualIgnoreCase(key, "max-age")) {
            max_age = std.fmt.parseInt(i64, val, 10) catch null;
        } else if (asciiEqualIgnoreCase(key, "expires")) {
            if (max_age == null) {
                if (parseHttpDate(val)) |e| expires = e;
            }
        }
    }
    if (max_age) |ma| expires = now + ma;

    return .{
        .domain = try allocator.dupe(u8, domain),
        .path = try allocator.dupe(u8, path),
        .name = try allocator.dupe(u8, name),
        .value = try allocator.dupe(u8, value),
        .secure = secure,
        .expires = expires,
    };
}

/// RFC 6265 §5.1.3 domain-match: the request host equals the cookie domain or
/// ends with the domain preceded by a dot. A leading dot on the cookie domain
/// is only a subdomain hint and does not affect matching. Comparison is
/// case-insensitive.
fn domainMatches(host: []const u8, domain: []const u8) bool {
    if (domain.len == 0) return false;
    const d = if (domain[0] == '.') domain[1..] else domain;
    if (d.len == 0) return false;
    if (asciiEqualIgnoreCase(host, d)) return true;
    if (d.len >= host.len) return false;
    const suffix = host[host.len - d.len ..];
    if (!asciiEqualIgnoreCase(suffix, d)) return false;
    return host[host.len - d.len - 1] == '.';
}

/// RFC 6265 §5.1.4 path-match: the request path equals the cookie path or is
/// a path within it (segment-aligned).
fn pathMatches(path: []const u8, cookie_path: []const u8) bool {
    if (cookie_path.len == 0) return true;
    if (std.mem.eql(u8, path, cookie_path)) return true;
    if (!std.mem.startsWith(u8, path, cookie_path)) return false;
    if (cookie_path[cookie_path.len - 1] == '/') return true;
    return path.len > cookie_path.len and path[cookie_path.len] == '/';
}

fn asciiEqualIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

/// Parse an HTTP-date (RFC 9110 §5.6.7), e.g.
/// `Wed, 21 Oct 2015 07:28:00 GMT`, into unix seconds. Returns null for
/// anything it cannot parse.
fn parseHttpDate(s: []const u8) ?i64 {
    const comma = std.mem.indexOfScalar(u8, s, ',') orelse return null;
    var it = std.mem.tokenizeAny(u8, s[comma + 1 ..], " ");
    const day = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
    const month = monthIndex(it.next() orelse return null) orelse return null;
    const year = std.fmt.parseInt(u16, it.next() orelse return null, 10) catch return null;
    const time = it.next() orelse return null;
    var colons = std.mem.splitScalar(u8, time, ':');
    const hour = std.fmt.parseInt(u8, colons.next() orelse return null, 10) catch return null;
    const minute = std.fmt.parseInt(u8, colons.next() orelse return null, 10) catch return null;
    const second = std.fmt.parseInt(u8, colons.next() orelse return null, 10) catch return null;
    if (year < 1970 or month < 1 or month > 12 or day < 1 or day > 31) return null;
    if (hour > 23 or minute > 59 or second > 60) return null;
    const days = daysSinceEpoch(year, month, day) orelse return null;
    return @as(i64, days) * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
}

fn monthIndex(name: []const u8) ?u8 {
    const months = [_][]const u8{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };
    for (months, 0..) |m, i| {
        if (std.mem.eql(u8, name, m)) return @intCast(i + 1);
    }
    return null;
}

/// Days between 1970-01-01 (day 0) and the given date, or null for invalid
/// dates. Months are 1-based.
fn daysSinceEpoch(year: u16, month: u8, day: u8) ?i64 {
    if (month < 1 or month > 12 or day < 1 or day > 31) return null;
    const mdays = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (day > mdays[month - 1]) {
        // Allow Feb 29 only in leap years.
        if (!(month == 2 and day == 29 and isLeap(year))) return null;
    }
    var days: i64 = 0;
    var y: u16 = 1970;
    while (y < year) : (y += 1) {
        days += if (isLeap(y)) 366 else 365;
    }
    var m: u8 = 0;
    while (m < month - 1) : (m += 1) {
        days += mdays[m];
        if (m == 1 and isLeap(year)) days += 1;
    }
    days += @as(i64, day) - 1;
    return days;
}

fn isLeap(year: u16) bool {
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0);
}

test "parse netscape text" {
    const allocator = std.testing.allocator;
    const text =
        "# Netscape HTTP Cookie File\n" ++
        "# https://curl.se/docs/http-cookies.html\n" ++
        "\n" ++
        ".example.com\tTRUE\t/\tFALSE\t0\tsid\tabc123\n" ++
        "example.com\tTRUE\t/\tTRUE\t1893456000\tprefs\tlang=en\n" ++
        "bad-line-without-tabs\n";
    const cookies_list = try parseNetscapeText(allocator, text);
    defer {
        for (cookies_list) |c| freeCookie(allocator, c);
        allocator.free(cookies_list);
    }
    try std.testing.expectEqual(@as(usize, 2), cookies_list.len);
    try std.testing.expectEqualStrings(".example.com", cookies_list[0].domain);
    try std.testing.expectEqualStrings("/", cookies_list[0].path);
    try std.testing.expectEqualStrings("sid", cookies_list[0].name);
    try std.testing.expectEqualStrings("abc123", cookies_list[0].value);
    try std.testing.expectEqual(@as(i64, 0), cookies_list[0].expires);
    try std.testing.expect(!cookies_list[0].secure);
    try std.testing.expect(cookies_list[1].secure);
    try std.testing.expectEqual(@as(i64, 1893456000), cookies_list[1].expires);
}

test "parse set-cookie header" {
    const allocator = std.testing.allocator;
    const c = try parseSetCookie(
        allocator,
        1_700_000_000,
        "api.example.com",
        "session=xyz; Path=/app; Domain=.example.com; Secure; Max-Age=3600",
    );
    defer freeCookie(allocator, c);
    try std.testing.expectEqualStrings("session", c.name);
    try std.testing.expectEqualStrings("xyz", c.value);
    try std.testing.expectEqualStrings("/app", c.path);
    try std.testing.expectEqualStrings(".example.com", c.domain);
    try std.testing.expect(c.secure);
    try std.testing.expectEqual(@as(i64, 1_700_003_600), c.expires);

    const c2 = try parseSetCookie(allocator, 100, "api.example.com", "n=v; Expires=Wed, 21 Oct 2015 07:28:00 GMT");
    defer freeCookie(allocator, c2);
    try std.testing.expectEqualStrings("api.example.com", c2.domain); // default domain
    try std.testing.expectEqualStrings("/", c2.path); // default path
    // 2015-10-21T07:28:00Z = 1445412480
    try std.testing.expectEqual(@as(i64, 1445412480), c2.expires);
}

test "domain and path matching" {
    try std.testing.expect(domainMatches("www.example.com", ".example.com"));
    try std.testing.expect(domainMatches("example.com", ".example.com"));
    try std.testing.expect(domainMatches("example.com", "example.com"));
    try std.testing.expect(domainMatches("sub.example.com", "example.com"));
    try std.testing.expect(!domainMatches("example.org", ".example.com"));
    try std.testing.expect(!domainMatches("notexample.com", "example.com"));
    try std.testing.expect(!domainMatches("", "example.com"));

    try std.testing.expect(pathMatches("/a/b", "/a"));
    try std.testing.expect(pathMatches("/a", "/a"));
    try std.testing.expect(pathMatches("/a/b", "/"));
    try std.testing.expect(pathMatches("/a/b/c", "/a/b/"));
    try std.testing.expect(!pathMatches("/abc", "/a"));
    try std.testing.expect(!pathMatches("/a", "/a/b"));
}

test "cookie jar upsert, matching, and round trip" {
    const allocator = std.testing.allocator;
    var jar = CookieJar.init(allocator);
    defer jar.deinit();

    try jar.addSetCookie(allocator, 100, "www.example.com", "sid=abc; Path=/; Domain=.example.com");
    try jar.addSetCookie(allocator, 100, "www.example.com", "theme=dark; Path=/");
    // Same (domain, path, name) replaces the old value.
    try jar.addSetCookie(allocator, 100, "www.example.com", "sid=def; Path=/; Domain=.example.com");
    try std.testing.expectEqual(@as(usize, 2), jar.cookies.items.len);

    // Matching header for www.example.com contains both; unrelated host none.
    const hdr = (try jar.headerFor(allocator, 1, "www.example.com", "/")) orelse return error.TestUnexpectedResult;
    defer allocator.free(hdr);
    try std.testing.expectEqualStrings("sid=def; theme=dark", hdr);
    try std.testing.expectEqual(
        null,
        try jar.headerFor(allocator, 1, "other.example.net", "/"),
    );

    // Path filtering.
    try jar.addSetCookie(allocator, 100, "www.example.com", "app=1; Path=/app");
    const root_hdr = (try jar.headerFor(allocator, 1, "www.example.com", "/")) orelse return error.TestUnexpectedResult;
    defer allocator.free(root_hdr);
    try std.testing.expect(std.mem.indexOf(u8, root_hdr, "app=1") == null);
    const app_hdr = (try jar.headerFor(allocator, 1, "www.example.com", "/app/x")) orelse return error.TestUnexpectedResult;
    defer allocator.free(app_hdr);
    try std.testing.expect(std.mem.indexOf(u8, app_hdr, "app=1") != null);

    // Expired cookies are not sent.
    try jar.addSetCookie(allocator, 100, "www.example.com", "old=gone; Path=/; Max-Age=1");
    const now_hdr = (try jar.headerFor(allocator, 200, "www.example.com", "/")) orelse return error.TestUnexpectedResult;
    defer allocator.free(now_hdr);
    try std.testing.expect(std.mem.indexOf(u8, now_hdr, "old=gone") == null);

    // Netscape text round trip preserves cookies.
    const text = try jar.toText(allocator);
    defer allocator.free(text);
    const reparsed = try parseNetscapeText(allocator, text);
    defer {
        for (reparsed) |c| freeCookie(allocator, c);
        allocator.free(reparsed);
    }
    try std.testing.expectEqual(jar.cookies.items.len, reparsed.len);
}

test "cookie jar module" {
    _ = @import("cookies.zig");
}
