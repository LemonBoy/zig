// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2021 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("std");
const builtin = std.builtin;
const assert = std.debug.assert;
const mem = std.mem;
const os = std.os;
const net = std.net;
const testing = std.testing;

pub const IPv4 = extern struct {
    inner: [4]u8,

    pub const SockaddrType = os.sockaddr_in;

    pub const ParseError = error{
        InvalidCharacter,
        InvalidEnd,
        Incomplete,
        Overflow,
    };

    pub fn eql(a: IPv4, b: IPv4) bool {
        return mem.eql(u8, a.inner, b.inner);
    }

    pub fn format(
        self: IPv4,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        if (fmt.len != 0 and fmt[0] != 's')
            @compileError("Unsupported format specifier for IPv4 type '" ++ fmt ++ "'");

        try std.fmt.format(writer, "{}.{}.{}.{}", .{
            self.inner[0],
            self.inner[1],
            self.inner[2],
            self.inner[3],
        });
    }

    pub fn fromString(buf: []const u8) ParseError!IPv4 {
        var octects: [4]u8 = undefined;

        var x: u8 = 0;
        var index: u8 = 0;
        var saw_any_digits = false;
        for (buf) |c| {
            if (c == '.') {
                if (!saw_any_digits) {
                    return error.InvalidCharacter;
                }
                if (index == 3) {
                    return error.InvalidEnd;
                }
                octects[index] = x;
                index += 1;
                x = 0;
                saw_any_digits = false;
            } else if (c >= '0' and c <= '9') {
                saw_any_digits = true;
                x = try std.math.mul(u8, x, 10);
                x = try std.math.add(u8, x, c - '0');
            } else {
                return error.InvalidCharacter;
            }
        }
        if (index == 3 and saw_any_digits) {
            octects[index] = x;
            return IPv4{ .inner = octects };
        }

        return error.Incomplete;
    }

    pub fn isLoopback(self: IPv4) bool {
        return self.inner[0] == 127;
    }
};

pub const IPv6 = extern struct {
    inner: [16]u8,
    scope_id: u32 = NO_SCOPE_ID,

    const NO_SCOPE_ID = std.math.maxInt(u32);

    const V4MappedPrefix = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    const Loopback = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    pub const SockaddrType = os.sockaddr_in6;

    pub const ParseError = error{
        InvalidCharacter,
        InvalidEnd,
        Incomplete,
        InvalidIpv4Mapping,
        Overflow,
    };

    pub fn eql(a: IPv6, b: IPv6) bool {
        return (a.scope_id == NO_SCOPE_ID or a.scope_id == b.scope_id) and
            mem.eql(u8, a.inner, b.inner);
    }

    pub fn format(
        self: IPv6,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        if (fmt.len != 0 and fmt[0] != 's')
            @compileError("Unsupported format specifier for IPv4 type '" ++ fmt ++ "')");

        if (mem.startsWith(u8, &self.inner, &V4MappedPrefix)) {
            return std.fmt.format(writer, "::ffff:{}.{}.{}.{}", .{
                self.inner[12],
                self.inner[13],
                self.inner[14],
                self.inner[15],
            });
        }

        // The longest sequence of consecutive all-zero fields is replaced with
        // two colons ("::"). If the address contains multiple runs of all-zero
        // fields, then it is the leftmost that is compressed to prevent
        // ambiguities.
        const zero_span = span: {
            var i: usize = 0;
            while (i < self.inner.len) : (i += 2) {
                if (self.inner[i] == 0 and self.inner[i + 1] == 0) break;
            } else break :span .{ .from = 0, .to = 0 };

            const from = i;

            while (i < self.inner.len) : (i += 2) {
                if (self.inner[i] != 0 or self.inner[i + 1] != 0) break;
            }

            break :span .{ .from = from, .to = i };
        };

        var i: usize = 0;
        while (i != 16) : (i += 2) {
            if (zero_span.from != zero_span.to and i == zero_span.from) {
                try writer.writeAll("::");
            } else if (i >= zero_span.from and i < zero_span.to) {} else {
                if (i != 0 and i != zero_span.to)
                    try writer.writeAll(":");

                const val = @as(u16, self.inner[i]) << 8 | self.inner[i + 1];
                try std.fmt.formatIntValue(val, "x", .{}, writer);
            }
        }
    }

    pub fn fromString(buf: []const u8) ParseError!IPv6 {
        return parseInner(buf, NO_SCOPE_ID);
    }

    pub fn fromStringWithScope(buf: []const u8) (ParseError || error{InvalidScope})!IPv6 {
        // The optional scope id follows the canonical IPv6 representation, the
        // two are separated by a single '%' character.
        if (mem.lastIndexOfScalar(u8, buf, '%')) |pct_index| {
            const ip_part = buf[0..pct_index];
            const scope_part = buf[pct_index + 1 ..];

            if (scope_part.len < 1)
                return error.Incomplete;

            // The scope is either numerical or a network interface name.
            const scope_id: u32 = switch (scope_part[0]) {
                '0'...'9' => std.fmt.parseInt(u32, scope_part, 10) catch
                    return error.InvalidScope,
                else => net.if_nametoindex(scope_part) catch
                    return error.InvalidScope,
            };

            return parseInner(ip_part, scope_id);
        }

        return parseInner(buf, NO_SCOPE_ID);
    }

    fn parseInner(buf: []const u8, scope_id: u32) ParseError!IPv6 {
        var octects: [16]u8 = undefined;
        var tail: [16]u8 = undefined;
        var out_slice: []u8 = &octects;

        var x: u16 = 0;
        var saw_any_digits = false;
        var index: u8 = 0;
        var abbrv = false;
        for (buf) |c, i| {
            if (c == ':') {
                if (!saw_any_digits) {
                    if (abbrv) return error.InvalidCharacter; // ':::'
                    if (i != 0) abbrv = true;
                    mem.set(u8, out_slice[index..], 0);
                    out_slice = &tail;
                    index = 0;
                    continue;
                }
                if (index == 14) {
                    return error.InvalidEnd;
                }
                out_slice[index] = @truncate(u8, x >> 8);
                index += 1;
                out_slice[index] = @truncate(u8, x);
                index += 1;

                x = 0;
                saw_any_digits = false;
            } else if (c == '.') {
                if (!abbrv or out_slice[0] != 0xff or out_slice[1] != 0xff) {
                    // must start with '::ffff:'
                    return error.InvalidIpv4Mapping;
                }
                const start_index = mem.lastIndexOfScalar(u8, buf[0..i], ':').? + 1;
                const v4 = (IPv4.fromString(buf[start_index..]) catch {
                    return error.InvalidIpv4Mapping;
                }).inner;
                octects[10] = 0xff;
                octects[11] = 0xff;

                octects[12] = v4[0];
                octects[13] = v4[1];
                octects[14] = v4[2];
                octects[15] = v4[3];

                return IPv6{ .inner = octects, .scope_id = scope_id };
            } else {
                saw_any_digits = true;
                const digit = try std.fmt.charToDigit(c, 16);
                x = try std.math.mul(u16, x, 16);
                x = try std.math.add(u16, x, digit);
            }
        }

        if (!saw_any_digits and !abbrv) {
            return error.Incomplete;
        }

        if (index == 14) {
            out_slice[14] = @truncate(u8, x >> 8);
            out_slice[15] = @truncate(u8, x);
        } else {
            out_slice[index] = @truncate(u8, x >> 8);
            index += 1;
            out_slice[index] = @truncate(u8, x);
            index += 1;
            mem.copy(u8, octects[16 - index ..], out_slice[0..index]);
        }

        return IPv6{ .inner = octects, .scope_id = scope_id };
    }

    pub fn isV4Mapped(self: IPv6) bool {
        return mem.startsWith(u8, &self.inner, &V4MappedPrefix);
    }

    pub fn isLoopback(self: IPv6) bool {
        return mem.eql(u8, &self.inner, &LoopbackPrefix);
    }
};

test "v4: parse&render" {
    if (builtin.os.tag == .wasi)
        return error.SkipZigTest;

    const ips = [_][]const u8{
        "0.0.0.0",
        "255.255.255.255",
        "1.2.3.4",
        "123.255.0.91",
        "127.0.0.1",
    };
    for (ips) |ip| {
        try testing.expectFmt(ip, "{}", .{try IPv4.fromString(ip)});
    }
}

test "v6: parse&render" {
    if (builtin.os.tag == .wasi)
        return error.SkipZigTest;

    const ips = [_][]const u8{
        "FF01:0:0:0:0:0:0:FB",
        "FF01::Fb",
        "::1",
        "::",
        "2001:db8::",
        "::1234:5678",
        "2001:db8::1234:5678",
        "::ffff:123.5.123.5",
        "FF01::FB%wlp3s0",
    };
    const printed = [_][]const u8{
        "ff01::fb",
        "ff01::fb",
        "::1",
        "::",
        "2001:db8::",
        "::1234:5678",
        "2001:db8::1234:5678",
        "::ffff:123.5.123.5",
        "ff01::fb",
    };
    for (ips) |ip, i| {
        try testing.expectFmt(printed[i], "{}", .{try IPv6.fromStringWithScope(ip)});
    }
}
