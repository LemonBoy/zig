const std = @import("std");
const os = std.os;
const warn = std.debug.warn;

pub fn main() !void {
    var file = try os.File.openRead("~/nonExistent/ok.txt");
    defer file.close();

    var buffer: [20]u8 = undefined;
    _ = try file.read(buffer[0..buffer.len]);

    warn("buffer:\n");
    warn("{}", buffer);
}
