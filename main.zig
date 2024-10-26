const std = @import("std");
const repl = @import("repl.zig");

pub fn main() !void {
    // Get current username
    const username = "user";

    const stdout = std.io.getStdOut().writer();
    try stdout.print("Hello {s}! This is the Monkey programming language!\n", .{username});
    try stdout.print("Feel free to type in commands\n", .{});

    try repl.start(std.io.getStdIn().reader(), stdout);
}
