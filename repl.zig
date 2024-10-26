const std = @import("std");
const Token = @import("token.zig").Token;
const Lexer = @import("lexer.zig").Lexer;

const PROMPT = ">> ";

pub fn start(reader: anytype, writer: anytype) !void {
    var buf: [1024]u8 = undefined;

    while (true) {
        // Print prompt
        try writer.print(PROMPT, .{});

        // Read line
        if (try reader.readUntilDelimiterOrEof(&buf, '\n')) |line| {
            // Create new lexer
            var l = Lexer.init(line);

            // Print tokens until EOF
            while (true) {
                const tok = l.nextToken();
                try writer.print("{any}\n", .{tok});

                if (tok.type == .EOF) {
                    break;
                }
            }
        } else {
            break;
        }
    }
}
