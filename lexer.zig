const std = @import("std");
const Token = @import("token.zig").Token;
const TokenType = @import("token.zig").TokenType;

pub const Lexer = struct {
    input: []const u8,
    position: usize,
    read_position: usize,
    ch: u8,

    // Constructor
    pub fn init(input: []const u8) Lexer {
        var l = Lexer{
            .input = input,
            .position = 0,
            .read_position = 0,
            .ch = 0,
        };
        l.readChar();
        return l;
    }

    fn readChar(self: *Lexer) void {
        if (self.read_position >= self.input.len) {
            self.ch = 0;
        } else {
            self.ch = self.input[self.read_position];
        }
        self.position = self.read_position;
        self.read_position += 1;
    }

    pub fn nextToken(self: *Lexer) Token {
        self.skipWhitespace();

        const tok: Token = switch (self.ch) {
            '=' => blk: {
                if (self.peekChar() == '=') {
                    self.readChar();
                    break :blk Token.init(.EQ, "==");
                } else {
                    break :blk Token.init(.ASSIGN, "=");
                }
            },
            '+' => Token.init(.PLUS, "+"),
            '(' => Token.init(.LPAREN, "("),
            ')' => Token.init(.RPAREN, ")"),
            '{' => Token.init(.LBRACE, "{"),
            '}' => Token.init(.RBRACE, "}"),
            ',' => Token.init(.COMMA, ","),
            ';' => Token.init(.SEMICOLON, ";"),
            '-' => Token.init(.MINUS, "-"),
            '!' => blk: {
                if (self.peekChar() == '=') {
                    self.readChar();
                    break :blk Token.init(.NOT_EQ, "!=");
                } else {
                    break :blk Token.init(.BANG, "!");
                }
            },
            '*' => Token.init(.ASTERISK, "*"),
            '/' => Token.init(.SLASH, "/"),
            '<' => Token.init(.LT, "<"),
            '>' => Token.init(.GT, ">"),
            0 => Token.init(.EOF, ""),
            else => {
                if (isLetter(self.ch)) {
                    const literal = self.readIdentifier();
                    return Token.init(lookupIdent(literal), literal);
                } else if (isDigit(self.ch)) {
                    const literal = self.readNumber();
                    return Token.init(.INT, literal);
                } else {
                    return Token.init(.ILLEGAL, &[_]u8{self.ch});
                }
            },
        };

        self.readChar();
        return tok;
    }

    fn readIdentifier(self: *Lexer) []const u8 {
        const position = self.position;
        while (isLetter(self.ch)) {
            self.readChar();
        }
        return self.input[position..self.position];
    }

    fn isLetter(ch: u8) bool {
        return ('a' <= ch and ch <= 'z') or
            ('A' <= ch and ch <= 'Z') or
            ch == '_';
    }

    fn lookupIdent(ident: []const u8) TokenType {
        const keywords = std.StaticStringMap(TokenType).initComptime(.{
            .{ "fn", .FUNCTION },
            .{ "let", .LET },
            .{ "true", .TRUE },
            .{ "false", .FALSE },
            .{ "if", .IF },
            .{ "else", .ELSE },
            .{ "return", .RETURN },
        });

        return keywords.get(ident) orelse .IDENT;
    }

    fn skipWhitespace(self: *Lexer) void {
        while (self.ch == ' ' or self.ch == '\t' or self.ch == '\n' or self.ch == '\r') {
            self.readChar();
        }
    }

    fn readNumber(self: *Lexer) []const u8 {
        const position = self.position;
        while (isDigit(self.ch)) {
            self.readChar();
        }
        return self.input[position..self.position];
    }

    fn isDigit(ch: u8) bool {
        return '0' <= ch and ch <= '9';
    }

    fn peekChar(self: *Lexer) u8 {
        if (self.read_position >= self.input.len) {
            return 0;
        } else {
            return self.input[self.read_position];
        }
    }
};

// Test cases
test "test next token" {
    const input =
        \\let five = 5;
        \\let ten = 10;
        \\
        \\let add = fn(x, y) {
        \\  x + y;
        \\};
        \\
        \\let result = add(five, ten);
        \\!-/*5;
        \\5 < 10 > 5;
        \\
        \\if (5 < 10) {
        \\  return true;
        \\} else {
        \\  return false;
        \\}
        \\
        \\10 == 10;
        \\10 != 9;
    ;

    const TestCase = struct {
        expected_type: TokenType,
        expected_literal: []const u8,
    };

    const test_cases = [_]TestCase{
        .{ .expected_type = .LET, .expected_literal = "let" },
        .{ .expected_type = .IDENT, .expected_literal = "five" },
        .{ .expected_type = .ASSIGN, .expected_literal = "=" },
        .{ .expected_type = .INT, .expected_literal = "5" },
        .{ .expected_type = .SEMICOLON, .expected_literal = ";" },
        .{ .expected_type = .LET, .expected_literal = "let" },
        .{ .expected_type = .IDENT, .expected_literal = "ten" },
        .{ .expected_type = .ASSIGN, .expected_literal = "=" },
        .{ .expected_type = .INT, .expected_literal = "10" },
        .{ .expected_type = .SEMICOLON, .expected_literal = ";" },
        .{ .expected_type = .LET, .expected_literal = "let" },
        .{ .expected_type = .IDENT, .expected_literal = "add" },
        .{ .expected_type = .ASSIGN, .expected_literal = "=" },
        .{ .expected_type = .FUNCTION, .expected_literal = "fn" },
        .{ .expected_type = .LPAREN, .expected_literal = "(" },
        .{ .expected_type = .IDENT, .expected_literal = "x" },
        .{ .expected_type = .COMMA, .expected_literal = "," },
        .{ .expected_type = .IDENT, .expected_literal = "y" },
        .{ .expected_type = .RPAREN, .expected_literal = ")" },
        .{ .expected_type = .LBRACE, .expected_literal = "{" },
        .{ .expected_type = .IDENT, .expected_literal = "x" },
        .{ .expected_type = .PLUS, .expected_literal = "+" },
        .{ .expected_type = .IDENT, .expected_literal = "y" },
        .{ .expected_type = .SEMICOLON, .expected_literal = ";" },
        .{ .expected_type = .RBRACE, .expected_literal = "}" },
        .{ .expected_type = .SEMICOLON, .expected_literal = ";" },
        .{ .expected_type = .LET, .expected_literal = "let" },
        .{ .expected_type = .IDENT, .expected_literal = "result" },
        .{ .expected_type = .ASSIGN, .expected_literal = "=" },
        .{ .expected_type = .IDENT, .expected_literal = "add" },
        .{ .expected_type = .LPAREN, .expected_literal = "(" },
        .{ .expected_type = .IDENT, .expected_literal = "five" },
        .{ .expected_type = .COMMA, .expected_literal = "," },
        .{ .expected_type = .IDENT, .expected_literal = "ten" },
        .{ .expected_type = .RPAREN, .expected_literal = ")" },
        .{ .expected_type = .SEMICOLON, .expected_literal = ";" },
        .{ .expected_type = .BANG, .expected_literal = "!" },
        .{ .expected_type = .MINUS, .expected_literal = "-" },
        .{ .expected_type = .SLASH, .expected_literal = "/" },
        .{ .expected_type = .ASTERISK, .expected_literal = "*" },
        .{ .expected_type = .INT, .expected_literal = "5" },
        .{ .expected_type = .SEMICOLON, .expected_literal = ";" },
        .{ .expected_type = .INT, .expected_literal = "5" },
        .{ .expected_type = .LT, .expected_literal = "<" },
        .{ .expected_type = .INT, .expected_literal = "10" },
        .{ .expected_type = .GT, .expected_literal = ">" },
        .{ .expected_type = .INT, .expected_literal = "5" },
        .{ .expected_type = .SEMICOLON, .expected_literal = ";" },
        .{ .expected_type = .IF, .expected_literal = "if" },
        .{ .expected_type = .LPAREN, .expected_literal = "(" },
        .{ .expected_type = .INT, .expected_literal = "5" },
        .{ .expected_type = .LT, .expected_literal = "<" },
        .{ .expected_type = .INT, .expected_literal = "10" },
        .{ .expected_type = .RPAREN, .expected_literal = ")" },
        .{ .expected_type = .LBRACE, .expected_literal = "{" },
        .{ .expected_type = .RETURN, .expected_literal = "return" },
        .{ .expected_type = .TRUE, .expected_literal = "true" },
        .{ .expected_type = .SEMICOLON, .expected_literal = ";" },
        .{ .expected_type = .RBRACE, .expected_literal = "}" },
        .{ .expected_type = .ELSE, .expected_literal = "else" },
        .{ .expected_type = .LBRACE, .expected_literal = "{" },
        .{ .expected_type = .RETURN, .expected_literal = "return" },
        .{ .expected_type = .FALSE, .expected_literal = "false" },
        .{ .expected_type = .SEMICOLON, .expected_literal = ";" },
        .{ .expected_type = .RBRACE, .expected_literal = "}" },
        .{ .expected_type = .INT, .expected_literal = "10" },
        .{ .expected_type = .EQ, .expected_literal = "==" },
        .{ .expected_type = .INT, .expected_literal = "10" },
        .{ .expected_type = .SEMICOLON, .expected_literal = ";" },
        .{ .expected_type = .INT, .expected_literal = "10" },
        .{ .expected_type = .NOT_EQ, .expected_literal = "!=" },
        .{ .expected_type = .INT, .expected_literal = "9" },
        .{ .expected_type = .SEMICOLON, .expected_literal = ";" },
        .{ .expected_type = .EOF, .expected_literal = "" },
    };

    var l = Lexer.init(input);

    for (test_cases) |
        tc,
    | {
        const tok = l.nextToken();

        try std.testing.expectEqual(tc.expected_type, tok.type);

        try std.testing.expectEqualStrings(tc.expected_literal, tok.literal);
    }
}
