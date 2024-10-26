const std = @import("std");

// Define the TokenType as an enum
pub const TokenType = enum {
    ILLEGAL,
    EOF,
    // Identifiers + literals
    IDENT, // add, foobar, x, y, ...
    INT, // 1343456
    // Operators
    ASSIGN,
    PLUS,
    MINUS,
    BANG,
    ASTERISK,
    SLASH,
    LT,
    GT,
    // Delimiters
    COMMA,
    SEMICOLON,
    LPAREN,
    RPAREN,
    LBRACE,
    RBRACE,
    // Keywords
    FUNCTION,
    LET,
    TRUE,
    FALSE,
    IF,
    ELSE,
    RETURN,
    EQ,
    NOT_EQ,

    pub fn toString(self: TokenType) []const u8 {
        return switch (self) {
            .ILLEGAL => "ILLEGAL",
            .EOF => "EOF",
            .IDENT => "IDENT",
            .INT => "INT",
            .ASSIGN => "ASSIGN",
            .PLUS => "PLUS",
            .MINUS => "MINUS",
            .BANG => "BANG",
            .ASTERISK => "ASTERISK",
            .SLASH => "SLASH",
            .LT => "LT",
            .GT => "GT",
            .COMMA => "COMMA",
            .SEMICOLON => "SEMICOLON",
            .LPAREN => "LPAREN",
            .RPAREN => "RPAREN",
            .LBRACE => "LBRACE",
            .RBRACE => "RBRACE",
            .FUNCTION => "FUNCTION",
            .LET => "LET",
            .TRUE => "TRUE",
            .FALSE => "FALSE",
            .IF => "IF",
            .ELSE => "ELSE",
            .RETURN => "RETURN",
            .EQ => "EQ",
            .NOT_EQ => "NOT_EQ",
        };
    }
};

// Define the Token struct
pub const Token = struct {
    type: TokenType,
    literal: []const u8,

    // Constructor function
    pub fn init(token_type: TokenType, lit: []const u8) Token {
        return Token{
            .type = token_type,
            .literal = lit,
        };
    }

    pub fn format(
        self: Token,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("Token{{ type: {s}, literal: '{s}' }}", .{
            self.type.toString(),
            self.literal,
        });
    }
};
