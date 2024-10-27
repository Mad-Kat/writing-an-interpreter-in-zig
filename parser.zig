const Lexer = @import("lexer.zig").Lexer;
const Token = @import("token.zig").Token;
const TokenType = @import("token.zig").TokenType;
const ast = @import("ast.zig");
const std = @import("std");

pub const ParseError = error{
    UnexpectedToken,
    InvalidIdentifier,
    MissingSemicolon,
    OutOfMemory,
};

const Parser = struct {
    allocator: std.mem.Allocator,
    lexer: *Lexer,
    curr_token: Token,
    peek_token: Token,

    pub fn init(allocator: std.mem.Allocator, lexer: *Lexer) Parser {
        var parser = Parser{
            .allocator = allocator,
            .lexer = lexer,
            .curr_token = undefined,
            .peek_token = undefined,
        };

        // Read two tokens to initialize curr_token and peek_token
        parser.nextToken();
        parser.nextToken();

        return parser;
    }

    fn nextToken(self: *Parser) void {
        self.curr_token = self.peek_token;
        self.peek_token = self.lexer.nextToken();
    }

    pub fn parseProgram(self: *Parser) ParseError!ast.Program {
        var program = try ast.Program.init(self.allocator);
        errdefer program.deinit();

        while (self.curr_token.type != .EOF) {
            if (try self.parseStatement()) |stmt| {
                try program.statements.append(stmt);
            }
            self.nextToken();
        }

        return program;
    }

    fn parseStatement(self: *Parser) ParseError!?ast.Statement {
        return switch (self.curr_token.type) {
            .LET => .{
                .let_statement = try self.parseLetStatement(),
            },
            else => null,
        };
    }

    fn parseLetStatement(self: *Parser) ParseError!ast.LetStatement {
        const stmt_token = self.curr_token;

        try self.expectPeek(.IDENT);

        var stmt = try ast.LetStatement.init(self.allocator);
        errdefer stmt.deinit();
        stmt.name.token = self.curr_token;
        stmt.name.value = self.curr_token.literal;

        try self.expectPeek(.ASSIGN);
        self.nextToken();

        try self.expectSemicolon();

        stmt.token = stmt_token;
        return stmt;
    }

    fn expectPeek(self: *Parser, expected: TokenType) ParseError!void {
        if (self.peek_token.type != expected) {
            return error.UnexpectedToken;
        }
        self.nextToken();
    }

    fn expectSemicolon(self: *Parser) ParseError!void {
        while (!self.checkToken(.SEMICOLON)) {
            if (self.checkToken(.EOF)) {
                return error.MissingSemicolon;
            }
            self.nextToken();
        }
    }

    fn checkToken(self: Parser, tok_type: TokenType) bool {
        return self.curr_token.type == tok_type;
    }

    // Testing
    const Testing = struct {
        fn expectLetStatement(statement: *const ast.Statement, name: []const u8) !void {
            try std.testing.expectEqualStrings("let", statement.tokenLiteral());

            const let_stmt = switch (statement.*) {
                .let_statement => |ls| ls,
            };

            try std.testing.expectEqualStrings(name, let_stmt.name.value);
            try std.testing.expectEqualStrings(name, let_stmt.name.tokenLiteral());
        }
    };
};

test "test let statements" {
    const input =
        \\let x = 5;
        \\let y = 10;
        \\let foobar = 838383;
    ;
    var lexer = Lexer.init(input);
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator, &lexer);

    var program = try parser.parseProgram();
    defer program.deinit();

    const TestCase = struct {
        expected_identifier: []const u8,
    };

    const test_cases = [_]TestCase{
        .{ .expected_identifier = "x" },
        .{ .expected_identifier = "y" },
        .{ .expected_identifier = "foobar" },
    };

    try std.testing.expectEqual(@as(usize, 3), program.statements.items.len);

    for (test_cases, 0..) |test_case, i| {
        const stmt = &program.statements.items[i];
        try Parser.Testing.expectLetStatement(stmt, test_case.expected_identifier);
    }
}