const Lexer = @import("lexer.zig").Lexer;
const Token = @import("token.zig").Token;
const TokenType = @import("token.zig").TokenType;
const ast = @import("ast.zig");
const std = @import("std");

pub const ParseError = error{ UnexpectedToken, InvalidIdentifier, MissingSemicolon, OutOfMemory, Overflow, InvalidCharacter };

pub const prefixParseFn = *const fn (*Parser) ParseError!ast.Expression;
pub const infixParseFn = *const fn (*Parser, ast.Expression) ParseError!ast.Expression;

const Priority = enum(u4) {
    LOWEST = 1,
    EQUALS = 2, // ==
    LESSGREATER = 3, // > or <
    SUM = 4, // +
    PRODUCT = 5, // *
    PREFIX = 6, // -X or !X
    CALL = 7, // myFunction(X)
};

const precedences = struct {
    fn init() type {
        const MapType = struct {
            const map = std.static_string_map.StaticStringMap(Priority).initComptime(.{
                .{ TokenType.EQ.toString(), .EQUALS },
                .{ TokenType.NOT_EQ.toString(), .EQUALS },
                .{ TokenType.LT.toString(), .LESSGREATER },
                .{ TokenType.GT.toString(), .LESSGREATER },
                .{ TokenType.PLUS.toString(), .SUM },
                .{ TokenType.MINUS.toString(), .SUM },
                .{ TokenType.SLASH.toString(), .PRODUCT },
                .{ TokenType.ASTERISK.toString(), .PRODUCT },
                .{ TokenType.LPAREN.toString(), .CALL },
            });

            pub fn get(token_type: TokenType) Priority {
                return map.get(token_type.toString()) orelse .LOWEST;
            }
        };
        return MapType;
    }
}.init();

const Parser = struct {
    allocator: std.mem.Allocator,
    lexer: *Lexer,
    curr_token: Token,
    peek_token: Token,
    errors: std.ArrayList([]const u8),
    prefix_parse_fns: std.AutoHashMap(TokenType, prefixParseFn),
    infix_parse_fns: std.AutoHashMap(TokenType, infixParseFn),

    pub fn init(allocator: std.mem.Allocator, lexer: *Lexer) Parser {
        var parser = Parser{
            .allocator = allocator,
            .lexer = lexer,
            .curr_token = undefined,
            .peek_token = undefined,
            .errors = std.ArrayList([]const u8).init(allocator),
            .prefix_parse_fns = std.AutoHashMap(TokenType, prefixParseFn).init(allocator),
            .infix_parse_fns = std.AutoHashMap(TokenType, infixParseFn).init(allocator),
        };

        parser.registerPrefix(.IDENT, @This().parseIdentifier) catch {};
        parser.registerPrefix(.INT, @This().parseIntegerLiteral) catch {};
        parser.registerPrefix(.BANG, @This().parsePrefixExpression) catch {};
        parser.registerPrefix(.MINUS, @This().parsePrefixExpression) catch {};

        parser.registerInfix(.PLUS, @This().parseInfixExpression) catch {};
        parser.registerInfix(.MINUS, @This().parseInfixExpression) catch {};
        parser.registerInfix(.SLASH, @This().parseInfixExpression) catch {};
        parser.registerInfix(.ASTERISK, @This().parseInfixExpression) catch {};
        parser.registerInfix(.EQ, @This().parseInfixExpression) catch {};
        parser.registerInfix(.NOT_EQ, @This().parseInfixExpression) catch {};
        parser.registerInfix(.LT, @This().parseInfixExpression) catch {};
        parser.registerInfix(.GT, @This().parseInfixExpression) catch {};

        // Read two tokens to initialize curr_token and peek_token
        parser.nextToken();
        parser.nextToken();

        return parser;
    }

    pub fn deinit(self: *Parser) void {
        for (self.errors.items) |msg| {
            self.allocator.free(msg);
        }
        self.errors.clearAndFree();
        self.prefix_parse_fns.deinit();
        self.infix_parse_fns.deinit();
    }

    fn peekError(self: *Parser, expected: TokenType) !void {
        const msg = try std.fmt.allocPrint(self.allocator, "expected next token to be {}, got {} instead", .{
            expected,
            self.peek_token.type,
        });
        errdefer self.allocator.free(msg);
        try self.errors.append(msg);
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
            .RETURN => .{
                .return_statement = try self.parseReturnStatement(),
            },
            else => .{
                .expression_statement = try self.parseExpressionStatement(),
            },
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

    fn parseReturnStatement(self: *Parser) ParseError!ast.ReturnStatement {
        const stmt_token = self.curr_token;
        self.nextToken();
        while (!self.checkToken(.SEMICOLON)) {
            self.nextToken();
        }

        var stmt = try ast.ReturnStatement.init(self.allocator);
        errdefer stmt.deinit();
        stmt.token = stmt_token;

        return stmt;
    }

    fn parseExpressionStatement(self: *Parser) ParseError!ast.ExpressionStatement {
        const stmt = .{
            .expression = try self.parseExpression(.LOWEST),
            .token = undefined,
        };

        if (self.peek_token.type == .SEMICOLON) {
            self.nextToken();
        }

        return stmt;
    }

    fn parseExpression(self: *Parser, precedence: Priority) ParseError!ast.Expression {
        const prefix = self.prefix_parse_fns.get(self.curr_token.type);
        if (prefix == null) {
            std.debug.print("no prefix parse function for {s} found\n", .{self.curr_token.type.toString()});
        }
        var left_exp = try prefix.?(self);

        while (self.peek_token.type != .SEMICOLON and @intFromEnum(precedence) < @intFromEnum(self.peekPrecedence())) {
            const infix = self.infix_parse_fns.get(self.peek_token.type);
            if (infix == null) {
                return left_exp;
            }

            self.nextToken();
            left_exp = try infix.?(self, left_exp);
        }

        return left_exp;
    }

    fn parseIdentifier(self: *Parser) ParseError!ast.Expression {
        return .{ .identifier = .{
            .token = self.curr_token,
            .value = self.curr_token.literal,
        } };
    }

    fn parseIntegerLiteral(self: *Parser) ParseError!ast.Expression {
        const lit = try std.fmt.parseInt(i64, self.curr_token.literal, 10);
        return .{ .integer_literal = .{
            .token = self.curr_token,
            .value = lit,
        } };
    }

    fn parsePrefixExpression(self: *Parser) ParseError!ast.Expression {
        var prefixExpression = try ast.PrefixExpression.init(self.allocator);
        errdefer prefixExpression.deinit();

        prefixExpression.token = self.curr_token;
        prefixExpression.operator = self.curr_token.literal;

        self.nextToken();

        const right_expr = try self.parseExpression(.PREFIX);
        prefixExpression.right.* = right_expr;

        return .{ .prefix_expression = prefixExpression };
    }

    fn parseInfixExpression(self: *Parser, left: ast.Expression) ParseError!ast.Expression {
        var infixExpression = try ast.InfixExpression.init(self.allocator);
        errdefer infixExpression.deinit();

        infixExpression.token = self.curr_token;
        infixExpression.operator = self.curr_token.literal;
        infixExpression.left.* = left;

        const precedence = self.curPrecedence();
        self.nextToken();

        const right_expr = try self.parseExpression(precedence);
        infixExpression.right.* = right_expr;

        return .{ .infix_expression = infixExpression };
    }

    fn expectPeek(self: *Parser, expected: TokenType) ParseError!void {
        if (self.peek_token.type != expected) {
            try self.peekError(expected);
            return;
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

    fn registerPrefix(self: *Parser, token_type: TokenType, f: prefixParseFn) !void {
        try self.prefix_parse_fns.put(token_type, f);
    }

    fn registerInfix(self: *Parser, token_type: TokenType, f: infixParseFn) !void {
        try self.infix_parse_fns.put(token_type, f);
    }

    fn peekPrecedence(self: *Parser) Priority {
        return precedences.get(self.peek_token.type);
    }

    fn curPrecedence(self: *Parser) Priority {
        return precedences.get(self.curr_token.type);
    }

    // Testing
    const Testing = struct {
        fn expectLetStatement(statement: *const ast.Statement, name: []const u8) !void {
            try std.testing.expectEqualStrings("let", statement.tokenLiteral());

            const let_stmt = switch (statement.*) {
                .let_statement => |ls| ls,
                else => blk: {
                    try std.testing.expect(false);
                    break :blk null;
                },
            };
            try std.testing.expectEqualStrings(name, let_stmt.?.name.value);
            try std.testing.expectEqualStrings(name, let_stmt.?.name.tokenLiteral());
        }

        fn checkParserErrors(parser: *const Parser) !void {
            if (parser.errors.items.len != 0) {
                std.debug.print("parser has {} errors\n", .{parser.errors.items.len});
                for (parser.errors.items) |msg| {
                    std.debug.print("parser error: {s}\n", .{msg});
                }
            }
            try std.testing.expectEqual(@as(usize, 0), parser.errors.items.len);
        }

        fn testIntegerLiteral(il: ast.Expression, value: i64) !void {
            const int_lit = il.integer_literal;

            var b: [10]u8 = undefined;
            const x = try std.fmt.bufPrint(&b, "{d}", .{value});

            try std.testing.expectEqual(value, int_lit.value);
            try std.testing.expectEqualStrings(x, int_lit.tokenLiteral());
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
    defer parser.deinit();

    var program = try parser.parseProgram();
    defer program.deinit();

    try Parser.Testing.checkParserErrors(&parser);

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

test "test return statements" {
    const input =
        \\return 5;
        \\return 10;
        \\return 993322;
    ;
    var lexer = Lexer.init(input);
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator, &lexer);
    defer parser.deinit();

    var program = try parser.parseProgram();
    defer program.deinit();

    try Parser.Testing.checkParserErrors(&parser);

    try std.testing.expectEqual(@as(usize, 3), program.statements.items.len);

    for (0..program.statements.items.len) |i| {
        const stmt = &program.statements.items[i];
        try std.testing.expectEqualStrings("return", @as(*ast.ReturnStatement, @ptrCast(stmt)).tokenLiteral());
    }
}

test "test identifier expression" {
    const input = "foobar;";
    var lexer = Lexer.init(input);
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator, &lexer);
    defer parser.deinit();

    var program = try parser.parseProgram();
    defer program.deinit();

    try Parser.Testing.checkParserErrors(&parser);

    try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

    for (0..program.statements.items.len) |i| {
        const stmt = &program.statements.items[i];
        const expr_stmt = @as(*ast.ExpressionStatement, @ptrCast(stmt));
        const ident = expr_stmt.expression.identifier;

        try std.testing.expectEqualStrings("foobar", ident.value);
        try std.testing.expectEqualStrings("foobar", ident.tokenLiteral());
    }
}

test "test integer literal expression" {
    const input = "5;";
    var lexer = Lexer.init(input);
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator, &lexer);
    defer parser.deinit();

    var program = try parser.parseProgram();
    defer program.deinit();

    try Parser.Testing.checkParserErrors(&parser);

    try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

    for (0..program.statements.items.len) |i| {
        const stmt = &program.statements.items[i];
        const expr_stmt = @as(*ast.ExpressionStatement, @ptrCast(stmt));
        const ident = expr_stmt.expression.integer_literal;

        try std.testing.expectEqual(5, ident.value);
        try std.testing.expectEqualStrings("5", ident.tokenLiteral());
    }
}

test "test parsing prefix expression" {
    const Case = struct {
        input: []const u8,
        expected_operator: []const u8,
        expected_value: i64,
    };
    const input = [_]Case{ .{ .input = "!5;", .expected_operator = "!", .expected_value = 5 }, .{ .input = "-15;", .expected_operator = "-", .expected_value = 15 } };
    for (input) |tt| {
        var lexer = Lexer.init(tt.input);
        const allocator = std.testing.allocator;
        var parser = Parser.init(allocator, &lexer);
        defer parser.deinit();

        var program = try parser.parseProgram();
        defer program.deinit();

        try Parser.Testing.checkParserErrors(&parser);

        try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

        for (0..program.statements.items.len) |i| {
            const stmt = &program.statements.items[i];
            const expr_stmt = @as(*ast.ExpressionStatement, @ptrCast(stmt));
            const prfx_expr = expr_stmt.expression.prefix_expression;

            try std.testing.expectEqual(tt.expected_operator, prfx_expr.operator);
            try Parser.Testing.testIntegerLiteral(prfx_expr.right.*, tt.expected_value);
        }
    }
}

test "test parsing infix expressions" {
    const Case = struct {
        input: []const u8,
        expected_left_value: i64,
        expected_operator: []const u8,
        expected_right_value: i64,
    };

    const input = [_]Case{
        .{ .input = "5 + 5;", .expected_left_value = 5, .expected_operator = "+", .expected_right_value = 5 },
        .{ .input = "5 - 5;", .expected_left_value = 5, .expected_operator = "-", .expected_right_value = 5 },
        .{ .input = "5 * 5;", .expected_left_value = 5, .expected_operator = "*", .expected_right_value = 5 },
        .{ .input = "5 / 5;", .expected_left_value = 5, .expected_operator = "/", .expected_right_value = 5 },
        .{ .input = "5 > 5;", .expected_left_value = 5, .expected_operator = ">", .expected_right_value = 5 },
        .{ .input = "5 < 5;", .expected_left_value = 5, .expected_operator = "<", .expected_right_value = 5 },
        .{ .input = "5 == 5;", .expected_left_value = 5, .expected_operator = "==", .expected_right_value = 5 },
        .{ .input = "5 != 5;", .expected_left_value = 5, .expected_operator = "!=", .expected_right_value = 5 },
    };
    for (input) |tt| {
        var lexer = Lexer.init(tt.input);
        const allocator = std.testing.allocator;
        var parser = Parser.init(allocator, &lexer);
        defer parser.deinit();

        var program = try parser.parseProgram();
        defer program.deinit();

        try Parser.Testing.checkParserErrors(&parser);

        try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

        for (0..program.statements.items.len) |i| {
            const stmt = &program.statements.items[i];
            const expr_stmt = @as(*ast.ExpressionStatement, @ptrCast(stmt));
            const infx_expr = expr_stmt.expression.infix_expression;

            try Parser.Testing.testIntegerLiteral(infx_expr.left.*, tt.expected_left_value);
            try std.testing.expectEqual(tt.expected_operator, infx_expr.operator);
            try Parser.Testing.testIntegerLiteral(infx_expr.right.*, tt.expected_right_value);
        }
    }
}

test "test parsing operator precedence" {
    const Case = struct {
        input: []const u8,
        expected: []const u8,
    };

    const input = [_]Case{
        .{ .input = "-a * b", .expected = "((-a) * b)" },
        .{ .input = "!-a", .expected = "(!(-a))" },
        .{ .input = "a + b + c", .expected = "((a + b) + c)" },
        .{ .input = "a + b - c", .expected = "((a + b) - c)" },
        .{ .input = "a * b * c", .expected = "((a * b) * c)" },
        .{ .input = "a * b / c", .expected = "((a * b) / c)" },
        .{ .input = "a + b / c", .expected = "(a + (b / c))" },
        .{ .input = "a + b * c + d / e - f", .expected = "(((a + (b * c)) + (d / e)) - f)" },
        .{ .input = "3 + 4; -5 * 5", .expected = "(3 + 4)((-5) * 5)" },
        .{ .input = "5 > 4 == 3 < 4", .expected = "((5 > 4) == (3 < 4))" },
        .{ .input = "5 < 4 != 3 > 4", .expected = "((5 < 4) != (3 > 4))" },
        .{ .input = "3 + 4 * 5 == 3 * 1 + 4 * 5", .expected = "((3 + (4 * 5)) == ((3 * 1) + (4 * 5)))" },
    };
    for (input) |tt| {
        var lexer = Lexer.init(tt.input);
        const allocator = std.testing.allocator;
        var parser = Parser.init(allocator, &lexer);
        defer parser.deinit();

        var program = try parser.parseProgram();
        defer program.deinit();

        try Parser.Testing.checkParserErrors(&parser);

        const result = try program.string();
        defer allocator.free(result);
        try std.testing.expectEqualStrings(tt.expected, result);
    }
}
