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
        parser.registerPrefix(.TRUE, @This().parseBoolean) catch {};
        parser.registerPrefix(.FALSE, @This().parseBoolean) catch {};
        parser.registerPrefix(.LPAREN, @This().parseGroupedExpression) catch {};
        parser.registerPrefix(.IF, @This().parseIfExpression) catch {};
        parser.registerPrefix(.FUNCTION, @This().parseFunctionLiteral) catch {};

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

    fn parseBoolean(self: *Parser) ParseError!ast.Expression {
        return .{ .boolean = .{
            .token = self.curr_token,
            .value = self.curr_token.type == .TRUE,
        } };
    }

    fn parseGroupedExpression(self: *Parser) ParseError!ast.Expression {
        self.nextToken();

        const exp = try self.parseExpression(.LOWEST);

        try self.expectPeek(.RPAREN);

        return exp;
    }

    fn parseIntegerLiteral(self: *Parser) ParseError!ast.Expression {
        const lit = try std.fmt.parseInt(i64, self.curr_token.literal, 10);
        return .{ .integer_literal = .{
            .token = self.curr_token,
            .value = lit,
        } };
    }

    fn parseIfExpression(self: *Parser) ParseError!ast.Expression {
        var if_expr = try ast.IfExpression.init(self.allocator);
        errdefer if_expr.deinit();

        if_expr.token = self.curr_token;

        try self.expectPeek(.LPAREN);
        self.nextToken();

        const condition = try self.parseExpression(.LOWEST);
        if_expr.condition.* = condition;

        try self.expectPeek(.RPAREN);
        try self.expectPeek(.LBRACE);

        if_expr.consequence = try self.parseBlockStatement();

        if (self.peek_token.type == .ELSE) {
            self.nextToken();
            try self.expectPeek(.LBRACE);
            if_expr.alternative = try self.parseBlockStatement();
        }

        return .{ .if_expression = if_expr };
    }

    fn parseFunctionLiteral(self: *Parser) ParseError!ast.Expression {
        var function = try ast.FunctionExpression.init(self.allocator);
        errdefer function.parameters.deinit();

        function.token = self.curr_token;

        try self.expectPeek(.LPAREN);
        try self.parseFunctionParameters(&function);

        try self.expectPeek(.LBRACE);

        // Initialize the body with the allocator
        function.body = ast.BlockStatement.init(self.allocator);
        errdefer function.body.deinit();

        // Parse the body
        function.body = try self.parseBlockStatement();

        return .{ .function_expression = function };
    }

    fn parseFunctionParameters(self: *Parser, function: *ast.FunctionExpression) ParseError!void {
        if (self.peek_token.type == .RPAREN) {
            self.nextToken(); // Skip the right paren if no parameters
            return;
        }

        self.nextToken(); // Move past LPAREN

        // Parse first parameter
        try function.parameters.append(.{ .token = self.curr_token, .value = self.curr_token.literal });

        while (self.peek_token.type == .COMMA) {
            self.nextToken(); // Move to comma
            self.nextToken(); // Move to parameter
            try function.parameters.append(.{ .token = self.curr_token, .value = self.curr_token.literal });
        }

        try self.expectPeek(.RPAREN);
    }

    fn parseBlockStatement(self: *Parser) ParseError!ast.BlockStatement {
        var block = ast.BlockStatement.init(self.allocator);
        errdefer block.deinit();

        block.token = self.curr_token;
        self.nextToken();

        while (!self.checkToken(.RBRACE) and !self.checkToken(.EOF)) {
            if (try self.parseStatement()) |stmt| {
                try block.statements.append(stmt);
            }
            self.nextToken();
        }

        return block;
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

        fn testIdentifier(expr: ast.Expression, value: []const u8) !void {
            const ident = expr.identifier;
            try std.testing.expectEqualStrings(value, ident.value);
            try std.testing.expectEqualStrings(value, ident.tokenLiteral());
        }

        fn testLiteralExpression(expr: ast.Expression, expected: anytype) !void {
            const T = @TypeOf(expected);
            return switch (@typeInfo(T)) {
                .Pointer => |ptr_info| {
                    // Check if it's a string literal type (*const [N:0]u8)
                    if (ptr_info.size == .One and
                        ptr_info.is_const and
                        @typeInfo(ptr_info.child) == .Array and
                        @typeInfo(ptr_info.child).Array.child == u8)
                    {
                        try Parser.Testing.testIdentifier(expr, expected);
                    } else {
                        std.debug.print("Type is: {s}\n", .{@typeName(T)});
                        try std.testing.expect(false);
                    }
                },
                .Array => |arr_info| {
                    if (arr_info.child == u8) {
                        try Parser.Testing.testIdentifier(expr, expected);
                    } else {
                        std.debug.print("Type is: {s}\n", .{@typeName(T)});
                        try std.testing.expect(false);
                    }
                },
                .Int => {
                    try Parser.Testing.testIntegerLiteral(expr, expected);
                },
                .Bool => {
                    try Parser.Testing.testBooleanLiteral(expr, expected);
                },
                else => {
                    std.debug.print("Type is: {s}\n", .{@typeName(@TypeOf(expected))});
                    try std.testing.expect(false);
                },
            };
        }

        fn testInfixExpression(expr: ast.Expression, left: anytype, operator: []const u8, right: anytype) !void {
            const infix_expr = expr.infix_expression;

            try Parser.Testing.testLiteralExpression(infix_expr.left.*, left);
            try std.testing.expectEqualStrings(operator, infix_expr.operator);
            try Parser.Testing.testLiteralExpression(infix_expr.right.*, right);
        }

        fn testPrefixExpression(expr: ast.Expression, operator: []const u8, right: anytype) !void {
            const prfx_expr = expr.prefix_expression;

            try std.testing.expectEqualStrings(operator, prfx_expr.operator);
            try Parser.Testing.testLiteralExpression(prfx_expr.right.*, right);
        }

        fn testBooleanLiteral(expr: ast.Expression, expected: bool) !void {
            if (expected) {
                try std.testing.expectEqualStrings("true", expr.tokenLiteral());
            } else {
                try std.testing.expectEqualStrings("false", expr.tokenLiteral());
            }
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

        try Parser.Testing.testIdentifier(expr_stmt.expression, "foobar");
    }
}

test "test boolean expression" {
    const input = "true;";
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

        try Parser.Testing.testLiteralExpression(expr_stmt.expression, true);
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

        try Parser.Testing.testIntegerLiteral(expr_stmt.expression, 5);
    }
}

test "test parsing prefix expression" {
    const Value = union(enum) { int: i64, bool_value: bool };
    const Case = struct {
        input: []const u8,
        expected_operator: []const u8,
        expected_value: Value,
    };
    const input = [_]Case{
        .{ .input = "!5;", .expected_operator = "!", .expected_value = .{ .int = 5 } },
        .{ .input = "-15;", .expected_operator = "-", .expected_value = .{ .int = 15 } },
        .{ .input = "!true;", .expected_operator = "!", .expected_value = .{ .bool_value = true } },
        .{ .input = "!false;", .expected_operator = "!", .expected_value = .{ .bool_value = false } },
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

            switch (tt.expected_value) {
                .int => {
                    try Parser.Testing.testPrefixExpression(expr_stmt.expression, tt.expected_operator, tt.expected_value.int);
                },
                .bool_value => {
                    try Parser.Testing.testPrefixExpression(expr_stmt.expression, tt.expected_operator, tt.expected_value.bool_value);
                },
            }
        }
    }
}
test "test parsing infix expressions" {
    const Value = union(enum) { int: i64, bool_value: bool };

    const Case = struct {
        input: []const u8,
        expected_left_value: Value,
        expected_operator: []const u8,
        expected_right_value: Value,
    };

    const input = [_]Case{
        .{ .input = "5 + 5;", .expected_left_value = .{ .int = 5 }, .expected_operator = "+", .expected_right_value = .{ .int = 5 } },
        .{ .input = "5 - 5;", .expected_left_value = .{ .int = 5 }, .expected_operator = "-", .expected_right_value = .{ .int = 5 } },
        .{ .input = "5 * 5;", .expected_left_value = .{ .int = 5 }, .expected_operator = "*", .expected_right_value = .{ .int = 5 } },
        .{ .input = "5 / 5;", .expected_left_value = .{ .int = 5 }, .expected_operator = "/", .expected_right_value = .{ .int = 5 } },
        .{ .input = "5 > 5;", .expected_left_value = .{ .int = 5 }, .expected_operator = ">", .expected_right_value = .{ .int = 5 } },
        .{ .input = "5 < 5;", .expected_left_value = .{ .int = 5 }, .expected_operator = "<", .expected_right_value = .{ .int = 5 } },
        .{ .input = "5 == 5;", .expected_left_value = .{ .int = 5 }, .expected_operator = "==", .expected_right_value = .{ .int = 5 } },
        .{ .input = "5 != 5;", .expected_left_value = .{ .int = 5 }, .expected_operator = "!=", .expected_right_value = .{ .int = 5 } },
        .{ .input = "true == true;", .expected_left_value = .{ .bool_value = true }, .expected_operator = "==", .expected_right_value = .{ .bool_value = true } },
        .{ .input = "true != false;", .expected_left_value = .{ .bool_value = true }, .expected_operator = "!=", .expected_right_value = .{ .bool_value = false } },
        .{ .input = "false == false;", .expected_left_value = .{ .bool_value = false }, .expected_operator = "==", .expected_right_value = .{ .bool_value = false } },
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

            switch (tt.expected_left_value) {
                .int => {
                    try Parser.Testing.testInfixExpression(expr_stmt.expression, tt.expected_left_value.int, tt.expected_operator, tt.expected_right_value.int);
                },
                .bool_value => {
                    try Parser.Testing.testInfixExpression(expr_stmt.expression, tt.expected_left_value.bool_value, tt.expected_operator, tt.expected_right_value.bool_value);
                },
            }
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
        .{ .input = "true", .expected = "true" },
        .{ .input = "false", .expected = "false" },
        .{ .input = "3 > 5 == false", .expected = "((3 > 5) == false)" },
        .{ .input = "3 < 5 == true", .expected = "((3 < 5) == true)" },
        .{ .input = "1 + (2 + 3) + 4", .expected = "((1 + (2 + 3)) + 4)" },
        .{ .input = "(5 + 5) * 2", .expected = "((5 + 5) * 2)" },
        .{ .input = "2 / (5 + 5)", .expected = "(2 / (5 + 5))" },
        .{ .input = "-(5 + 5)", .expected = "(-(5 + 5))" },
        .{ .input = "!(true == true)", .expected = "(!(true == true))" },
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

test "test if expression" {
    const input = "if (x < y) { x }";
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

        try Parser.Testing.testInfixExpression(expr_stmt.expression.if_expression.condition.*, "x", "<", "y");
        try std.testing.expectEqual(@as(usize, 1), expr_stmt.expression.if_expression.consequence.statements.items.len);

        const consequence = &expr_stmt.expression.if_expression.consequence.statements.items[0].expression_statement;
        try Parser.Testing.testIdentifier(consequence.expression, "x");
        try std.testing.expectEqual(null, expr_stmt.expression.if_expression.alternative);
    }
}

test "test if else expression" {
    const input = "if (x < y) { x } else { y }";
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

        try Parser.Testing.testInfixExpression(expr_stmt.expression.if_expression.condition.*, "x", "<", "y");
        try std.testing.expectEqual(@as(usize, 1), expr_stmt.expression.if_expression.consequence.statements.items.len);

        const consequence = &expr_stmt.expression.if_expression.consequence.statements.items[0].expression_statement;
        try Parser.Testing.testIdentifier(consequence.expression, "x");
        try std.testing.expectEqual(@as(usize, 1), expr_stmt.expression.if_expression.alternative.?.statements.items.len);
        const alternative = &expr_stmt.expression.if_expression.alternative.?.statements.items[0].expression_statement;
        try Parser.Testing.testIdentifier(alternative.expression, "y");
    }
}

test "test function literal parsing" {
    const input = "fn(x, y) { x + y; }";
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

        const function_expression = expr_stmt.expression.function_expression;

        try std.testing.expectEqual(@as(usize, 2), function_expression.parameters.items.len);

        try std.testing.expectEqualStrings(function_expression.parameters.items[0].value, "x");
        try std.testing.expectEqualStrings(function_expression.parameters.items[1].value, "y");

        try std.testing.expectEqual(@as(usize, 1), function_expression.body.statements.items.len);
        try Parser.Testing.testInfixExpression(function_expression.body.statements.items[0].expression_statement.expression, "x", "+", "y");
    }
}

test "test function parameter parsing" {
    const allocator = std.testing.allocator;

    // Define the test cases with their expected parameters
    const TestCase = struct {
        input: []const u8,
        expected_params: []const []const u8,
    };

    const test_cases = [_]TestCase{
        .{ .input = "fn() {};", .expected_params = &[_][]const u8{} },
        .{ .input = "fn(x) {};", .expected_params = &[_][]const u8{"x"} },
        .{ .input = "fn(x, y, z) {};", .expected_params = &[_][]const u8{ "x", "y", "z" } },
    };

    for (test_cases) |tt| {
        var lexer = Lexer.init(tt.input);
        var parser = Parser.init(allocator, &lexer);
        defer parser.deinit();

        var program = try parser.parseProgram();
        defer program.deinit();

        try Parser.Testing.checkParserErrors(&parser);

        // We expect one statement
        try std.testing.expectEqual(@as(usize, 1), program.statements.items.len);

        const stmt = &program.statements.items[0];
        const expr_stmt = stmt.expression_statement;
        const function = expr_stmt.expression.function_expression;

        // Check number of parameters
        try std.testing.expectEqual(tt.expected_params.len, function.parameters.items.len);

        // Check each parameter
        for (tt.expected_params, 0..) |expected_param, i| {
            try std.testing.expectEqualStrings(expected_param, function.parameters.items[i].value);
        }
    }
}
