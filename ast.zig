const Token = @import("token.zig").Token;
const std = @import("std");

const Node = union(enum) {
    statement: Statement,
    expression: Expression,

    pub fn tokenLiteral(self: *const Node) []const u8 {
        return switch (self.*) {
            inline else => |impl| impl.tokenLiteral(),
        };
    }

    pub fn string(self: *const Node) []const u8 {
        return switch (self.*) {
            inline else => |impl| impl.string(),
        };
    }
};

pub const Statement = union(enum) {
    let_statement: LetStatement,
    return_statement: ReturnStatement,
    expression_statement: ExpressionStatement,

    pub fn tokenLiteral(self: *const Statement) []const u8 {
        return switch (self.*) {
            inline else => |impl| impl.tokenLiteral(),
        };
    }

    pub fn string(self: *const Statement, allocator: std.mem.Allocator) ![]const u8 {
        return switch (self.*) {
            inline else => |impl| try impl.string(allocator),
        };
    }
};

pub const Expression = union(enum) {
    identifier: Identifier,
    integer_literal: IntegerLiteral,
    prefix_expression: PrefixExpression,
    infix_expression: InfixExpression,

    pub fn tokenLiteral(self: *const Expression) []const u8 {
        return switch (self.*) {
            inline else => |impl| impl.tokenLiteral(),
        };
    }

    pub fn string(self: *const Expression, allocator: std.mem.Allocator) anyerror![]const u8 {
        return switch (self.*) {
            inline else => |impl| impl.string(allocator),
        };
    }
};

pub const ExpressionStatement = struct {
    token: Token,
    expression: Expression,

    pub fn statmentNode() void {}
    pub fn tokenLiteral(es: *const ExpressionStatement) []const u8 {
        return es.token.literal;
    }
    pub fn string(es: *const ExpressionStatement, allocator: std.mem.Allocator) ![]const u8 {
        var output = std.ArrayList(u8).init(allocator);
        errdefer output.deinit();

        const expr_str = try es.expression.string(allocator);
        defer allocator.free(expr_str);
        try output.appendSlice(expr_str);

        return output.toOwnedSlice();
    }
};

pub const Identifier = struct {
    token: Token,
    value: []const u8,

    pub fn tokenLiteral(i: *const Identifier) []const u8 {
        return i.token.literal;
    }

    pub fn string(i: *const Identifier, allocator: std.mem.Allocator) ![]const u8 {
        return allocator.dupe(u8, i.value);
    }
};

pub const IntegerLiteral = struct {
    token: Token,
    value: i64,

    pub fn tokenLiteral(i: *const IntegerLiteral) []const u8 {
        return i.token.literal;
    }

    pub fn string(i: *const IntegerLiteral, allocator: std.mem.Allocator) ![]const u8 {
        return allocator.dupe(u8, i.token.literal);
    }
};

pub const PrefixExpression = struct {
    token: Token,
    operator: []const u8,
    right: *Expression,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !PrefixExpression {
        return PrefixExpression{
            .token = undefined,
            .operator = undefined,
            .right = try allocator.create(Expression),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PrefixExpression) void {
        // First recursively free any nested expressions
        switch (self.right.*) {
            .prefix_expression => |*pe| pe.deinit(),
            .infix_expression => |*ie| ie.deinit(),
            else => {},
        }
        // Then free the right expression pointer itself
        self.allocator.destroy(self.right);
    }

    pub fn tokenLiteral(pe: *const PrefixExpression) []const u8 {
        return pe.token.literal;
    }

    pub fn string(pe: *const PrefixExpression, allocator: std.mem.Allocator) ![]const u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();

        try out.appendSlice("(");
        try out.appendSlice(pe.operator);

        const right_str = try pe.right.string(allocator);
        defer allocator.free(right_str);
        try out.appendSlice(right_str);

        try out.appendSlice(")");
        return out.toOwnedSlice();
    }
};

pub const InfixExpression = struct {
    token: Token,
    left: *Expression,
    operator: []const u8,
    right: *Expression,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !InfixExpression {
        return InfixExpression{
            .token = undefined,
            .left = try allocator.create(Expression),
            .operator = undefined,
            .right = try allocator.create(Expression),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *InfixExpression) void {
        // First recursively free any nested expressions
        switch (self.left.*) {
            .prefix_expression => |*pe| pe.deinit(),
            .infix_expression => |*ie| ie.deinit(),
            else => {},
        }
        switch (self.right.*) {
            .prefix_expression => |*pe| pe.deinit(),
            .infix_expression => |*ie| ie.deinit(),
            else => {},
        }
        // Then free the expression pointers themselves
        self.allocator.destroy(self.left);
        self.allocator.destroy(self.right);
    }

    pub fn tokenLiteral(self: *const InfixExpression) []const u8 {
        return self.token.literal;
    }

    pub fn string(self: *const InfixExpression, allocator: std.mem.Allocator) ![]const u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();

        const left_str = try self.left.string(allocator);
        defer allocator.free(left_str);

        const right_str = try self.right.string(allocator);
        defer allocator.free(right_str);

        try out.appendSlice("(");
        try out.appendSlice(left_str);
        try out.appendSlice(" ");
        try out.appendSlice(self.operator);
        try out.appendSlice(" ");
        try out.appendSlice(right_str);
        try out.appendSlice(")");

        return out.toOwnedSlice();
    }
};

pub const LetStatement = struct {
    token: Token,
    name: *Identifier,
    value: *Expression,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !LetStatement {
        return LetStatement{
            .token = undefined,
            .name = try allocator.create(Identifier),
            .value = try allocator.create(Expression),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *LetStatement) void {
        self.allocator.destroy(self.name);
        self.allocator.destroy(self.value);
    }

    pub fn tokenLiteral(ls: *const LetStatement) []const u8 {
        return ls.token.literal;
    }

    pub fn string(ls: *const LetStatement, allocator: std.mem.Allocator) ![]const u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();

        try out.appendSlice("let ");
        try out.appendSlice(ls.name.value);
        try out.appendSlice(" = ");
        try out.appendSlice(ls.value.tokenLiteral());
        try out.appendSlice(";");
        return out.toOwnedSlice();
    }
};

pub const ReturnStatement = struct {
    token: Token,
    returnValue: *Expression,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !ReturnStatement {
        return ReturnStatement{
            .token = undefined,
            .returnValue = try allocator.create(Expression),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ReturnStatement) void {
        self.allocator.destroy(self.returnValue);
    }

    pub fn tokenLiteral(rs: *const ReturnStatement) []const u8 {
        return rs.token.literal;
    }

    pub fn string(rs: *const ReturnStatement, allocator: std.mem.Allocator) ![]const u8 {
        var out = std.ArrayList(u8).init(allocator);
        defer out.deinit();
        try out.appendSlice("return ");
        try out.appendSlice(rs.returnValue.tokenLiteral());
        try out.appendSlice(";");
        return out.toOwnedSlice();
    }
};

pub const Program = struct {
    statements: std.ArrayList(Statement),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !Program {
        return .{
            .statements = std.ArrayList(Statement).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Program) void {
        for (self.statements.items) |*stmt| {
            switch (stmt.*) {
                .let_statement => |*ls| ls.deinit(),
                .return_statement => |*rs| rs.deinit(),
                .expression_statement => |*es| {
                    switch (es.expression) {
                        .prefix_expression => |*pe| {
                            pe.deinit();
                        },
                        .infix_expression => |*ie| {
                            ie.deinit();
                        },
                        else => {},
                    }
                },
            }
        }
        self.statements.deinit();
    }

    pub fn tokenLiteral(p: *const Program) []const u8 {
        if (p.statements.items.len > 0) {
            return p.statements.items[0].TokenLiteral();
        } else {
            return "";
        }
    }

    pub fn string(p: *const Program) ![]const u8 {
        var output = std.ArrayList(u8).init(p.allocator);
        errdefer output.deinit();

        // Iterate through statements and append their string representations
        for (p.statements.items) |statement| {
            if (statement.string(p.allocator)) |stmt_str| {
                defer p.allocator.free(stmt_str);
                try output.appendSlice(stmt_str);
            } else |err| {
                output.deinit();
                return err;
            }
        }

        return output.toOwnedSlice();
    }
};

test "test serializing let statement" {
    const allocator = std.testing.allocator;

    // Initialize Program first since it should be deallocated last
    var program = Program{
        .statements = std.ArrayList(Statement).init(allocator),
        .allocator = allocator,
    };
    defer program.deinit(); // This will clean up everything

    // Create identifier
    const identifier = try allocator.create(Identifier);
    identifier.* = Identifier{
        .token = .{
            .type = .IDENT,
            .literal = "myVar",
        },
        .value = "myVar",
    };

    // Create expression
    const value = try allocator.create(Expression);
    value.* = Expression{
        .identifier = .{
            .token = .{
                .type = .IDENT,
                .literal = "anotherVar",
            },
            .value = "anotherVar",
        },
    };

    // Create and append the statement
    try program.statements.append(Statement{
        .let_statement = LetStatement{
            .name = identifier,
            .token = .{
                .type = .LET,
                .literal = "let",
            },
            .value = value,
            .allocator = allocator,
        },
    });

    // Test the string output
    const result = try program.string();
    defer allocator.free(result);

    try std.testing.expectEqualStrings("let myVar = anotherVar;", result);
}

test "test serializing return statement" {
    const allocator = std.testing.allocator;

    // Initialize Program first since it should be deallocated last
    var program = Program{
        .statements = std.ArrayList(Statement).init(allocator),
        .allocator = allocator,
    };
    defer program.deinit(); // This will clean up everything

    // Create expression
    const value = try allocator.create(Expression);
    value.* = Expression{
        .identifier = .{
            .token = .{
                .type = .IDENT,
                .literal = "myVal",
            },
            .value = "myVal",
        },
    };

    // Create and append the statement
    try program.statements.append(Statement{
        .return_statement = ReturnStatement{
            // .name = identifier,
            .token = .{
                .type = .RETURN,
                .literal = "return",
            },
            // .value = value,
            .returnValue = value,
            .allocator = allocator,
        },
    });

    // Test the string output
    const result = try program.string();
    defer allocator.free(result);

    try std.testing.expectEqualStrings("return myVal;", result);
}
