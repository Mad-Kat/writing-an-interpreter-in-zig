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
    boolean: Boolean,
    if_expression: IfExpression,
    function_expression: FunctionExpression,

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

pub const Boolean = struct {
    token: Token,
    value: bool,

    pub fn tokenLiteral(b: *const Boolean) []const u8 {
        return b.token.literal;
    }

    pub fn string(b: *const Boolean, allocator: std.mem.Allocator) ![]const u8 {
        return allocator.dupe(u8, b.token.literal);
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
            .if_expression => |*ie| ie.deinit(),
            .function_expression => |*fe| fe.deinit(),
            else => {},
        }
        switch (self.right.*) {
            .prefix_expression => |*pe| pe.deinit(),
            .infix_expression => |*ie| ie.deinit(),
            .if_expression => |*ie| ie.deinit(),
            .function_expression => |*fe| fe.deinit(),
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

pub const BlockStatement = struct {
    token: Token,
    statements: std.ArrayList(Statement),

    pub fn init(allocator: std.mem.Allocator) BlockStatement {
        return .{
            .token = undefined,
            .statements = std.ArrayList(Statement).init(allocator),
        };
    }
    pub fn deinit(self: *BlockStatement) void {
        self.statements.deinit();
    }

    pub fn tokenLiteral(bs: *const BlockStatement) []const u8 {
        return bs.token.literal;
    }

    pub fn string(bs: *const BlockStatement, allocator: std.mem.Allocator) ![]const u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();

        for (bs.statements.items) |stmt| {
            if (stmt.string(allocator)) |stmt_str| {
                defer allocator.free(stmt_str);
                try out.appendSlice(stmt_str);
            } else |err| {
                out.deinit();
                return err;
            }
        }

        return out.toOwnedSlice();
    }
};

pub const FunctionExpression = struct {
    token: Token,
    parameters: std.ArrayList(Identifier),
    body: BlockStatement,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !FunctionExpression {
        return FunctionExpression{
            .token = undefined,
            .parameters = std.ArrayList(Identifier).init(allocator),
            .body = undefined,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *FunctionExpression) void {
        // Clean up parameters
        self.parameters.deinit();

        // Clean up body's statements
        for (self.body.statements.items) |*stmt| {
            switch (stmt.*) {
                .expression_statement => |*es| {
                    switch (es.expression) {
                        .prefix_expression => |*pe| pe.deinit(),
                        .infix_expression => |*ie| ie.deinit(),
                        .if_expression => |*ie| ie.deinit(),
                        .function_expression => |*fe| fe.deinit(),
                        else => {},
                    }
                },
                else => {},
            }
        }
        self.body.deinit();
    }

    pub fn tokenLiteral(fe: *const FunctionExpression) []const u8 {
        return fe.token.literal;
    }

    pub fn string(fe: *const FunctionExpression, allocator: std.mem.Allocator) ![]const u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();

        try out.appendSlice(fe.token.literal);
        try out.appendSlice("(");

        for (fe.parameters.items) |param| {
            try out.appendSlice(param.value);
            // if (param.value != fe.parameters.items[fe.parameters.items.len - 1].value) {
            //     try out.appendSlice(", ");
            // }
        }

        try out.appendSlice(") ");
        try out.appendSlice(try fe.body.string(allocator));

        return out.toOwnedSlice();
    }
};

pub const IfExpression = struct {
    token: Token,
    condition: *Expression,
    consequence: BlockStatement,
    alternative: ?BlockStatement,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !IfExpression {
        return IfExpression{
            .token = undefined,
            .condition = try allocator.create(Expression),
            .consequence = undefined,
            .alternative = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *IfExpression) void {
        switch (self.condition.*) {
            .prefix_expression => |*pe| pe.deinit(),
            .infix_expression => |*ie| ie.deinit(),
            .if_expression => |*ie| ie.deinit(),
            .function_expression => |*fe| fe.deinit(),
            else => {},
        }

        self.consequence.statements.deinit();
        if (self.alternative) |*alt| {
            alt.statements.deinit();
        }
        self.allocator.destroy(self.condition);
    }

    pub fn tokenLiteral(ie: *const IfExpression) []const u8 {
        return ie.token.literal;
    }

    pub fn string(ie: *const IfExpression, allocator: std.mem.Allocator) anyerror![]const u8 {
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();

        try out.appendSlice("if");
        try out.appendSlice(try ie.condition.string(allocator));
        try out.appendSlice(" ");
        try out.appendSlice(try ie.consequence.string(allocator));

        if (ie.alternative != null) {
            try out.appendSlice("else ");
            try out.appendSlice(try ie.alternative.?.string(allocator));
        }

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
                        .if_expression => |*ie| {
                            ie.deinit();
                        },
                        .function_expression => |*fe| {
                            fe.deinit();
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
