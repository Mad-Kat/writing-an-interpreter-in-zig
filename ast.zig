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
};

pub const Statement = union(enum) {
    let_statement: LetStatement,

    pub fn tokenLiteral(self: *const Statement) []const u8 {
        return switch (self.*) {
            inline else => |impl| impl.tokenLiteral(),
        };
    }
};

pub const Expression = union(enum) {
    identifier: Identifier,

    pub fn tokenLiteral(self: *const Expression) []const u8 {
        return switch (self.*) {
            inline else => |impl| impl.tokenLiteral(),
        };
    }
};

pub const Identifier = struct {
    token: Token,
    value: []const u8,

    pub fn tokenLiteral(i: *const Identifier) []const u8 {
        return i.token.literal;
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
};

pub const Program = struct {
    statements: std.ArrayList(Statement),

    pub fn init(allocator: std.mem.Allocator) !Program {
        return .{
            .statements = std.ArrayList(Statement).init(allocator),
        };
    }

    pub fn deinit(self: *Program) void {
        for (self.statements.items) |*stmt| {
            switch (stmt.*) {
                .let_statement => |*ls| ls.deinit(),
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
};
