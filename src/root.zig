//! A pure zig implementation of xxhash specification.
const std = @import("std");

// Exports
pub const xxh32 = @import("xxh32.zig");

// Hack to run all unit tests in referenced source files.
// https://ziggit.dev/t/getting-zig-build-test-to-find-all-the-tests-in-my-module/6276
test {
    std.testing.refAllDeclsRecursive(@This());
}

// Fuzz tests to test equivalence with reference C implementation.
// zig build test --fuzz
// FIXME: This does not work as expected.

test "fuzz 32 bit oneshot hash" {
    const Context = struct {
        fn testOne(context: @This(), data: []const u8) !void {
            _ = context;
            _ = xxh32.oneshot(data, 0);
        }
    };

    try std.testing.fuzz(Context{}, Context.testOne, .{});
}
