const std = @import("std");
const lib = @import("xxhash");

// Hash variants.
const xxh32 = lib.xxh32;

pub fn main() !void {
    // TODO: CLI to make these configurable.
    const data = "Hello, Zig";

    // 32 bit hash of data.
    const hash_32 = xxh32.oneshot(data, 0);
    std.debug.print("32 bit hash of \"{s}\" is: {d}\n", .{ data, hash_32 });
}
