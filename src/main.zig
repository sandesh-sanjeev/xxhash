const std = @import("std");
const lib = @import("xxhash");

// Hash variants.
const xxh32 = lib.xxh32;
const xxh64 = lib.xxh64;

pub fn main() !void {
    // TODO: CLI to make these configurable.
    const data = "Hello, Zig";

    // 32 bit hash of data.
    const hash_32 = xxh32.oneshot(data, 0);
    std.debug.print("xxh32 of \"{s}\" with seed: {d} is: {d}\n", .{ data, 0, hash_32 });

    // 64 bit hash of data.
    const hash_64 = xxh64.oneshot(data, 0);
    std.debug.print("xxh64 of \"{s}\" with seed: {d} is: {d}\n", .{ data, 0, hash_64 });
}
