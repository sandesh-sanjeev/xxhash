const std = @import("std");
const lib = @import("xxhash");

// Hash variants.
const Xxh64 = lib.xxh64.Xxh64;

pub fn main() !void {
    // TODO: CLI to make these configurable.
    const data = "Hello, Zig";

    // 64 bit hash of data.
    _ = Xxh64.oneshotV(data, 0);
    // std.debug.print("xxh64 of \"{s}\" with seed: {d} is: {d}\n", .{ data, 0, hash_64 });
}
