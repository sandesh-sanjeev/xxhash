//! Implementation of 64 bit xxhash [spec](https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md#xxh64-algorithm-description).

const std = @import("std");
const bytes = @import("bytes.zig");

const testing = std.testing;
const math = std.math;

const PRIME64_1: u64 = 0x9E3779B185EBCA87;
const PRIME64_2: u64 = 0xC2B2AE3D27D4EB4F;
const PRIME64_3: u64 = 0x165667B19E3779F9;
const PRIME64_4: u64 = 0x85EBCA77C2B2AE63;
const PRIME64_5: u64 = 0x27D4EB2F165667C5;

/// Generate 64 bit hash of an entire message.
///
/// # Arguments
///
/// * `data` - Blob of bytes from a message.
/// * `seed` - Seed to use when generating hash.
pub fn oneshot(data: []const u8, seed: u64) u64 {
    // Setup initial state for the digest.
    var acc: u64 = 0;
    var buf = bytes.NumBuf{ .data = data };

    // Process bytes in stripes if enough bytes are available.
    if (data.len >= 32) {
        // Step 1: Initialize internal accumulators.
        // Accumulators one per lane in a stripe.
        var acc_1 = seed +% PRIME64_1 +% PRIME64_2;
        var acc_2 = seed +% PRIME64_2;
        var acc_3 = seed;
        var acc_4 = seed -% PRIME64_1;

        // Step 2: Process stripes.
        // Each stripe is contiguous memory slice of 32 bytes.
        // And each stripe is made up of 4 lanes each 8 bytes wide.
        while (buf.remaining() >= 32) {
            acc_1 = round(acc_1, buf.next(u64));
            acc_2 = round(acc_2, buf.next(u64));
            acc_3 = round(acc_3, buf.next(u64));
            acc_4 = round(acc_4, buf.next(u64));
        }

        // Step 3: Accumulator convergence.
        acc +%= math.rotl(u64, acc_1, 1);
        acc +%= math.rotl(u64, acc_2, 7);
        acc +%= math.rotl(u64, acc_3, 12);
        acc +%= math.rotl(u64, acc_4, 18);

        acc = mergeAccumulator(acc, acc_1);
        acc = mergeAccumulator(acc, acc_2);
        acc = mergeAccumulator(acc, acc_3);
        acc = mergeAccumulator(acc, acc_4);
    } else {
        // Don't have enough bytes for a complete stripe.
        acc +%= seed + PRIME64_5;
    }

    // Step 4: Add input length.
    // If size larger than 64 bits, preserve the lower 64 bits.
    // This should almost never happen because most (modern) platforms have 64 bit address space.
    acc +%= @truncate(data.len);

    // Step 5: Consume remaining input.
    while (buf.remaining() >= 8) {
        acc ^= round(0, buf.next(u64));
        acc = math.rotl(u64, acc, 27) *% PRIME64_1;
        acc +%= PRIME64_4;
    }

    if (buf.remaining() >= 4) {
        acc ^= (@as(u64, buf.next(u32)) *% PRIME64_1);
        acc = math.rotl(u64, acc, 23) *% PRIME64_2;
        acc +%= PRIME64_3;
    }

    while (buf.remaining() >= 1) {
        acc ^= (@as(u64, buf.next(u8)) *% PRIME64_5);
        acc = math.rotl(u64, acc, 11) *% PRIME64_1;
    }

    // Step 6: Final mix (avalanche).
    acc ^= acc >> 33;
    acc *%= PRIME64_2;
    acc ^= acc >> 29;
    acc *%= PRIME64_3;
    acc ^= acc >> 32;

    // Step 7: Return the message digest.
    return acc;
}

fn round(acc: u64, lane: u64) u64 {
    const acc_new = acc +% (lane *% PRIME64_2);
    return math.rotl(u64, acc_new, 31) *% PRIME64_1;
}

fn mergeAccumulator(acc: u64, acc_n: u64) u64 {
    var acc_new = acc ^ round(0, acc_n);
    acc_new *%= PRIME64_1;
    return acc_new +% PRIME64_4;
}

// https://asecuritysite.com/encryption/xxhash

test "example 1" {
    const data = "Nobody inspects the spammish repetition";
    const hash = oneshot(data, 0);
    try testing.expect(hash == 0xfbcea83c8a378bf1);
}

test "example 1 with seed" {
    const data = "Nobody inspects the spammish repetition";
    const hash = oneshot(data, 69);
    try testing.expect(hash == 0xb7b1577fc25f21e6);
}

test "example 2" {
    const data = "The quick brown fox jumps over the lazy dog";
    const hash = oneshot(data, 0);
    try testing.expect(hash == 0x0b242d361fda71bc);
}

test "example 2 with seed" {
    const data = "The quick brown fox jumps over the lazy dog";
    const hash = oneshot(data, 69);
    try testing.expect(hash == 0x1673b09e13f8fff8);
}

test "fuzz test conformance" {
    const Context = struct {
        fn testOne(self: @This(), data: []const u8) anyerror!void {
            _ = self;

            // Compute hash from a reference implementation.
            // TODO: Replace this with "read" reference implementation.
            // https://github.com/Cyan4973/xxHash.
            var xxHash = std.hash.XxHash64.init(0);
            xxHash.update(data);
            const expected = xxHash.final();

            // Compute hash using our implementation.
            const actual = oneshot(data, 0);

            // They should be the same because seed is the same.
            try testing.expectEqual(expected, actual);
        }
    };

    try testing.fuzz(Context{}, Context.testOne, .{});
}
