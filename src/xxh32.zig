//! Implementation of 32 bit xxhash [spec](https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md#xxh32-algorithm-description).

const std = @import("std");
const bytes = @import("bytes.zig");

const testing = std.testing;
const math = std.math;

const PRIME32_1: u32 = 0x9E3779B1;
const PRIME32_2: u32 = 0x85EBCA77;
const PRIME32_3: u32 = 0xC2B2AE3D;
const PRIME32_4: u32 = 0x27D4EB2F;
const PRIME32_5: u32 = 0x165667B1;

/// Generate 32 bit hash of an entire message.
///
/// # Arguments
///
/// * `data` - Blob of bytes from a message.
/// * `seed` - Seed to use when generating hash.
pub fn oneshot(data: []const u8, seed: u32) u32 {
    // Setup initial state for the digest.
    var acc: u32 = 0;
    var buf = bytes.NumBuf{ .data = data };

    // Process bytes in stripes if enough bytes are available.
    if (data.len >= 16) {
        // Step 1: Initialize internal accumulators.
        // Accumulators one per lane in a stripe.
        var acc_1 = seed +% PRIME32_1 +% PRIME32_2;
        var acc_2 = seed +% PRIME32_2;
        var acc_3 = seed;
        var acc_4 = seed -% PRIME32_1;

        // Step 2: Process stripes.
        // Each stripe is contiguous memory slice of 16 bytes.
        // And each stripe is made up of 4 lanes each 4 bytes wide.
        while (buf.remaining() >= 16) {
            acc_1 = round(acc_1, buf.next(u32));
            acc_2 = round(acc_2, buf.next(u32));
            acc_3 = round(acc_3, buf.next(u32));
            acc_4 = round(acc_4, buf.next(u32));
        }

        // Step 3: Accumulator convergence.
        acc +%= math.rotl(u32, acc_1, 1);
        acc +%= math.rotl(u32, acc_2, 7);
        acc +%= math.rotl(u32, acc_3, 12);
        acc +%= math.rotl(u32, acc_4, 18);
    } else {
        // Don't have enough bytes for a complete stripe.
        acc +%= seed + PRIME32_5;
    }

    // Step 4: Add input length.
    // If size larger than 32 bits, preserve the lower 32 bits.
    acc +%= @truncate(data.len);

    // Step 5: Consume remaining input.
    while (buf.remaining() >= 4) {
        acc +%= buf.next(u32) *% PRIME32_3;
        acc = math.rotl(u32, acc, 17) *% PRIME32_4;
    }

    while (buf.remaining() >= 1) {
        const lane = @as(u32, buf.next(u8));
        acc +%= (lane *% PRIME32_5);
        acc = math.rotl(u32, acc, 11) *% PRIME32_1;
    }

    // Step 6: Final mix (avalanche).
    acc ^= acc >> 15;
    acc *%= PRIME32_2;
    acc ^= acc >> 13;
    acc *%= PRIME32_3;
    acc ^= acc >> 16;

    // Step 7: Return the digest.
    return acc;
}

fn round(acc: u32, lane: u32) u32 {
    const acc_new = acc +% (lane *% PRIME32_2);
    return math.rotl(u32, acc_new, 13) *% PRIME32_1;
}

// https://asecuritysite.com/encryption/xxhash

test "example 1" {
    const data = "Nobody inspects the spammish repetition";
    const hash = oneshot(data, 0);
    try testing.expect(hash == 0xe2293b2f);
}

test "example 1 with seed" {
    const data = "Nobody inspects the spammish repetition";
    const hash = oneshot(data, 69);
    try testing.expect(hash == 0xda0e31cb);
}

test "example 2" {
    const data = "The quick brown fox jumps over the lazy dog";
    const hash = oneshot(data, 0);
    try testing.expect(hash == 0xe85ea4de);
}

test "example 2 with seed" {
    const data = "The quick brown fox jumps over the lazy dog";
    const hash = oneshot(data, 69);
    try testing.expect(hash == 0x4f8fa903);
}

test "fuzz test conformance" {
    const Context = struct {
        fn testOne(self: @This(), data: []const u8) anyerror!void {
            _ = self;

            // Compute hash from a reference implementation.
            // TODO: Replace this with "real" reference implementation.
            // https://github.com/Cyan4973/xxHash.
            var xxHash = std.hash.XxHash32.init(0);
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
