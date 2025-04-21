//! Implementation of 64 bit xxhash [spec](https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md#xxh64-algorithm-description).

const std = @import("std");
const bytes = @import("bytes.zig");

const testing = std.testing;
const rotl = std.math.rotl;

const PRIME_1: u64 = 0x9E3779B185EBCA87;
const PRIME_2: u64 = 0xC2B2AE3D27D4EB4F;
const PRIME_3: u64 = 0x165667B19E3779F9;
const PRIME_4: u64 = 0x85EBCA77C2B2AE63;
const PRIME_5: u64 = 0x27D4EB2F165667C5;

/// 64 bit variant of xxHash.
pub const Xxh64 = struct {
    /// Generate hash for an entire message.
    ///
    /// # Arguments
    ///
    /// * `data` - Message to hash.
    /// * `seed` - Initial seed for the hash.
    pub fn oneshot(data: []const u8, seed: u64) u64 {
        // Setup initial state for the digest.
        var digest: Digest = undefined;
        var buf = bytes.IntBuf{ .data = data };

        // Initialize digest.
        if (data.len >= 32) {
            // Step 1: Initialize accumulators.
            var stripe = Stripe.initialize(seed);

            // Step 2: Process stripes.
            while (buf.remaining() >= 32) {
                stripe.process(buf.next_stripe(u64));
            }

            // Step 3: Accumulator convergence.
            digest = stripe.converge();
        } else {
            // Step 1: Don't have enough bytes for a complete stripe.
            digest = Digest.initialize(seed);
        }

        // Step 4: Add input length.
        digest.addLength(data.len);

        // Step 5: Consume remaining input.
        while (buf.remaining() >= 8) {
            digest.process64(buf.next(u64));
        }

        if (buf.remaining() >= 4) {
            digest.process32(buf.next(u32));
        }

        while (buf.remaining() >= 1) {
            digest.process8(buf.next(u8));
        }

        // Step 6: Final mix (avalanche).
        return digest.finalize();
    }
};

const Digest = struct {
    accumulator: u64,

    /// Step 1 for input length < 32 bytes.
    fn initialize(seed: u64) @This() {
        return Digest{
            .accumulator = seed +% PRIME_5,
        };
    }

    /// Step 4: Add input length.
    fn addLength(self: *@This(), length: usize) void {
        // If size larger than 64 bits, preserve the lower 64 bits.
        self.accumulator +%= @truncate(length);
    }

    // Step 5: Add remaining.

    fn process8(self: *@This(), data: u8) void {
        self.accumulator ^= (@as(u64, data) *% PRIME_5);
        self.accumulator = rotl(u64, self.accumulator, 11) *% PRIME_1;
    }

    fn process32(self: *@This(), data: u32) void {
        self.accumulator ^= (@as(u64, data) *% PRIME_1);
        self.accumulator = rotl(u64, self.accumulator, 23) *% PRIME_2;
        self.accumulator +%= PRIME_3;
    }

    fn process64(self: *@This(), data: u64) void {
        self.accumulator ^= round(0, data);
        self.accumulator = rotl(u64, self.accumulator, 27) *% PRIME_1;
        self.accumulator +%= PRIME_4;
    }

    fn finalize(self: *@This()) u64 {
        // Step 6: Final mix (avalanche).
        self.accumulator ^= self.accumulator >> 33;
        self.accumulator *%= PRIME_2;
        self.accumulator ^= self.accumulator >> 29;
        self.accumulator *%= PRIME_3;
        self.accumulator ^= self.accumulator >> 32;

        // Step 7: Return the message digest.
        return self.accumulator;
    }

    fn round(accumulator: u64, lane: u64) u64 {
        return rotl(u64, accumulator +% (lane *% PRIME_2), 31) *% PRIME_1;
    }
};

const Stripe = struct {
    accumulator_1: u64,
    accumulator_2: u64,
    accumulator_3: u64,
    accumulator_4: u64,

    /// Step 1: Initialize internal accumulators.
    fn initialize(seed: u64) @This() {
        return Stripe{
            .accumulator_1 = seed +% PRIME_1 +% PRIME_2,
            .accumulator_2 = seed +% PRIME_2,
            .accumulator_3 = seed,
            .accumulator_4 = seed -% PRIME_1,
        };
    }

    /// Step 2: Process stripes.
    fn process(self: *@This(), stripe: [4]u64) void {
        self.accumulator_1 = round(self.accumulator_1, stripe[0]);
        self.accumulator_2 = round(self.accumulator_2, stripe[1]);
        self.accumulator_3 = round(self.accumulator_3, stripe[2]);
        self.accumulator_4 = round(self.accumulator_4, stripe[3]);
    }

    /// Step 3: Accumulator convergence.
    fn converge(self: *@This()) Digest {
        var accumulator: u64 = 0;

        accumulator +%= rotl(u64, self.accumulator_1, 1);
        accumulator +%= rotl(u64, self.accumulator_2, 7);
        accumulator +%= rotl(u64, self.accumulator_3, 12);
        accumulator +%= rotl(u64, self.accumulator_4, 18);

        accumulator = mergeAccumulator(accumulator, self.accumulator_1);
        accumulator = mergeAccumulator(accumulator, self.accumulator_2);
        accumulator = mergeAccumulator(accumulator, self.accumulator_3);
        accumulator = mergeAccumulator(accumulator, self.accumulator_4);

        return Digest{
            .accumulator = accumulator,
        };
    }

    fn mergeAccumulator(accumulator: u64, lane: u64) u64 {
        return ((accumulator ^ round(0, lane)) *% PRIME_1) +% PRIME_4;
    }

    fn round(accumulator: u64, lane: u64) u64 {
        return rotl(u64, accumulator +% (lane *% PRIME_2), 31) *% PRIME_1;
    }
};

// https://asecuritysite.com/encryption/xxhash

test "example 1" {
    const data = "Nobody inspects the spammish repetition";
    const hash = Xxh64.oneshot(data, 0);
    try testing.expect(hash == 0xfbcea83c8a378bf1);
}

test "example 1 with seed" {
    const data = "Nobody inspects the spammish repetition";
    const hash = Xxh64.oneshot(data, 69);
    try testing.expect(hash == 0xb7b1577fc25f21e6);
}

test "example 2" {
    const data = "The quick brown fox jumps over the lazy dog";
    const hash = Xxh64.oneshot(data, 0);
    try testing.expect(hash == 0x0b242d361fda71bc);
}

test "example 2 with seed" {
    const data = "The quick brown fox jumps over the lazy dog";
    const hash = Xxh64.oneshot(data, 69);
    try testing.expect(hash == 0x1673b09e13f8fff8);
}
