//! Implementation of 32 bit xxhash [spec](https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md#xxh32-algorithm-description).

const std = @import("std");
const bytes = @import("bytes.zig");

const testing = std.testing;
const rotl = std.math.rotl;

const PRIME_1: u32 = 0x9E3779B1;
const PRIME_2: u32 = 0x85EBCA77;
const PRIME_3: u32 = 0xC2B2AE3D;
const PRIME_4: u32 = 0x27D4EB2F;
const PRIME_5: u32 = 0x165667B1;

/// 32 bit variant of xxHash.
pub const Xxh32 = struct {
    /// Generate hash of an entire message.
    ///
    /// # Arguments
    ///
    /// * `data` - Blob of bytes from a message.
    /// * `seed` - Seed to use when generating hash.
    pub fn oneshot(data: []const u8, seed: u32) u32 {
        // Setup initial state for the digest.
        var digest: Digest = undefined;
        var buf = bytes.IntBuf{ .data = data };

        // Initialize digest.
        if (data.len >= 16) {
            // Step 1: Initialize accumulators.
            var stripe = Stripe.initialize(seed);

            // Step 2: Process stripes.
            while (buf.remaining() >= 16) {
                stripe.process(buf.next_stripe(u32));
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
        while (buf.remaining() >= 4) {
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
    accumulator: u32,

    /// Step 1 for input length < 32 bytes.
    fn initialize(seed: u32) @This() {
        return Digest{
            .accumulator = seed +% PRIME_5,
        };
    }

    /// Step 4: Add input length.
    fn addLength(self: *@This(), length: usize) void {
        // If size larger than 32 bits, preserve the lower 32 bits.
        self.accumulator +%= @truncate(length);
    }

    // Step 5: Add remaining.

    fn process8(self: *@This(), data: u8) void {
        self.accumulator +%= @as(u32, data) *% PRIME_5;
        self.accumulator = rotl(u32, self.accumulator, 11) *% PRIME_1;
    }

    fn process32(self: *@This(), data: u32) void {
        self.accumulator +%= data *% PRIME_3;
        self.accumulator = rotl(u32, self.accumulator, 17) *% PRIME_4;
    }

    fn finalize(self: *@This()) u32 {
        // Step 6: Final mix (avalanche).
        self.accumulator ^= self.accumulator >> 15;
        self.accumulator *%= PRIME_2;
        self.accumulator ^= self.accumulator >> 13;
        self.accumulator *%= PRIME_3;
        self.accumulator ^= self.accumulator >> 16;

        // Step 7: Return the message digest.
        return self.accumulator;
    }
};

const Stripe = struct {
    accumulator_1: u32,
    accumulator_2: u32,
    accumulator_3: u32,
    accumulator_4: u32,

    /// Step 1: Initialize internal accumulators.
    fn initialize(seed: u32) @This() {
        return Stripe{
            .accumulator_1 = seed +% PRIME_1 +% PRIME_2,
            .accumulator_2 = seed +% PRIME_2,
            .accumulator_3 = seed,
            .accumulator_4 = seed -% PRIME_1,
        };
    }

    /// Step 2: Process stripes.
    fn process(self: *@This(), stripe: [4]u32) void {
        self.accumulator_1 = round(self.accumulator_1, stripe[0]);
        self.accumulator_2 = round(self.accumulator_2, stripe[1]);
        self.accumulator_3 = round(self.accumulator_3, stripe[2]);
        self.accumulator_4 = round(self.accumulator_4, stripe[3]);
    }

    /// Step 3: Accumulator convergence.
    fn converge(self: *@This()) Digest {
        var accumulator: u32 = 0;

        accumulator +%= rotl(u32, self.accumulator_1, 1);
        accumulator +%= rotl(u32, self.accumulator_2, 7);
        accumulator +%= rotl(u32, self.accumulator_3, 12);
        accumulator +%= rotl(u32, self.accumulator_4, 18);

        return Digest{
            .accumulator = accumulator,
        };
    }

    fn round(accumulator: u32, lane: u32) u32 {
        return rotl(u32, accumulator +% (lane *% PRIME_2), 13) *% PRIME_1;
    }
};

// https://asecuritysite.com/encryption/xxhash

test "example 1" {
    const data = "Nobody inspects the spammish repetition";
    const hash = Xxh32.oneshot(data, 0);
    try testing.expect(hash == 0xe2293b2f);
}

test "example 1 with seed" {
    const data = "Nobody inspects the spammish repetition";
    const hash = Xxh32.oneshot(data, 69);
    try testing.expect(hash == 0xda0e31cb);
}

test "example 2" {
    const data = "The quick brown fox jumps over the lazy dog";
    const hash = Xxh32.oneshot(data, 0);
    try testing.expect(hash == 0xe85ea4de);
}

test "example 2 with seed" {
    const data = "The quick brown fox jumps over the lazy dog";
    const hash = Xxh32.oneshot(data, 69);
    try testing.expect(hash == 0x4f8fa903);
}
