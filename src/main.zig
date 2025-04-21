//! Executable that runs xxhash benchmarks.

const std = @import("std");
const xxhash = @import("xxhash");
const zbench = @import("zbench");

const Xxh64 = xxhash.Xxh64;
const XxHash64 = std.hash.XxHash64;

const Xxh32 = xxhash.Xxh32;
const XxHash32 = std.hash.XxHash32;

const Benchmark = zbench.Benchmark;

// For pseudo random stuff.
const Random = std.Random.Xoshiro256;

// For allocations.
const Allocator = std.mem.Allocator;
const SmpAllocator = std.heap.smp_allocator;

pub fn main() !void {
    // Inputs for benchmarks.
    var random = try getRandom();

    // Seed for the test.
    const seed64 = random.next();
    const seed32: u32 = @truncate(random.next());

    // Configurations for the benchmark harness.
    const config = zbench.Config{ .iterations = 10000000 };

    // Initialize benchmark harness.
    var bench = Benchmark.init(SmpAllocator, config);
    defer bench.deinit();

    // Benchmarks for 1 KB message.
    var data1KB = randomBytes(&random, 1024);

    const oneshotXxh32 = BenchmarkXxh32{ .data = &data1KB, .seed = seed32 };
    const oneshotXxh64 = BenchmarkXxh64{ .data = &data1KB, .seed = seed64 };

    try bench.addParam("custom: xxh32 (1KB)", &oneshotXxh32, .{});
    try bench.addParam("custom: xxh64 (1KB)", &oneshotXxh64, .{});

    const oneshotXxh32Std = BenchmarkXxHash32{ .data = &data1KB, .seed = seed32 };
    const oneshotXxh64Std = BenchmarkXxHash64{ .data = &data1KB, .seed = seed64 };

    try bench.addParam("std: xxh32 (1KB)", &oneshotXxh32Std, .{});
    try bench.addParam("std: xxh64 (1KB)", &oneshotXxh64Std, .{});

    // Write benchmark report to stdout.
    const stdout = std.io.getStdOut();
    try stdout.writer().writeAll("\n");
    try bench.run(stdout.writer());

    // const xxh64_hash = Xxh64.oneshot(&data1KB, seed64);
    // const xxhash64_hash = XxHash64.hash(seed64, &data1KB);
    // if (xxh64_hash != xxhash64_hash) {
    //     @panic("64 bit hash doesn't match");
    // }

    // const xxh32_hash = Xxh32.oneshot(&data1KB, seed32);
    // const xxhash32_hash = XxHash32.hash(seed32, &data1KB);
    // if (xxh32_hash != xxhash32_hash) {
    //     @panic("32 bit hash doesn't match");
    // }

    // std.debug.print("xxh32: {d}\n", .{Xxh32.oneshot(&data1KB, seed32)});
    // std.debug.print("xxh64: {d}\n", .{Xxh64.oneshot(&data1KB, seed64)});
    // std.debug.print("xxHash32: {d}\n", .{XxHash32.hash(seed32, &data1KB)});
    // std.debug.print("xxHash64: {d}\n", .{XxHash64.hash(seed64, &data1KB)});
}

// Definition of all the benchmarks.

const BenchmarkXxh32 = struct {
    data: []const u8,
    seed: u32,

    pub fn run(self: @This(), _: Allocator) void {
        _ = Xxh32.oneshot(self.data, self.seed);
    }
};

const BenchmarkXxHash32 = struct {
    data: []const u8,
    seed: u32,

    pub fn run(self: @This(), _: Allocator) void {
        _ = XxHash32.hash(self.seed, self.data);
    }
};

const BenchmarkXxh64 = struct {
    data: []const u8,
    seed: u64,

    pub fn run(self: @This(), _: Allocator) void {
        _ = Xxh64.oneshot(self.data, self.seed);
    }
};

const BenchmarkXxHash64 = struct {
    data: []const u8,
    seed: u64,

    pub fn run(self: @This(), _: Allocator) void {
        _ = XxHash64.hash(self.seed, self.data);
    }
};

// Other helpers

fn getRandom() !Random {
    var seed: u64 = undefined;
    try std.posix.getrandom(std.mem.asBytes(&seed));
    return std.Random.DefaultPrng.init(seed);
}

fn randomBytes(random: *Random, T: comptime_int) [T]u8 {
    var data: [T]u8 = undefined;
    random.fill(&data);
    return data;
}
