//! A pure zig implementation of xxhash specification.
const std = @import("std");

// Exports
pub const xxh32 = @import("xxh32.zig");
pub const xxh64 = @import("xxh64.zig");

// Hack to run all unit tests in referenced source files.
// https://ziggit.dev/t/getting-zig-build-test-to-find-all-the-tests-in-my-module/6276
test {
    std.testing.refAllDeclsRecursive(@This());
}
