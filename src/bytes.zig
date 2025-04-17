//! Set of common byte manipulation utilities used across hash variants.

const std = @import("std");

/// A buffer that one can use to read a blob of bytes as a sequence of numbers.
pub const NumBuf = struct {
    data: []const u8,
    offset: usize = 0,

    /// Number of bytes remaining in the buffer.
    pub fn remaining(self: *NumBuf) usize {
        return self.data.len - self.offset;
    }

    /// Fetch the next number.
    ///
    /// # Arguments
    ///
    /// * `T` - Number of number to fetch.
    pub fn next(self: *NumBuf, comptime T: type) T {
        // Fetch the exact size of the number type.
        const size = @sizeOf(T);

        // Fetch rage of bytes that holds the next number.
        const start = self.offset;
        const end = self.offset + size;
        const bytes = self.data[start..end][0..size];
        self.offset += size;

        // Parse the provided bytes into the target number type.
        return std.mem.readInt(T, bytes, .little);
    }
};
