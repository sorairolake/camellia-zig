// SPDX-FileCopyrightText: 2025 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

test {
    const testing = @import("std").testing;

    _ = @import("camellia_128.zig");
    _ = @import("camellia_192.zig");
    _ = @import("camellia_256.zig");

    testing.refAllDecls(@This());
}
