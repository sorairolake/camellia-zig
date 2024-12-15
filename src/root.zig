// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `camellia` package is an implementation of the [Camellia] block cipher
//! defined in [RFC 3713].
//!
//! [Camellia]: https://info.isl.ntt.co.jp/crypt/eng/camellia/
//! [RFC 3713]: https://datatracker.ietf.org/doc/html/rfc3713

const std = @import("std");
const testing = std.testing;

export fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "basic add functionality" {
    try testing.expect(add(3, 7) == 10);
}
