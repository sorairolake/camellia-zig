// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `camellia` package is an implementation of the
//! [Camellia](https://info.isl.ntt.co.jp/crypt/eng/camellia/) block cipher
//! defined in [RFC 3713](https://datatracker.ietf.org/doc/html/rfc3713).

const camellia = @import("camellia.zig");

pub const Camellia128 = camellia.Camellia128;
pub const Camellia192 = camellia.Camellia192;
pub const Camellia256 = camellia.Camellia256;
pub const DecryptContext = camellia.DecryptContext;
pub const EncryptContext = camellia.EncryptContext;

test {
    const testing = @import("std").testing;

    _ = @import("consts.zig");

    testing.refAllDeclsRecursive(@This());
}
