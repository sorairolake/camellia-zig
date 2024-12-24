// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Implementations of the Camellia block cipher.

const std = @import("std");

const consts = @import("consts.zig");

const builtin = std.builtin;
const debug = std.debug;
const math = std.math;
const mem = std.mem;

/// MASK32 constant value defined in RFC 3713.
const mask_32 = 0xFFFF_FFFF;

/// MASK64 constant value defined in RFC 3713.
const mask_64 = 0xFFFF_FFFF_FFFF_FFFF;

/// F-function defined in RFC 3713.
///
/// This implementation is based on the Camellia implementation in the [Botan]
/// cryptography library, which is licensed under the [BSD 2-Clause License].
/// See [`camellia.cpp`] for details.
///
/// [Botan]: https://botan.randombit.net/
/// [BSD 2-Clause License]: https://github.com/randombit/botan/blob/3.6.1/license.txt
/// [`camellia.cpp`]: https://github.com/randombit/botan/blob/3.6.1/src/lib/block/camellia/camellia.cpp#L87-L109
fn f(f_in: u64, ke: u64) u64 {
    const m1 = 0x0101_0100_0100_0001;
    const m2 = 0x0001_0101_0101_0000;
    const m3 = 0x0100_0101_0001_0100;
    const m4 = 0x0101_0001_0000_0101;
    const m5 = 0x0001_0101_0001_0101;
    const m6 = 0x0100_0101_0100_0101;
    const m7 = 0x0101_0001_0101_0001;
    const m8 = 0x0101_0100_0101_0100;

    var x: [8]u8 = undefined;
    mem.writeInt(u64, &x, f_in ^ ke, builtin.Endian.big);

    const z1 = m1 * @as(u64, consts.sbox_1[x[0]]);
    const z2 = m2 * @as(u64, consts.sbox_2[x[1]]);
    const z3 = m3 * @as(u64, consts.sbox_3[x[2]]);
    const z4 = m4 * @as(u64, consts.sbox_4[x[3]]);
    const z5 = m5 * @as(u64, consts.sbox_2[x[4]]);
    const z6 = m6 * @as(u64, consts.sbox_3[x[5]]);
    const z7 = m7 * @as(u64, consts.sbox_4[x[6]]);
    const z8 = m8 * @as(u64, consts.sbox_1[x[7]]);
    return z1 ^ z2 ^ z3 ^ z4 ^ z5 ^ z6 ^ z7 ^ z8;
}

/// FL-function defined in RFC 3713.
fn fl(fl_in: u64, ke: u64) u64 {
    var x1: u32 = @intCast(fl_in >> 32);
    var x2: u32 = @intCast(fl_in & mask_32);

    const k1: u32 = @intCast(ke >> 32);
    const k2: u32 = @intCast(ke & mask_32);

    x2 ^= math.rotl(u32, x1 & k1, 1);
    x1 ^= x2 | k2;
    return (@as(u64, x1) << 32) | x2;
}

/// FLINV-function defined in RFC 3713.
fn flinv(flinv_in: u64, ke: u64) u64 {
    var y1: u32 = @intCast(flinv_in >> 32);
    var y2: u32 = @intCast(flinv_in & mask_32);

    const k1: u32 = @intCast(ke >> 32);
    const k2: u32 = @intCast(ke & mask_32);

    y1 ^= y2 | k2;
    y2 ^= math.rotl(u32, y1 & k1, 1);
    return (@as(u64, y1) << 32) | y2;
}

fn KeySchedule(comptime Camellia: type) type {
    debug.assert(Camellia.rounds == 18 or Camellia.rounds == 24);

    return struct {
        kw: [4]u64,
        k: [Camellia.rounds]u64,
        ke: [(Camellia.rounds / 3) - 2]u64,

        const Self = @This();

        fn generate_ka(kl: u128, kr: u128) u128 {
            var d1: u64 = @intCast((kl ^ kr) >> 64);
            var d2: u64 = @intCast((kl ^ kr) & mask_64);
            d2 ^= f(d1, consts.sigma_1);
            d1 ^= f(d2, consts.sigma_2);
            d1 ^= @intCast(kl >> 64);
            d2 ^= @intCast(kl & mask_64);
            d2 ^= f(d1, consts.sigma_3);
            d1 ^= f(d2, consts.sigma_4);
            return (@as(u128, d1) << 64) | d2;
        }

        fn generate_kb(ka: u128, kr: u128) u128 {
            var d1: u64 = @intCast((ka ^ kr) >> 64);
            var d2: u64 = @intCast((ka ^ kr) & mask_64);
            d2 ^= f(d1, consts.sigma_5);
            d1 ^= f(d2, consts.sigma_6);
            return (@as(u128, d1) << 64) | d2;
        }

        fn generate_subkeys_26(kl: u128, ka: u128) Self {
            var kw: [4]u64 = undefined;
            var k: [18]u64 = undefined;
            var ke: [4]u64 = undefined;

            kw[0] = @intCast(kl >> 64);
            kw[1] = @intCast(kl & mask_64);
            k[0] = @intCast(ka >> 64);
            k[1] = @intCast(ka & mask_64);
            k[2] = @intCast(math.rotl(u128, kl, 15) >> 64);
            k[3] = @intCast(math.rotl(u128, kl, 15) & mask_64);
            k[4] = @intCast(math.rotl(u128, ka, 15) >> 64);
            k[5] = @intCast(math.rotl(u128, ka, 15) & mask_64);
            ke[0] = @intCast(math.rotl(u128, ka, 30) >> 64);
            ke[1] = @intCast(math.rotl(u128, ka, 30) & mask_64);
            k[6] = @intCast(math.rotl(u128, kl, 45) >> 64);
            k[7] = @intCast(math.rotl(u128, kl, 45) & mask_64);
            k[8] = @intCast(math.rotl(u128, ka, 45) >> 64);
            k[9] = @intCast(math.rotl(u128, kl, 60) & mask_64);
            k[10] = @intCast(math.rotl(u128, ka, 60) >> 64);
            k[11] = @intCast(math.rotl(u128, ka, 60) & mask_64);
            ke[2] = @intCast(math.rotl(u128, kl, 77) >> 64);
            ke[3] = @intCast(math.rotl(u128, kl, 77) & mask_64);
            k[12] = @intCast(math.rotl(u128, kl, 94) >> 64);
            k[13] = @intCast(math.rotl(u128, kl, 94) & mask_64);
            k[14] = @intCast(math.rotl(u128, ka, 94) >> 64);
            k[15] = @intCast(math.rotl(u128, ka, 94) & mask_64);
            k[16] = @intCast(math.rotl(u128, kl, 111) >> 64);
            k[17] = @intCast(math.rotl(u128, kl, 111) & mask_64);
            kw[2] = @intCast(math.rotl(u128, ka, 111) >> 64);
            kw[3] = @intCast(math.rotl(u128, ka, 111) & mask_64);
            return .{ .kw = kw, .k = k, .ke = ke };
        }

        fn generate_subkeys_34(kl: u128, kr: u128, ka: u128, kb: u128) Self {
            var kw: [4]u64 = undefined;
            var k: [24]u64 = undefined;
            var ke: [6]u64 = undefined;

            kw[0] = @intCast(kl >> 64);
            kw[1] = @intCast(kl & mask_64);
            k[0] = @intCast(kb >> 64);
            k[1] = @intCast(kb & mask_64);
            k[2] = @intCast(math.rotl(u128, kr, 15) >> 64);
            k[3] = @intCast(math.rotl(u128, kr, 15) & mask_64);
            k[4] = @intCast(math.rotl(u128, ka, 15) >> 64);
            k[5] = @intCast(math.rotl(u128, ka, 15) & mask_64);
            ke[0] = @intCast(math.rotl(u128, kr, 30) >> 64);
            ke[1] = @intCast(math.rotl(u128, kr, 30) & mask_64);
            k[6] = @intCast(math.rotl(u128, kb, 30) >> 64);
            k[7] = @intCast(math.rotl(u128, kb, 30) & mask_64);
            k[8] = @intCast(math.rotl(u128, kl, 45) >> 64);
            k[9] = @intCast(math.rotl(u128, kl, 45) & mask_64);
            k[10] = @intCast(math.rotl(u128, ka, 45) >> 64);
            k[11] = @intCast(math.rotl(u128, ka, 45) & mask_64);
            ke[2] = @intCast(math.rotl(u128, kl, 60) >> 64);
            ke[3] = @intCast(math.rotl(u128, kl, 60) & mask_64);
            k[12] = @intCast(math.rotl(u128, kr, 60) >> 64);
            k[13] = @intCast(math.rotl(u128, kr, 60) & mask_64);
            k[14] = @intCast(math.rotl(u128, kb, 60) >> 64);
            k[15] = @intCast(math.rotl(u128, kb, 60) & mask_64);
            k[16] = @intCast(math.rotl(u128, kl, 77) >> 64);
            k[17] = @intCast(math.rotl(u128, kl, 77) & mask_64);
            ke[4] = @intCast(math.rotl(u128, ka, 77) >> 64);
            ke[5] = @intCast(math.rotl(u128, ka, 77) & mask_64);
            k[18] = @intCast(math.rotl(u128, kr, 94) >> 64);
            k[19] = @intCast(math.rotl(u128, kr, 94) & mask_64);
            k[20] = @intCast(math.rotl(u128, ka, 94) >> 64);
            k[21] = @intCast(math.rotl(u128, ka, 94) & mask_64);
            k[22] = @intCast(math.rotl(u128, kl, 111) >> 64);
            k[23] = @intCast(math.rotl(u128, kl, 111) & mask_64);
            kw[2] = @intCast(math.rotl(u128, kb, 111) >> 64);
            kw[3] = @intCast(math.rotl(u128, kb, 111) & mask_64);
            return .{ .kw = kw, .k = k, .ke = ke };
        }

        fn init128(key: [Camellia.key_size]u8) Self {
            const kl = mem.readInt(u128, &key, builtin.Endian.big);
            const kr = 0;
            const ka = generate_ka(kl, kr);
            return generate_subkeys_26(kl, ka);
        }

        fn init192(key: [Camellia.key_size]u8) Self {
            const kl = mem.readInt(u128, key[0..16], builtin.Endian.big);
            const rightmost_64 = mem.readInt(u64, key[16..], builtin.Endian.big);
            const kr = (@as(u128, rightmost_64) << 64) | (~rightmost_64);
            const ka = generate_ka(kl, kr);
            const kb = generate_kb(ka, kr);
            return generate_subkeys_34(kl, kr, ka, kb);
        }

        fn init256(key: [Camellia.key_size]u8) Self {
            const kl = mem.readInt(u128, key[0..16], builtin.Endian.big);
            const kr = mem.readInt(u128, key[16..], builtin.Endian.big);
            const ka = generate_ka(kl, kr);
            const kb = generate_kb(ka, kr);
            return generate_subkeys_34(kl, kr, ka, kb);
        }
    };
}

/// A context to perform encryption using the Camellia block cipher.
pub fn EncryptContext(comptime Camellia: type) type {
    debug.assert(Camellia.key_size == 16 or Camellia.key_size == 24 or Camellia.key_size == 32);

    return struct {
        key_schedule: KeySchedule(Camellia),

        const Self = @This();

        /// Creates a new encryption context with the given key.
        pub fn init(key: [Camellia.key_size]u8) Self {
            const key_schedule = switch (Camellia) {
                Camellia128 => KeySchedule(Camellia).init128(key),
                Camellia192 => KeySchedule(Camellia).init192(key),
                Camellia256 => KeySchedule(Camellia).init256(key),
                else => unreachable,
            };
            return .{ .key_schedule = key_schedule };
        }

        /// Encrypts a single block.
        pub fn encrypt(
            self: Self,
            dst: *[Camellia.block_size]u8,
            src: *const [Camellia.block_size]u8,
        ) void {
            var d1 = mem.readInt(u64, src[0..8], builtin.Endian.big);
            var d2 = mem.readInt(u64, src[8..], builtin.Endian.big);

            d1 ^= self.key_schedule.kw[0];
            d2 ^= self.key_schedule.kw[1];

            comptime var i = 0;
            inline while (i < Camellia.rounds) : (i += 2) {
                if ((i > 0) and (i % 6 == 0)) {
                    d1 = fl(d1, self.key_schedule.ke[(i / 3) - 2]);
                    d2 = flinv(d2, self.key_schedule.ke[(i / 3) - 1]);
                }

                d2 ^= f(d1, self.key_schedule.k[i]);
                d1 ^= f(d2, self.key_schedule.k[i + 1]);
            }

            d2 ^= self.key_schedule.kw[2];
            d1 ^= self.key_schedule.kw[3];

            mem.writeInt(u128, dst, (@as(u128, d2) << 64) | d1, builtin.Endian.big);
        }
    };
}

/// A context to perform decryption using the Camellia block cipher.
pub fn DecryptContext(comptime Camellia: type) type {
    debug.assert(Camellia.key_size == 16 or Camellia.key_size == 24 or Camellia.key_size == 32);

    return struct {
        key_schedule: KeySchedule(Camellia),

        const Self = @This();

        /// Creates a new decryption context with the given key.
        pub fn init(key: [Camellia.key_size]u8) Self {
            const key_schedule = switch (Camellia) {
                Camellia128 => KeySchedule(Camellia).init128(key),
                Camellia192 => KeySchedule(Camellia).init192(key),
                Camellia256 => KeySchedule(Camellia).init256(key),
                else => unreachable,
            };
            return .{ .key_schedule = key_schedule };
        }

        /// Decrypts a single block.
        pub fn decrypt(
            self: Self,
            dst: *[Camellia.block_size]u8,
            src: *const [Camellia.block_size]u8,
        ) void {
            var d1 = mem.readInt(u64, src[0..8], builtin.Endian.big);
            var d2 = mem.readInt(u64, src[8..], builtin.Endian.big);

            d2 ^= self.key_schedule.kw[3];
            d1 ^= self.key_schedule.kw[2];

            comptime var i = Camellia.rounds;
            inline while (i >= 2) : (i -= 2) {
                if ((i < Camellia.rounds) and (i % 6 == 0)) {
                    d1 = fl(d1, self.key_schedule.ke[(i / 3) - 1]);
                    d2 = flinv(d2, self.key_schedule.ke[(i / 3) - 2]);
                }

                d2 ^= f(d1, self.key_schedule.k[i - 1]);
                d1 ^= f(d2, self.key_schedule.k[i - 2]);
            }

            d1 ^= self.key_schedule.kw[1];
            d2 ^= self.key_schedule.kw[0];

            mem.writeInt(u128, dst, (@as(u128, d2) << 64) | d1, builtin.Endian.big);
        }
    };
}

/// Camellia-128 block cipher.
pub const Camellia128 = struct {
    const Self = @This();

    /// Key size in bytes.
    pub const key_size = 16;

    /// Block size in bytes.
    pub const block_size = 16;

    /// The number of rounds.
    pub const rounds = 18;

    /// Creates a new context for encryption.
    pub fn initEncrypt(key: [key_size]u8) EncryptContext(Self) {
        return EncryptContext(Self).init(key);
    }

    test initEncrypt {
        _ = Camellia128.initEncrypt([_]u8{0} ** Camellia128.key_size);
    }

    /// Creates a new context for decryption.
    pub fn initDecrypt(key: [key_size]u8) DecryptContext(Self) {
        return DecryptContext(Self).init(key);
    }

    test initDecrypt {
        _ = Camellia128.initDecrypt([_]u8{0} ** Camellia128.key_size);
    }
};

/// Camellia-192 block cipher.
pub const Camellia192 = struct {
    const Self = @This();

    /// Key size in bytes.
    pub const key_size = 24;

    /// Block size in bytes.
    pub const block_size = 16;

    /// The number of rounds.
    pub const rounds = 24;

    /// Creates a new context for encryption.
    pub fn initEncrypt(key: [key_size]u8) EncryptContext(Self) {
        return EncryptContext(Self).init(key);
    }

    test initEncrypt {
        _ = Camellia192.initEncrypt([_]u8{0} ** Camellia192.key_size);
    }

    /// Creates a new context for decryption.
    pub fn initDecrypt(key: [key_size]u8) DecryptContext(Self) {
        return DecryptContext(Self).init(key);
    }

    test initDecrypt {
        _ = Camellia192.initDecrypt([_]u8{0} ** Camellia192.key_size);
    }
};

/// Camellia-256 block cipher.
pub const Camellia256 = struct {
    const Self = @This();

    /// Key size in bytes.
    pub const key_size = 32;

    /// Block size in bytes.
    pub const block_size = 16;

    /// The number of rounds.
    pub const rounds = 24;

    /// Creates a new context for encryption.
    pub fn initEncrypt(key: [key_size]u8) EncryptContext(Self) {
        return EncryptContext(Self).init(key);
    }

    test initEncrypt {
        _ = Camellia256.initEncrypt([_]u8{0} ** Camellia256.key_size);
    }

    /// Creates a new context for decryption.
    pub fn initDecrypt(key: [key_size]u8) DecryptContext(Self) {
        return DecryptContext(Self).init(key);
    }

    test initDecrypt {
        _ = Camellia256.initDecrypt([_]u8{0} ** Camellia256.key_size);
    }
};

test {
    _ = @import("tests/camellia_128.zig");
    _ = @import("tests/camellia_192.zig");
    _ = @import("tests/camellia_256.zig");
}

test "MASK32" {
    const testing = std.testing;

    try testing.expectEqual(math.maxInt(u32), mask_32);
}

test "MASK64" {
    const testing = std.testing;

    try testing.expectEqual(math.maxInt(u64), mask_64);
}

test "Camellia-128 constants" {
    const testing = std.testing;

    try testing.expectEqual(16, Camellia128.key_size);
    try testing.expectEqual(16, Camellia128.block_size);
    try testing.expectEqual(18, Camellia128.rounds);
}

test "Camellia-192 constants" {
    const testing = std.testing;

    try testing.expectEqual(24, Camellia192.key_size);
    try testing.expectEqual(16, Camellia192.block_size);
    try testing.expectEqual(24, Camellia192.rounds);
}

test "Camellia-256 constants" {
    const testing = std.testing;

    try testing.expectEqual(32, Camellia256.key_size);
    try testing.expectEqual(16, Camellia256.block_size);
    try testing.expectEqual(24, Camellia256.rounds);
}

test "Camellia-128 test vector from RFC 3713" {
    const testing = std.testing;

    // Test vector from RFC 3713, Appendix A.
    const key = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    };
    const plaintext = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    };
    const ciphertext = [16]u8{
        0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73, 0x08, 0x57, 0x06, 0x56, 0x48, 0xEA, 0xBE,
        0x43,
    };

    {
        var context = Camellia128.initEncrypt(key);
        var output: [ciphertext.len]u8 = undefined;
        context.encrypt(&output, &plaintext);
        try testing.expectEqualSlices(u8, &ciphertext, &output);
    }

    {
        var context = Camellia128.initDecrypt(key);
        var output: [plaintext.len]u8 = undefined;
        context.decrypt(&output, &ciphertext);
        try testing.expectEqualSlices(u8, &plaintext, &output);
    }
}

test "Camellia-192 test vector from RFC 3713" {
    const testing = std.testing;

    // Test vector from RFC 3713, Appendix A.
    const key = [24]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    };
    const plaintext = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    };
    const ciphertext = [16]u8{
        0xB4, 0x99, 0x34, 0x01, 0xB3, 0xE9, 0x96, 0xF8, 0x4E, 0xE5, 0xCE, 0xE7, 0xD7, 0x9B, 0x09,
        0xB9,
    };

    {
        var context = Camellia192.initEncrypt(key);
        var output: [ciphertext.len]u8 = undefined;
        context.encrypt(&output, &plaintext);
        try testing.expectEqualSlices(u8, &ciphertext, &output);
    }

    {
        var context = Camellia192.initDecrypt(key);
        var output: [plaintext.len]u8 = undefined;
        context.decrypt(&output, &ciphertext);
        try testing.expectEqualSlices(u8, &plaintext, &output);
    }
}

test "Camellia-256 test vector from RFC 3713" {
    const testing = std.testing;

    // Test vector from RFC 3713, Appendix A.
    const key = [32]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
        0xEE, 0xFF,
    };
    const plaintext = [16]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    };
    const ciphertext = [16]u8{
        0x9A, 0xCC, 0x23, 0x7D, 0xFF, 0x16, 0xD7, 0x6C, 0x20, 0xEF, 0x7C, 0x91, 0x9E, 0x3A, 0x75,
        0x09,
    };

    {
        var context = Camellia256.initEncrypt(key);
        var output: [ciphertext.len]u8 = undefined;
        context.encrypt(&output, &plaintext);
        try testing.expectEqualSlices(u8, &ciphertext, &output);
    }

    {
        var context = Camellia256.initDecrypt(key);
        var output: [plaintext.len]u8 = undefined;
        context.decrypt(&output, &ciphertext);
        try testing.expectEqualSlices(u8, &plaintext, &output);
    }
}
