// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

const std = @import("std");

const testing = std.testing;

const Camellia256 = @import("../camellia.zig").Camellia256;

test "Camellia-256 test vector from NTT" {
    const TestVectors = struct {
        test_vectors: [10]TestVector,
        const TestVector = struct {
            key: [32]u8,
            test_cases: [128]TestCase,
            const TestCase = struct {
                plaintext: [16]u8,
                ciphertext: [16]u8,
            };
        };
    };

    const test_vectors: TestVectors = @import("data/camellia_256.zon");

    for (test_vectors.test_vectors) |test_vector| {
        for (test_vector.test_cases) |test_case| {
            {
                var context = Camellia256.initEncrypt(test_vector.key);
                var output: [16]u8 = undefined;
                context.encrypt(&output, &test_case.plaintext);
                try testing.expectEqualSlices(u8, &test_case.ciphertext, &output);
            }

            {
                var context = Camellia256.initDecrypt(test_vector.key);
                var output: [16]u8 = undefined;
                context.decrypt(&output, &test_case.ciphertext);
                try testing.expectEqualSlices(u8, &test_case.plaintext, &output);
            }
        }
    }
}
