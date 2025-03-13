// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

const std = @import("std");

const testing = std.testing;

const Camellia128 = @import("../camellia.zig").Camellia128;

test "Camellia-128 test vector from NTT" {
    const TestVectors = struct {
        test_vectors: [10]TestVector,
        const TestVector = struct {
            key: [16]u8,
            test_cases: [128]TestCase,
            const TestCase = struct {
                plaintext: [16]u8,
                ciphertext: [16]u8,
            };
        };
    };

    const test_vectors: TestVectors = @import("data/camellia_128.zon");

    for (test_vectors.test_vectors) |test_vector| {
        for (test_vector.test_cases) |test_case| {
            {
                var context = Camellia128.initEncrypt(test_vector.key);
                var output: [16]u8 = undefined;
                context.encrypt(&output, &test_case.plaintext);
                try testing.expectEqualSlices(u8, &test_case.ciphertext, &output);
            }

            {
                var context = Camellia128.initDecrypt(test_vector.key);
                var output: [16]u8 = undefined;
                context.decrypt(&output, &test_case.ciphertext);
                try testing.expectEqualSlices(u8, &test_case.plaintext, &output);
            }
        }
    }
}
