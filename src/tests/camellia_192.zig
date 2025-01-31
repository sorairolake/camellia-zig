// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

const std = @import("std");

const json = std.json;
const testing = std.testing;

const Camellia192 = @import("../camellia.zig").Camellia192;

test "Camellia-192 test vector from NTT" {
    const TestVectors = struct {
        test_vectors: [10]TestVector,
        const TestVector = struct {
            key: [24]u8,
            test_cases: [128]TestCase,
            const TestCase = struct {
                plaintext: [16]u8,
                ciphertext: [16]u8,
            };
        };
    };

    const data = @embedFile("data/camellia_192.json");

    const parsed = try json.parseFromSlice(TestVectors, testing.allocator, data, .{});
    defer parsed.deinit();

    for (parsed.value.test_vectors) |test_vector| {
        for (test_vector.test_cases) |test_case| {
            {
                var context = Camellia192.initEncrypt(test_vector.key);
                var output: [16]u8 = undefined;
                context.encrypt(&output, &test_case.plaintext);
                try testing.expectEqualSlices(u8, &test_case.ciphertext, &output);
            }

            {
                var context = Camellia192.initDecrypt(test_vector.key);
                var output: [16]u8 = undefined;
                context.decrypt(&output, &test_case.ciphertext);
                try testing.expectEqualSlices(u8, &test_case.plaintext, &output);
            }
        }
    }
}
