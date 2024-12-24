// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

test "Camellia-128 test vector from NTT" {
    const std = @import("std");

    const camellia = @import("../camellia.zig");

    const testing = std.testing;

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

    const json = @embedFile("data/camellia_128.json");

    const parsed = try std.json.parseFromSlice(TestVectors, testing.allocator, json, .{});
    defer parsed.deinit();

    for (parsed.value.test_vectors) |test_vector| {
        for (test_vector.test_cases) |test_case| {
            {
                var context = camellia.Camellia128.initEncrypt(test_vector.key);
                var output: [16]u8 = undefined;
                context.encrypt(&output, &test_case.plaintext);
                try testing.expectEqualSlices(u8, &test_case.ciphertext, &output);
            }

            {
                var context = camellia.Camellia128.initDecrypt(test_vector.key);
                var output: [16]u8 = undefined;
                context.decrypt(&output, &test_case.ciphertext);
                try testing.expectEqualSlices(u8, &test_case.plaintext, &output);
            }
        }
    }
}
