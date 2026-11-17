/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* SHA-256 known-answer tests (FIPS 180-2 / NIST CSRC example vectors) and
 * streaming equivalence. */
#include "pw_sha256.h"
#include "pw_test.h"

#include <stdlib.h>
#include <string.h>

static int hex_is(const uint8_t d[32], const char *want) {
    char hx[65];
    pw_hex32(d, hx);
    return strcmp(hx, want) == 0;
}

int main(void) {
    uint8_t d[32];
    static const struct { const char *msg; const char *hex; } v[] = {
        { "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
          "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
          "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1" },
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; ++i) {
        pw_sha256(v[i].msg, strlen(v[i].msg), d);
        CHECK(hex_is(d, v[i].hex));
    }

    /* One million 'a' (FIPS 180-2 long message), fed in odd-sized chunks. */
    {
        pw_sha256_ctx c;
        uint8_t chunk[997];
        memset(chunk, 'a', sizeof chunk);
        pw_sha256_init(&c);
        size_t left = 1000000;
        while (left) {
            size_t n = left < sizeof chunk ? left : sizeof chunk;
            pw_sha256_update(&c, chunk, n);
            left -= n;
        }
        pw_sha256_final(&c, d);
        CHECK(hex_is(d, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
    }

    /* Streaming == one-shot for every length 0..300 and every split point
     * at multiples of 7 (covers the 55/56/63/64-byte padding edges). */
    {
        uint8_t msg[300], a[32], b[32];
        for (size_t i = 0; i < sizeof msg; ++i) msg[i] = (uint8_t)(i * 31u + 7u);
        int mismatches = 0;
        for (size_t len = 0; len <= sizeof msg; ++len) {
            pw_sha256(msg, len, a);
            for (size_t split = 0; split <= len; split += 7) {
                pw_sha256_ctx c;
                pw_sha256_init(&c);
                pw_sha256_update(&c, msg, split);
                pw_sha256_update(&c, msg + split, len - split);
                pw_sha256_final(&c, b);
                if (memcmp(a, b, 32) != 0) ++mismatches;
            }
        }
        CHECK(mismatches == 0);
    }
    return TEST_DONE("test_sha256");
}
