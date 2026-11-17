/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Sort determinism: shuffling functions, blocks, successor pairs, commutative
 * operands and records (fixed-seed LCG) must give a byte-identical bundle. */
#include "pw_xray_bundle.h"
#include "pw_xray_demo.h"
#include "pw_test.h"

#include <stdlib.h>
#include <string.h>

static uint64_t rng = 0x9E3779B97F4A7C15ull;
static uint32_t next_u32(void) {
    rng = rng * 6364136223846793005ull + 1442695040888963407ull;
    return (uint32_t)(rng >> 33);
}

#define SHUFFLE(arr, n, T) do { for (size_t i_ = (n); i_ > 1; --i_) { \
    size_t j_ = next_u32() % i_; T t_ = (arr)[i_ - 1]; (arr)[i_ - 1] = (arr)[j_]; (arr)[j_] = t_; } } while (0)

static int is_comm(uint16_t o) {
    return o == PW_OP_ADD || o == PW_OP_MUL || o == PW_OP_XOR || o == PW_OP_AND || o == PW_OP_OR;
}

int main(void) {
    static const uint8_t binary[] = "synthetic binary bytes";
    static const uint8_t alloy[] = "module demo\n";
    pw_demo_t base;
    CHECK(pw_demo_build(&base, binary, sizeof binary - 1, alloy, sizeof alloy - 1) == PW_OK);
    uint8_t *ref = NULL;
    size_t ref_len = 0;
    CHECK(pw_bundle_write(&base.input, &ref, &ref_len) == PW_OK);
    CHECK(pw_bundle_verify(ref, ref_len, binary, sizeof binary - 1, NULL) == PW_OK);

    const int trials = 500;
    int identical = 0;
    for (int t = 0; t < trials; ++t) {
        pw_demo_t d;
        CHECK(pw_demo_build(&d, binary, sizeof binary - 1, alloy, sizeof alloy - 1) == PW_OK);
        for (uint32_t f = 0; f < PW_DEMO_FUNCS; ++f) {
            SHUFFLE(d.blocks[f], d.funcs[f].block_count, pw_ir_block_t);
            for (uint32_t k = 0; k < d.funcs[f].block_count; ++k) {
                pw_ir_block_t *b = &d.blocks[f][k];
                if (b->succ_count == 2 && (next_u32() & 1u)) {
                    uint32_t s = b->succ_blocks[0];
                    b->succ_blocks[0] = b->succ_blocks[1];
                    b->succ_blocks[1] = s;
                }
            }
            for (uint32_t k = 0; k < d.funcs[f].inst_count; ++k) {
                pw_ir_inst_t *in = &d.insts[f][k];
                if (is_comm(in->opcode) && (next_u32() & 1u)) {
                    pw_operand_t s = in->src[0];
                    in->src[0] = in->src[1];
                    in->src[1] = s;
                }
            }
        }
        SHUFFLE(d.funcs, PW_DEMO_FUNCS, pw_func_input_t);
        SHUFFLE(d.records, PW_DEMO_RECORDS, pw_evidence_record_t);
        d.input.funcs = d.funcs;
        d.input.records = d.records;
        uint8_t *out = NULL;
        size_t out_len = 0;
        if (pw_bundle_write(&d.input, &out, &out_len) == PW_OK && out_len == ref_len &&
            memcmp(out, ref, ref_len) == 0) ++identical;
        free(out);
    }
    printf("test_sort: %d/%d shuffled inputs produced the identical %zu-byte bundle\n",
           identical, trials, ref_len);
    CHECK(identical == trials);

    /* Record order key: (site_va, rule_id, verdict, unknown_reason). */
    pw_evidence_record_t r[4];
    memset(r, 0, sizeof r);
    r[0].site_va = 2; r[1].site_va = 1; r[1].rule_id = 9;
    r[2].site_va = 1; r[2].rule_id = 3; r[2].verdict = 3;
    r[3].site_va = 1; r[3].rule_id = 3; r[3].verdict = 1;
    pw_sort_records(r, 4);
    CHECK(r[0].site_va == 1 && r[0].rule_id == 3 && r[0].verdict == 1);
    CHECK(r[1].verdict == 3);
    CHECK(r[2].rule_id == 9);
    CHECK(r[3].site_va == 2);

    free(ref);
    return TEST_DONE("test_sort");
}
