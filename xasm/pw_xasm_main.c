/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* pw-xasm: x86-64 subset assembler/disassembler (decoder in GNU assembler),
 * .pwxray struct parser (FORTRAN 77), and blob-to-bundle lifter. C23. */
#include "pw_fortran.h"
#include "pw_x86.h"
#include "pw_io.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

constexpr uint64_t DEFAULT_BASE = 0x401000;

static const char *const kind_names[] = {
    "", "pw_operand_t", "pw_ir_inst_t", "pw_ir_block_t", "pw_ir_func_hdr_t",
    "pw_evidence_record_t", "pw_evidence_manifest_t"
};

static int usage(void) {
    fputs("usage:\n"
          "  pw-xasm asm <in.s> -o <out.bin> [--base ADDR]\n"
          "  pw-xasm disasm <in.bin> [--base ADDR] [--listing]\n"
          "  pw-xasm lift <in.bin> -o <out.pwxray> [--base ADDR] [--alloy model.als]\n"
          "  pw-xasm structs <bundle.pwxray> [--ir]\n"
          "  pw-xasm layout\n", stderr);
    return 2;
}

typedef struct {
    const char *in;
    const char *out;
    const char *alloy;
    uint64_t    base;
    bool        listing;
    bool        ir;
} args_t;

[[nodiscard]] static bool parse_args(int argc, char **argv, args_t *a) {
    *a = (args_t){ .base = DEFAULT_BASE };
    for (int i = 2; i < argc; i++) {
        const char *s = argv[i];
        if (strcmp(s, "-o") == 0 && i + 1 < argc) a->out = argv[++i];
        else if (strcmp(s, "--alloy") == 0 && i + 1 < argc) a->alloy = argv[++i];
        else if (strcmp(s, "--base") == 0 && i + 1 < argc) {
            char *end = nullptr;
            a->base = strtoull(argv[++i], &end, 0);
            if (end == nullptr || *end != '\0') return false;
        } else if (strcmp(s, "--listing") == 0) a->listing = true;
        else if (strcmp(s, "--ir") == 0) a->ir = true;
        else if (s[0] == '-') return false;
        else if (a->in == nullptr) a->in = s;
        else return false;
    }
    return true;
}

static int cmd_asm(const args_t *a) {
    if (a->in == nullptr || a->out == nullptr) return usage();
    uint8_t *src = nullptr;
    size_t n = 0;
    if (pw_read_file(a->in, &src, &n) != 0) { perror(a->in); return 1; }
    char *text = malloc(n + 1);
    if (text == nullptr) { free(src); return 1; }
    memcpy(text, src, n);
    text[n] = '\0';
    free(src);
    uint8_t *code = nullptr;
    size_t len = 0;
    char err[256];
    const int rc = pw_x86_assemble(text, a->base, &code, &len, err, sizeof err);
    free(text);
    if (rc != 0) { fprintf(stderr, "%s: %s\n", a->in, err); return 1; }
    const int wr = pw_write_file(a->out, code, len);
    free(code);
    if (wr != 0) { perror(a->out); return 1; }
    printf("%zu bytes\n", len);
    return 0;
}

static int cmd_disasm(const args_t *a) {
    if (a->in == nullptr) return usage();
    uint8_t *code = nullptr;
    size_t len = 0;
    if (pw_read_file(a->in, &code, &len) != 0) { perror(a->in); return 1; }
    int rc = 0;
    for (size_t off = 0; off < len;) {
        pw_x86_insn_t in;
        const size_t l = pw_x86_decode(code + off, len - off, &in);
        char text[128];
        if (l == 0 || pw_x86_format(&in, a->base + off, text, sizeof text) < 0) {
            fprintf(stderr, "%s: undecodable byte 0x%02x at offset 0x%zx\n", a->in, code[off], off);
            rc = 1;
            break;
        }
        if (a->listing) {
            printf("%zx %s\n", off, pw_x86_mnemonic_name(&in));
        } else {
            printf("    %-40s ; %08" PRIx64 ":", text, a->base + off);
            for (size_t k = 0; k < l; k++) printf(" %02x", code[off + k]);
            putchar('\n');
        }
        off += l;
    }
    free(code);
    return rc;
}

static int cmd_lift(const args_t *a) {
    if (a->in == nullptr || a->out == nullptr) return usage();
    uint8_t *blob = nullptr, *alloy = nullptr, *bundle = nullptr;
    size_t blob_len = 0, alloy_len = 0, bundle_len = 0;
    if (pw_read_file(a->in, &blob, &blob_len) != 0) { perror(a->in); return 1; }
    if (a->alloy && pw_read_file(a->alloy, &alloy, &alloy_len) != 0) {
        perror(a->alloy);
        free(blob);
        return 1;
    }
    uint32_t ni = 0, nb = 0;
    const pw_status_t st = pw_x86_lift_bundle(blob, blob_len, a->base, alloy, alloy_len,
                                              &bundle, &bundle_len, &ni, &nb);
    int rc = 0;
    if (st != PW_OK) {
        fprintf(stderr, "lift failed: %s\n", pw_status_str(st));
        rc = 1;
    } else if (pw_write_file(a->out, bundle, bundle_len) != 0) {
        perror(a->out);
        rc = 1;
    } else {
        printf("%u instructions, %u blocks, %zu bytes\n", ni, nb, bundle_len);
    }
    free(blob);
    free(alloy);
    free(bundle);
    return rc;
}

static void field_name(int32_t kind, int32_t i, char out[21]) {
    pwfnam_(&kind, &i, out, 20);
    out[20] = '\0';
    for (int k = 19; k >= 0 && out[k] == ' '; k--) out[k] = '\0';
}

/* Prints one struct decoded by the Fortran parser. */
static int dump_struct(int32_t kind, const uint8_t *b, size_t avail, size_t file_off,
                       const char *indent) {
    int32_t nf = 0, ksiz = 0, ipad = 0, ierr = 0;
    const int32_t zero = 0;
    pwlayt_(&kind, &zero, &nf, &ksiz, &ipad, &ierr);
    if (ierr != 0 || avail < (size_t)ksiz) {
        printf("%s%s at 0x%zx: truncated\n", indent, kind_names[kind], file_off);
        return 1;
    }
    int64_t vals[PWF_MAX_VALS];
    int32_t nv = 0, ibad = 0;
    pwdec_(&kind, b, &ksiz, vals, &nv, &ierr);
    pwval_(&kind, b, &ksiz, &ibad, &ierr);
    printf("%s%s at 0x%zx (%d bytes)\n", indent, kind_names[kind], file_off, ksiz);
    int32_t v = 0;
    for (int32_t i = 1; i <= nf; i++) {
        int32_t ioff = 0, isiz = 0;
        pwlayt_(&kind, &i, &ioff, &isiz, &ipad, &ierr);
        char name[21];
        field_name(kind, i, name);
        printf("%s  +%-3d %-20s ", indent, ioff, name);
        if (isiz == 32) {
            for (int lane = 0; lane < 4; lane++) {
                const uint64_t u = (uint64_t)vals[v++];
                for (int k = 0; k < 8; k++) printf("%02x", (unsigned)(u >> (8 * k)) & 0xFF);
            }
            putchar('\n');
        } else {
            printf("0x%" PRIx64 "\n", (uint64_t)vals[v++]);
        }
    }
    if (ibad != 0) {
        char name[21];
        field_name(kind, ibad, name);
        printf("%s  padding field '%s' is not zero\n", indent, name);
        return 1;
    }
    return 0;
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int cmd_structs(const args_t *a) {
    if (a->in == nullptr) return usage();
    uint8_t *b = nullptr;
    size_t len = 0;
    if (pw_read_file(a->in, &b, &len) != 0) { perror(a->in); return 1; }
    int bad = 0;
    if (len > INT32_MAX) { fputs("file too large\n", stderr); free(b); return 1; }
    const int32_t n32 = (int32_t)len;
    printf("file %s: %zu bytes, adler32 0x%08" PRIx64 "\n", a->in, len, (uint64_t)pwadl_(b, &n32));
    bad |= dump_struct(PWF_MANIFEST, b, len, 0, "");
    if (len < PW_MANIFEST_BYTES) { free(b); return 1; }
    const uint32_t nrec = le32(b + 12);
    size_t off = PW_MANIFEST_BYTES;
    if ((len - off) / PW_RECORD_BYTES < nrec) {
        puts("records: truncated");
        free(b);
        return 1;
    }
    for (uint32_t r = 0; r < nrec; r++, off += PW_RECORD_BYTES)
        bad |= dump_struct(PWF_RECORD, b + off, len - off, off, "");
    if (nrec) {
        int32_t istat[11];
        double dstat[9];
        const int32_t nr = (int32_t)nrec;
        pwrst_(b + PW_MANIFEST_BYTES, &nr, istat, dstat);
        printf("record statistics (Fortran PWRST)\n");
        printf("  verdicts: compliant %d, vulnerable %d, unknown %d, invalid %d\n",
               istat[0], istat[1], istat[2], istat[9]);
        printf("  unknown_reason 1..5: %d %d %d %d %d\n", istat[3], istat[4], istat[5], istat[6], istat[7]);
        printf("  records with nonzero padding: %d\n", istat[10]);
        printf("  detected_bytes: mean %.6g variance %.6g min %.6g max %.6g\n",
               dstat[0], dstat[1], dstat[2], dstat[3]);
        printf("  required_bytes: mean %.6g variance %.6g min %.6g max %.6g\n",
               dstat[4], dstat[5], dstat[6], dstat[7]);
        printf("  shortfall: %d records, %.6g bytes total\n", istat[8], dstat[8]);
    }
    if (len - off < PW_IR_CORPUS_HDR_BYTES) { puts("ir corpus: truncated"); free(b); return 1; }
    const uint32_t nfunc = le32(b + off + 8);
    printf("ir corpus at 0x%zx: magic 0x%08x version 0x%08x functions %u\n", off, le32(b + off),
           le32(b + off + 4), nfunc);
    off += PW_IR_CORPUS_HDR_BYTES;
    for (uint32_t f = 0; f < nfunc; f++) {
        if (len - off < PW_FUNC_HDR_BYTES) { puts("function header: truncated"); bad = 1; break; }
        const uint32_t nb = le32(b + off + 4), ni = le32(b + off + 8);
        bad |= dump_struct(PWF_FUNC_HDR, b + off, len - off, off, "");
        off += PW_FUNC_HDR_BYTES;
        const uint64_t need = (uint64_t)nb * PW_BLOCK_BYTES + (uint64_t)ni * PW_INST_BYTES;
        if (need > len - off) { puts("function body: truncated"); bad = 1; break; }
        for (uint32_t k = 0; k < nb; k++, off += PW_BLOCK_BYTES) {
            int32_t ibad = 0, ierr = 0;
            const int32_t kind = PWF_BLOCK, sz = PW_BLOCK_BYTES;
            if (a->ir) bad |= dump_struct(PWF_BLOCK, b + off, len - off, off, "  ");
            else { pwval_(&kind, b + off, &sz, &ibad, &ierr); bad |= ibad != 0; }
        }
        for (uint32_t k = 0; k < ni; k++, off += PW_INST_BYTES) {
            int32_t ibad = 0, ierr = 0;
            const int32_t kind = PWF_INST, sz = PW_INST_BYTES;
            if (a->ir) bad |= dump_struct(PWF_INST, b + off, len - off, off, "  ");
            else { pwval_(&kind, b + off, &sz, &ibad, &ierr); bad |= ibad != 0; }
        }
        printf("  %u blocks, %u instructions\n", nb, ni);
    }
    printf("alloy model at 0x%zx: %zu bytes\n", off, len - off);
    printf("padding: %s\n", bad ? "NONZERO" : "all zero");
    free(b);
    return bad ? 1 : 0;
}

static int cmd_layout(void) {
    for (int32_t kind = 1; kind <= 6; kind++) {
        int32_t nf = 0, ksiz = 0, ipad = 0, ierr = 0;
        const int32_t zero = 0;
        pwlayt_(&kind, &zero, &nf, &ksiz, &ipad, &ierr);
        printf("%s %d bytes, %d fields\n", kind_names[kind], ksiz, nf);
        for (int32_t i = 1; i <= nf; i++) {
            int32_t ioff = 0, isiz = 0;
            pwlayt_(&kind, &i, &ioff, &isiz, &ipad, &ierr);
            char name[21];
            field_name(kind, i, name);
            printf("  %3d %2d %-20s%s\n", ioff, isiz, name, ipad ? " pad" : "");
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return usage();
    const char *cmd = argv[1];
    if (strcmp(cmd, "layout") == 0) return argc == 2 ? cmd_layout() : usage();
    args_t a;
    if (!parse_args(argc, argv, &a)) return usage();
    if (strcmp(cmd, "asm") == 0) return cmd_asm(&a);
    if (strcmp(cmd, "disasm") == 0) return cmd_disasm(&a);
    if (strcmp(cmd, "lift") == 0) return cmd_lift(&a);
    if (strcmp(cmd, "structs") == 0) return cmd_structs(&a);
    return usage();
}
