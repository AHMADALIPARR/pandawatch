#ifndef PW_XRAY_IR_H
#define PW_XRAY_IR_H

#include <stdint.h>
#include <stddef.h>

#define PW_IR_MAGIC   0x50574952U /* "PWIR" */
#define PW_IR_VERSION 0x00010000U /* v1.0 */

typedef enum {
    PW_ARCH_UNKNOWN = 0,
    PW_ARCH_X86_64  = 1,
    PW_ARCH_AARCH64 = 2
} pw_arch_t;

typedef enum {
    PW_TY_VOID = 0,
    PW_TY_I1   = 1,
    PW_TY_I8   = 2,
    PW_TY_I16  = 3,
    PW_TY_I32  = 4,
    PW_TY_I64  = 5,
    PW_TY_V128 = 6,
    PW_TY_PTR  = 7
} pw_type_t;

typedef enum {
    PW_OP_NOP        = 0x00,
    PW_OP_CONST      = 0x01,
    PW_OP_ADD        = 0x02, /* Commutative */
    PW_OP_SUB        = 0x03,
    PW_OP_MUL        = 0x04, /* Commutative */
    PW_OP_XOR        = 0x05, /* Commutative */
    PW_OP_AND        = 0x06, /* Commutative */
    PW_OP_OR         = 0x07, /* Commutative */
    PW_OP_SHL        = 0x08,
    PW_OP_SHR        = 0x09,
    PW_OP_ROTL       = 0x0A,
    PW_OP_ROTR       = 0x0B,
    PW_OP_LOAD       = 0x10,
    PW_OP_STORE      = 0x11,
    PW_OP_ALLOCA     = 0x12, /* Stack frame slot with explicit byte size */
    PW_OP_CMP_EQ     = 0x20,
    PW_OP_CMP_LT     = 0x21,
    PW_OP_BR         = 0x30,
    PW_OP_BR_COND    = 0x31,
    PW_OP_CALL_DIR   = 0x32,
    PW_OP_CALL_IND   = 0x33, /* Triggers UNKNOWN tracking if target unresolved */
    PW_OP_RET        = 0x34,
    PW_OP_PHI        = 0x40
} pw_opcode_t;

typedef enum {
    PW_OPERAND_NONE  = 0,
    PW_OPERAND_SSA   = 1,
    PW_OPERAND_IMM   = 2,
    PW_OPERAND_BLOCK = 3,
    PW_OPERAND_FUNC  = 4
} pw_operand_kind_t;

/* 16 bytes, zero implicit padding */
typedef struct {
    uint8_t  kind;      /* pw_operand_kind_t */
    uint8_t  type;      /* pw_type_t */
    uint16_t _pad0;     /* Must be 0 */
    uint32_t ref_id;    /* SSA value ID, Block ID, or Function ID */
    uint64_t imm_val;   /* Immediate literal (0 if ref_id used) */
} pw_operand_t;
_Static_assert(sizeof(pw_operand_t) == 16, "pw_operand_t must be 16 bytes");

/* 64 bytes, zero implicit padding */
typedef struct {
    uint32_t     ssa_id;     /* Monotonic dense ID within function */
    uint16_t     opcode;     /* pw_opcode_t */
    uint8_t      out_type;   /* pw_type_t */
    uint8_t      flags;      /* Bit 0: is_crypto_const, Bit 1: is_abi_boundary */
    uint64_t     source_va;  /* Original instruction virtual address */
    pw_operand_t src[3];     /* Up to 3 canonicalized operands (48 bytes) */
} pw_ir_inst_t;
_Static_assert(sizeof(pw_ir_inst_t) == 64, "pw_ir_inst_t must be 64 bytes");

/* 32 bytes, zero implicit padding */
typedef struct {
    uint32_t block_id;
    uint32_t first_inst;     /* Index into function's inst array */
    uint32_t inst_count;
    uint32_t succ_count;     /* 0, 1, or 2 */
    uint32_t succ_blocks[2]; /* Sorted ascending for canonical CFG edges */
    uint64_t start_va;
} pw_ir_block_t;
_Static_assert(sizeof(pw_ir_block_t) == 32, "pw_ir_block_t must be 32 bytes");

/* 64 bytes, zero implicit padding */
typedef struct {
    uint32_t func_id;
    uint32_t block_count;
    uint32_t inst_count;
    uint32_t stack_frame_bytes;
    uint64_t entry_va;
    uint8_t  ir_sha256[32];  /* Canonical SHA-256 of normalized blocks + insts */
    uint64_t _reserved;      /* Must be 0 */
} pw_ir_func_hdr_t;
_Static_assert(sizeof(pw_ir_func_hdr_t) == 64, "pw_ir_func_hdr_t must be 64 bytes");

#endif /* PW_XRAY_IR_H */

