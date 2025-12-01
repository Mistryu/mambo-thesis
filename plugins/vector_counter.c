// Counts how many vector instructions are executed at runtime

#include <stdio.h>

#include "plugins.h"

static inline bool rvv_is_vector_word(uint32_t insn) {
    uint32_t opcode = insn & 0x7F;
    uint32_t funct3 = (insn >> 12) & 0x7;

    switch (opcode) {
    case 0x57:
        return true;

    case 0x07:
    case 0x27:
        switch (funct3) {
        // get all vector encodings under LOAD-FP/STORE-FP opcodes
        case 0b000:
        case 0b101:
        case 0b110:
        case 0b111:
            return true;
        default:
            return false;
        }

    default:
        return false;
    }
}

bool mambo_is_vector(mambo_context *ctx) {
    uint32_t insn = *(uint32_t *)ctx->code.read_address;
    return rvv_is_vector_word(insn);
}

static uint64_t vector_inst_count = 0;

static int vector_pre_inst_cb(mambo_context *ctx) {
    if (!mambo_is_vector(ctx))
        return 0;
    emit_counter64_incr(ctx, &vector_inst_count, 1);
    return 0;
}

__attribute__((constructor)) static void vector_counter_init(void) {
    mambo_context *ctx = mambo_register_plugin();
    mambo_register_pre_inst_cb(ctx, &vector_pre_inst_cb);
}

// Prints count at exit
__attribute__((destructor)) static void vector_counter_fini(void) {
    fprintf(stderr, "[vector_counter] total vector instructions executed: %" PRIu64 "\n",
            vector_inst_count);
}
