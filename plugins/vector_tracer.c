// Counts how many vector instructions are executed at runtime
// Tracks register-register RVV instructions and stores register information to JSON

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "../plugins.h"




/* 

General helper functions

*/

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

// I cache vlanb value
static uint32_t cached_vlenb = 256;
static uint64_t vector_inst_count = 0;
static uint64_t reg_reg_count = 0;

/*

Reading registers

*/

// Function to read register values during runtime
// For vector registers: uses cached vlenb and stores register using vse8.v
// For GP registers: reads register value directly
static void read_register_value(uint8_t reg_num, bool is_vector, void *buffer) {
    if (is_vector) {
        // Use uintptr_t for address to avoid type mismatch as "r" needs integer not pointer
        uintptr_t addr = (uintptr_t)buffer;
        
        // Store vector register to buffer using vse8.v (RISC-V Vector Extension spec-compliant)
        // vse8.v vd, (rs1) - stores entire vector register vd as bytes to address in rs1
        // Stores VLEN bytes (entire register contents regardless of element width)
        // We can't use "vse8.v v%0, (%1)" with operand substitution because GCC doesn't support it
        // it replaces %0 with a0 and we get va0 aka not a valid register
        // Reference: https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html
        // https://github.com/riscvarchive/riscv-v-spec/releases/tag/v1.0


        //TODO:
        // Another issue is that vse8 only stores VL bytes not VLEN bytes. 
        // I need to have VL set to VL>= vlanb otherwise not all bytes are stored
        switch (reg_num) {
            case 0:  asm volatile("vse8.v v0, (%0)" : : "r"(addr) : "memory"); break;
            case 1:  asm volatile("vse8.v v1, (%0)" : : "r"(addr) : "memory"); break;
            case 2:  asm volatile("vse8.v v2, (%0)" : : "r"(addr) : "memory"); break;
            case 3:  asm volatile("vse8.v v3, (%0)" : : "r"(addr) : "memory"); break;
            case 4:  asm volatile("vse8.v v4, (%0)" : : "r"(addr) : "memory"); break;
            case 5:  asm volatile("vse8.v v5, (%0)" : : "r"(addr) : "memory"); break;
            case 6:  asm volatile("vse8.v v6, (%0)" : : "r"(addr) : "memory"); break;
            case 7:  asm volatile("vse8.v v7, (%0)" : : "r"(addr) : "memory"); break;
            case 8:  asm volatile("vse8.v v8, (%0)" : : "r"(addr) : "memory"); break;
            case 9:  asm volatile("vse8.v v9, (%0)" : : "r"(addr) : "memory"); break;
            case 10: asm volatile("vse8.v v10, (%0)" : : "r"(addr) : "memory"); break;
            case 11: asm volatile("vse8.v v11, (%0)" : : "r"(addr) : "memory"); break;
            case 12: asm volatile("vse8.v v12, (%0)" : : "r"(addr) : "memory"); break;
            case 13: asm volatile("vse8.v v13, (%0)" : : "r"(addr) : "memory"); break;
            case 14: asm volatile("vse8.v v14, (%0)" : : "r"(addr) : "memory"); break;
            case 15: asm volatile("vse8.v v15, (%0)" : : "r"(addr) : "memory"); break;
            case 16: asm volatile("vse8.v v16, (%0)" : : "r"(addr) : "memory"); break;
            case 17: asm volatile("vse8.v v17, (%0)" : : "r"(addr) : "memory"); break;
            case 18: asm volatile("vse8.v v18, (%0)" : : "r"(addr) : "memory"); break;
            case 19: asm volatile("vse8.v v19, (%0)" : : "r"(addr) : "memory"); break;
            case 20: asm volatile("vse8.v v20, (%0)" : : "r"(addr) : "memory"); break;
            case 21: asm volatile("vse8.v v21, (%0)" : : "r"(addr) : "memory"); break;
            case 22: asm volatile("vse8.v v22, (%0)" : : "r"(addr) : "memory"); break;
            case 23: asm volatile("vse8.v v23, (%0)" : : "r"(addr) : "memory"); break;
            case 24: asm volatile("vse8.v v24, (%0)" : : "r"(addr) : "memory"); break;
            case 25: asm volatile("vse8.v v25, (%0)" : : "r"(addr) : "memory"); break;
            case 26: asm volatile("vse8.v v26, (%0)" : : "r"(addr) : "memory"); break;
            case 27: asm volatile("vse8.v v27, (%0)" : : "r"(addr) : "memory"); break;
            case 28: asm volatile("vse8.v v28, (%0)" : : "r"(addr) : "memory"); break;
            case 29: asm volatile("vse8.v v29, (%0)" : : "r"(addr) : "memory"); break;
            case 30: asm volatile("vse8.v v30, (%0)" : : "r"(addr) : "memory"); break;
            case 31: asm volatile("vse8.v v31, (%0)" : : "r"(addr) : "memory"); break;
            default: break; // Invalid register number
        }
    } else {
        // Read GP register value
        uintptr_t reg_value = 0;
        switch (reg_num) {
            case 0:  asm volatile("mv %0, zero" : "=r"(reg_value)); break;
            case 1:  asm volatile("mv %0, ra" : "=r"(reg_value)); break;
            case 2:  asm volatile("mv %0, sp" : "=r"(reg_value)); break;
            case 3:  asm volatile("mv %0, gp" : "=r"(reg_value)); break;
            case 4:  asm volatile("mv %0, tp" : "=r"(reg_value)); break;
            case 5:  asm volatile("mv %0, t0" : "=r"(reg_value)); break;
            case 6:  asm volatile("mv %0, t1" : "=r"(reg_value)); break;
            case 7:  asm volatile("mv %0, t2" : "=r"(reg_value)); break;
            case 8:  asm volatile("mv %0, s0" : "=r"(reg_value)); break;
            case 9:  asm volatile("mv %0, s1" : "=r"(reg_value)); break;
            case 10: asm volatile("mv %0, a0" : "=r"(reg_value)); break;
            case 11: asm volatile("mv %0, a1" : "=r"(reg_value)); break;
            case 12: asm volatile("mv %0, a2" : "=r"(reg_value)); break;
            case 13: asm volatile("mv %0, a3" : "=r"(reg_value)); break;
            case 14: asm volatile("mv %0, a4" : "=r"(reg_value)); break;
            case 15: asm volatile("mv %0, a5" : "=r"(reg_value)); break;
            case 16: asm volatile("mv %0, a6" : "=r"(reg_value)); break;
            case 17: asm volatile("mv %0, a7" : "=r"(reg_value)); break;
            case 18: asm volatile("mv %0, s2" : "=r"(reg_value)); break;
            case 19: asm volatile("mv %0, s3" : "=r"(reg_value)); break;
            case 20: asm volatile("mv %0, s4" : "=r"(reg_value)); break;
            case 21: asm volatile("mv %0, s5" : "=r"(reg_value)); break;
            case 22: asm volatile("mv %0, s6" : "=r"(reg_value)); break;
            case 23: asm volatile("mv %0, s7" : "=r"(reg_value)); break;
            case 24: asm volatile("mv %0, s8" : "=r"(reg_value)); break;
            case 25: asm volatile("mv %0, s9" : "=r"(reg_value)); break;
            case 26: asm volatile("mv %0, s10" : "=r"(reg_value)); break;
            case 27: asm volatile("mv %0, s11" : "=r"(reg_value)); break;
            case 28: asm volatile("mv %0, t3" : "=r"(reg_value)); break;
            case 29: asm volatile("mv %0, t4" : "=r"(reg_value)); break;
            case 30: asm volatile("mv %0, t5" : "=r"(reg_value)); break;
            case 31: asm volatile("mv %0, t6" : "=r"(reg_value)); break;
        }
        memcpy(buffer, &reg_value, sizeof(uintptr_t));
    }
}

// Batch read multiple vector registers at once
static void read_registers_batch(uint8_t vd, uint8_t vs1, uint8_t vs2, uint8_t v0_flag,
                                  void *vd_buf, void *vs1_buf, void *vs2_buf, void *v0_buf) {
    read_register_value(vd, true, vd_buf);
    read_register_value(vs1, true, vs1_buf);
    read_register_value(vs2, true, vs2_buf);
    if (v0_flag == 0) {
        read_register_value(0, true, v0_buf);
    }
}

// Emit code to read a register value at runtime (single register - used for vd_after)
// We need to emit the instruction directly into the code so they run at runtime not during instrumentation
// Source: docs/tutorials/hipeac2025/exercise4/README.md Per Instruction Callbacks
// Also inside docs/tutorials/hipeac2025/exercise4/solution/solution.c
static void emit_read_register(mambo_context *ctx, uint8_t reg_num, bool is_vector, void *buffer) {
    // emit_safe_fcall does NOT preserve lr docs/tutorials/hipeac2025/exercise4/README.md line 292
    // So we must save it alongside a0, a1, a2
    // Using reg0, reg1, reg2 from enum reg_portable (RISC-V: reg0=10=a0, reg1=11=a1, reg2=12=a2)
    
    //TODO
    // There seems to be an issue with that as clang doesn't seem to see the registers 
    // It should work tho as this is risc-v specific so we need to test it during runtime
    emit_push(ctx, (1 << reg0) | (1 << reg1) | (1 << reg2) | (1 << lr));
    
    emit_set_reg(ctx, reg0, reg_num);
    emit_set_reg(ctx, reg1, is_vector ? 1 : 0);
    emit_set_reg_ptr(ctx, reg2, buffer);
    
    // Generate function call that will execute at runtime
    emit_safe_fcall(ctx, (void *)read_register_value, 3);
    
    // Restore registers    
    emit_pop(ctx, (1 << reg0) | (1 << reg1) | (1 << reg2) | (1 << lr));
}

// Emit code to batch read multiple vector registers at once
// This significantly reduces code emission compared to multiple separate calls
// Arguments: vd, vs1, vs2, uses_mask, vd_buf, vs1_buf, vs2_buf, v0_buf
static void emit_read_registers_batch(mambo_context *ctx, uint8_t vd, uint8_t vs1, uint8_t vs2, 
                                      bool uses_mask, void *vd_buf, void *vs1_buf, 
                                      void *vs2_buf, void *v0_buf) {
    // emit_safe_fcall does NOT preserve lr
    // We need to save: reg0, reg1, reg2, reg3, reg4, reg5, reg6, reg7, lr
    // RISC-V: reg0=a0, reg1=a1, reg2=a2, reg3=a3, reg4=a4, reg5=a5, reg6=a6, reg7=a7
    // But MAX_FCALL_ARGS is 8, so we can use a0-a7 for arguments
    emit_push(ctx, (1 << reg0) | (1 << reg1) | (1 << reg2) | (1 << reg3) | 
                   (1 << reg4) | (1 << reg5) | (1 << reg6) | (1 << reg7) | (1 << lr));
    
    // Seting up arguments for read_registers_batch(vd, vs1, vs2, v0_flag, vd_buf, vs1_buf, vs2_buf, v0_buf)
    // These are the instruction we will exectute at runtime and not during instrumentation
    // Here I set first 8 registers as arguments for read_registers_batch function call
    emit_set_reg(ctx, reg0, vd);
    emit_set_reg(ctx, reg1, vs1);
    emit_set_reg(ctx, reg2, vs2);
    emit_set_reg(ctx, reg3, uses_mask ? 0 : 1);
    emit_set_reg_ptr(ctx, reg4, vd_buf);
    emit_set_reg_ptr(ctx, reg5, vs1_buf);
    emit_set_reg_ptr(ctx, reg6, vs2_buf);
    emit_set_reg_ptr(ctx, reg7, v0_buf);
    
    // Generating function call that will execute at runtime
    emit_safe_fcall(ctx, (void *)read_registers_batch, 8);
    
    // Restore registers
    emit_pop(ctx, (1 << reg0) | (1 << reg1) | (1 << reg2) | (1 << reg3) | 
                  (1 << reg4) | (1 << reg5) | (1 << reg6) | (1 << reg7) | (1 << lr));
}



/* 

Register-register section

*/

// Register-register RVV instructions have opcode 0x57 so I'm using that to check
static inline bool rvv_is_reg_reg(uint32_t insn) {
    uint32_t opcode = insn & 0x7F; 
    return (opcode == 0x57);
}

// Register-register RVV instruction format: aaaaaabc ccccdddd deeeffff f1010111
// vd = bits [11:7] = fffff destination
// vs1 = bits [19:15] = ddddd source 1
// vs2 = bits [24:20] = ccccc source 2
// vm = bit [25] = b mask
// funct3 = bits [14:12] = eee
// funct6 = bits [31:26] = aaaaaa
// opcode = bits [6:0] = 0x57 for now later we should track the load and store as well
static inline void rvv_extract_regs(uint32_t insn, uint8_t *vd, uint8_t *vs1, uint8_t *vs2, uint8_t *vm, uint8_t *funct3, uint8_t *funct6, uint8_t *opcode) {
    *vd = (insn >> 7) & 0x1F;
    *vs1 = (insn >> 15) & 0x1F;
    *vs2 = (insn >> 20) & 0x1F;
    *vm = (insn >> 25) & 0x1;
    *funct3 = (insn >> 12) & 0x7;
    *funct6 = (insn >> 26) & 0x3F;
    *opcode = insn & 0x7F;
}

// Keep this the same
struct rr_entry {
    uintptr_t pc;
    uint32_t insn;
    uint8_t vd;
    uint8_t vs1;
    uint8_t vs2;
    uint8_t vm;
    uint8_t funct3;
    uint8_t funct6;
    uint8_t opcode;
    uint64_t timestamp;

    // Register values: before and after instruction execution
    void *vd_before;
    void *vd_after;
    void *vs1_before;
    void *vs2_before;
    void *v0_before;
    bool uses_mask;
};

// Change this to be a general one later
// Buffer
struct rr_trace {
    struct rr_entry *entries;
    size_t count;
    size_t capacity;
};

// Information about the vector instructions and register-register RVV instructions for JSON

static struct rr_trace trace_data = {NULL, 0, 1024};
static uint64_t timestamp_counter = 0;
static bool first_entry_in_file = true;

// Helper: Convert binary data to hex string
static void buffer_to_hex(const void *buffer, size_t size, char *hex_str) {
    const uint8_t *bytes = (const uint8_t *)buffer;
    for (size_t i = 0; i < size; i++) {
        sprintf(hex_str + (i * 2), "%02x", bytes[i]);
    }
}

// Helper: Write one register value to JSON
static void write_reg_json(FILE *file, const char *name, const void *buffer, char *hex_buf) {
    if (!buffer) return;
    buffer_to_hex(buffer, cached_vlenb, hex_buf);
    fprintf(file, "        \"%s\": \"%s\"", name, hex_buf);
}

static void flush_buffer_to_file(void) {
    FILE *file = fopen("trace.json", "a");
    if (!file) {
        fprintf(stderr, "[vector_tracer] Error: Could not open trace.json\n");
        exit(EXIT_FAILURE);
    }
    
    // Allocate hex buffer (VLA: cached_vlenb * 2 + 1 for hex string)
    char hex_buf[cached_vlenb * 2 + 1];
    
    for (size_t i = 0; i < trace_data.count; i++) {
        struct rr_entry *e = &trace_data.entries[i];
        if (!first_entry_in_file || i > 0) fprintf(file, ",\n");
        
        fprintf(file, "    {\n      \"instr\": {\n");
        fprintf(file, "        \"pc\": \"0x%" PRIxPTR "\",\n", e->pc);
        fprintf(file, "        \"timestamp\": %" PRIu64 ",\n", e->timestamp);
        fprintf(file, "        \"insn\": \"0x%08x\",\n", e->insn);
        fprintf(file, "        \"type\": \"rr\",\n");
        fprintf(file, "        \"vd\": %u,\n", e->vd);
        fprintf(file, "        \"vs1\": %u,\n", e->vs1);
        fprintf(file, "        \"vs2\": %u,\n", e->vs2);
        fprintf(file, "        \"vm\": %u,\n", e->vm);
        fprintf(file, "        \"funct3\": %u,\n", e->funct3);
        fprintf(file, "        \"funct6\": %u,\n", e->funct6);
        fprintf(file, "        \"opcode\": %u\n", e->opcode);
        fprintf(file, "      },\n      \"reg\": {\n");
        
        write_reg_json(file, "vs1", e->vs1_before, hex_buf);
        fprintf(file, ",\n");
        write_reg_json(file, "vs2", e->vs2_before, hex_buf);
        if (e->uses_mask) {
            fprintf(file, ",\n");
            write_reg_json(file, "mask", e->v0_before, hex_buf);
        }
        fprintf(file, ",\n");
        write_reg_json(file, "vd_before", e->vd_before, hex_buf);
        fprintf(file, ",\n");
        write_reg_json(file, "vd_after", e->vd_after, hex_buf);
        fprintf(file, "\n      }\n    }");
    }
    
    if (trace_data.count > 0) first_entry_in_file = false;
    trace_data.count = 0;
    fclose(file);
}

// Helper: Initialize entry structure with instruction fields
// Since we are going to be emiting our own instructions we need to put the 
// rr_entry into the memory so we can access it before and after our instructions are executed
static struct rr_entry *init_rr_entry(mambo_context *ctx, uintptr_t pc, uint32_t insn, 
                                      uint8_t vd, uint8_t vs1, uint8_t vs2, uint8_t vm,
                                      uint8_t funct3, uint8_t funct6, uint8_t opcode) {
    struct rr_entry *entry = mambo_alloc(ctx, sizeof(struct rr_entry));
    if (entry == NULL) return NULL;
    
    entry->pc = pc;
    entry->insn = insn;
    entry->vd = vd;
    entry->vs1 = vs1;
    entry->vs2 = vs2;
    entry->vm = vm;
    entry->funct3 = funct3;
    entry->funct6 = funct6;
    entry->opcode = opcode;
    entry->uses_mask = (vm == 0);
    
    // Allocate buffers for register values 
    // Check if we should free it later or just leave it
    // Not sure how Mambo handles this
    entry->vd_before = mambo_alloc(ctx, cached_vlenb);
    entry->vd_after = mambo_alloc(ctx, cached_vlenb);
    entry->vs1_before = mambo_alloc(ctx, cached_vlenb);
    entry->vs2_before = mambo_alloc(ctx, cached_vlenb);
    entry->v0_before = entry->uses_mask ? mambo_alloc(ctx, cached_vlenb) : NULL;
    
    // Checking for failures
    if (!entry->vd_before || !entry->vd_after || !entry->vs1_before || !entry->vs2_before ||
        (entry->uses_mask && !entry->v0_before)) {
        if (entry->vd_before) mambo_free(ctx, entry->vd_before);
        if (entry->vd_after) mambo_free(ctx, entry->vd_after);
        if (entry->vs1_before) mambo_free(ctx, entry->vs1_before);
        if (entry->vs2_before) mambo_free(ctx, entry->vs2_before);
        if (entry->v0_before) mambo_free(ctx, entry->v0_before);
        mambo_free(ctx, entry);
        return NULL;
    }
    return entry;
}

// Emit code to capture register values before instruction
// Uses batched register read to reduce code emission significantly
static void capture_registers_before(mambo_context *ctx, struct rr_entry *entry) {
    // Batch all register reads into a single function call
    emit_read_registers_batch(ctx, entry->vd, entry->vs1, entry->vs2, entry->uses_mask,
                              entry->vd_before, entry->vs1_before, entry->vs2_before, 
                              entry->v0_before);
}

// Runtime function: Add entry to trace buffer (after instruction executes)
static void add_rr_trace_entry_runtime(struct rr_entry *entry) {
    if (trace_data.count >= trace_data.capacity) {
        flush_buffer_to_file();
    }
    trace_data.entries[trace_data.count] = *entry;
    trace_data.entries[trace_data.count].timestamp = timestamp_counter++;
    trace_data.count++;
}


/*
    Pre and post instruction calls
*/


bool mambo_is_vector(mambo_context *ctx) {
    uint32_t insn = *(uint32_t *)ctx->code.read_address; // Check if this is correct
    return rvv_is_vector_word(insn);
}

// Executes before the instruction is executed
static int vector_pre_inst_cb(mambo_context *ctx) {
    if (!mambo_is_vector(ctx)) return 0;
    emit_counter64_incr(ctx, &vector_inst_count, 1);
    
    uint32_t insn = *(uint32_t *)ctx->code.read_address;
    if (!rvv_is_reg_reg(insn)) return 0;
    
    emit_counter64_incr(ctx, &reg_reg_count, 1);
    
    uint8_t vd, vs1, vs2, vm, funct3, funct6, opcode;
    rvv_extract_regs(insn, &vd, &vs1, &vs2, &vm, &funct3, &funct6, &opcode);
    
    struct rr_entry *entry = init_rr_entry(ctx, (uintptr_t)ctx->code.read_address, insn,
                                            vd, vs1, vs2, vm, funct3, funct6, opcode);
    if (!entry) {
        fprintf(stderr, "[vector_tracer] Error: Could not allocate entry\n");
        return 0;
    }
    
    mambo_set_thread_plugin_data(ctx, entry);
    capture_registers_before(ctx, entry);
    return 0;
}

static int vector_post_inst_cb(mambo_context *ctx) {
    if (!mambo_is_vector(ctx) || !rvv_is_reg_reg(*(uint32_t *)ctx->code.read_address)) {
        return 0;
    }
    
    struct rr_entry *entry = (struct rr_entry *)mambo_get_thread_plugin_data(ctx);
    if (!entry) return 0;
    
    emit_read_register(ctx, entry->vd, true, entry->vd_after);
    emit_push(ctx, (1 << reg0) | (1 << lr));
    emit_set_reg_ptr(ctx, reg0, entry);
    emit_safe_fcall(ctx, (void *)add_rr_trace_entry_runtime, 1);
    emit_pop(ctx, (1 << reg0) | (1 << lr));
    return 0;
}


/*
    Initialization functions
*/

static void init_trace_buffer(void) {
    trace_data.entries = malloc(trace_data.capacity * sizeof(struct rr_entry));
    if (trace_data.entries == NULL) {
        fprintf(stderr, "[vector_tracer] Error: Could not allocate trace buffer\n");
        exit(EXIT_FAILURE);
    }
    trace_data.count = 0;
    timestamp_counter = 0;
}

// Reads vlenb CSR initialization and caches it
// I'm forcefully putting an instruction in the code asm volatile
// "csrr %0, vlenb" -> reads vlenb CSR and stores it in %0 ( first operand )
// : "=r"(cached_vlenb) -> stores the value in cached_vlenb C variable
// Source: https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html
static void init_vlenb(void) {
    asm volatile("csrr %0, vlenb" : "=r"(cached_vlenb));
    if (cached_vlenb == 0) {
        fprintf(stderr, "[vector_tracer] Warning: vlenb is 0, using default 256 bytes\n");
        cached_vlenb = 256; // Maximum size
    }
}


static void init_json_file(void) {
    const char *filename = "trace.json";
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        fprintf(stderr, "[vector_tracer] Error: Could not create %s\n", filename);
        exit(EXIT_FAILURE);
    }
    
    // Initialize JSON array
    fprintf(file, "  [\n");
    
    fclose(file);
    first_entry_in_file = true;
}


// Initialises the plugin
__attribute__((constructor)) static void vector_counter_init(void) {
    mambo_context *ctx = mambo_register_plugin();
    mambo_register_pre_inst_cb(ctx, &vector_pre_inst_cb);
    mambo_register_post_inst_cb(ctx, &vector_post_inst_cb);
    
    init_vlenb();
    init_trace_buffer();
    init_json_file();
}

/*
    Finalization functions
*/

// Writes the remaining entries to the JSON file
static void finalize_json_file(void) {
    const char *filename = "trace.json";
    
    if (trace_data.count > 0) {
        flush_buffer_to_file();
    }
    
    FILE *file = fopen(filename, "a");
    if (file == NULL) {
        fprintf(stderr, "[vector_tracer] Error: Could not open %s for closing\n", filename);
        exit(EXIT_FAILURE);
    }
    fprintf(file, "\n  ]\n");
    fclose(file);
}

// Finalises the plugin
__attribute__((destructor)) static void vector_counter_fini(void) {
    fprintf(stderr, "[vector_tracer] total vector instructions executed: %" PRIu64 "\n",
            vector_inst_count);
    fprintf(stderr, "[vector_tracer] register-register RVV instructions executed: %" PRIu64 "\n",
            reg_reg_count);
    
    finalize_json_file();
    fprintf(stderr, "[vector_tracer] Wrote entries to trace.json\n");
    
    if (trace_data.entries != NULL) {
        free(trace_data.entries);
        trace_data.entries = NULL;
    }
}




// TODO figure out how to get the vector register values
// Should we use the vse8.v instruction to get the vector register values?
// There is something called emit. I think we have to put our own instructions in the code and use them to save the vector register values
// Should we use that approach? How time consuming would it be?
/*
We implement the emit function to get the data

Trace mask reg v0 in case mask is 1 

Implement status register handling 

memory accesses load and stores 






*/ 

/*
I have a big issue that I emit too many instruction. I need to optimize it otherwise the code doesn't run. 

*/