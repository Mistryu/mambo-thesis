# RISC-V Vector Extension Register-Register Instruction Tests

This directory contains comprehensive tests for RISC-V Vector Extension (RVV) register-register instructions to validate the vector tracer plugin.

## Test File: `test_rvv_reg_reg`

### Description

The test file `test_rvv_reg_reg.S` exercises 29 different register-register RVV instructions (opcode 0x57), including:

- **Instruction Types**: add, sub, mul, and, or, xor, shift left, shift right (logical/arithmetic), min, max, compare (equal/not equal)
- **Register Combinations**: Various source (vs1, vs2) and destination (vd) register combinations
- **Masked Operations**: Both masked (vm=0) and unmasked (vm=1) operations
- **Edge Cases**: Using v0 as destination, chaining operations, different register numbers

### Compilation

```bash
cd risc_v_tests
make
```

Or manually:

```bash
riscv64-unknown-linux-gnu-gcc -march=rv64gcv -mabi=lp64d -O2 -g test_rvv_reg_reg.S test_rvv_reg_reg.c -o test_rvv_reg_reg
```

**Requirements:**

- RISC-V GCC toolchain with Vector Extension support (`-march=rv64gcv`)
- The `gcv` extension includes: G (I+M+A), C (compressed), V (vector)

### Running with MAMBO

```bash
# Run with vector tracer plugin
../mambo --plugin vector_tracer test_rvv_reg_reg

# After execution, check trace.json for captured register values
cat trace.json
```

### Test Coverage

The test includes 29 register-register instructions:

1. **Unmasked operations** (vm=1): Tests where all elements are processed
2. **Masked operations** (vm=0): Tests where mask register v0 controls element processing
3. **Different funct6 values**: Tests various instruction types (add=0x00, sub=0x02, mul=0x25, etc.)
4. **Different funct3 values**: Tests different operation variants
5. **Register combinations**: Tests with different vd, vs1, vs2 values (0-31)
6. **Edge cases**: Using v0 as destination, chaining operations

### Expected Output

When run with the vector tracer plugin, the test should:

- Execute 29 register-register RVV instructions
- Generate entries in `trace.json` with:
  - Instruction details (pc, insn, vd, vs1, vs2, vm, funct3, funct6, opcode)
  - Register values before and after execution (vs1, vs2, mask if vm=0, vd_before, vd_after)

### Verification

Check `trace.json` to verify:

1. All 29 instructions are captured
2. Register values are correctly captured before and after
3. Mask register (v0) is captured when vm=0
4. All register combinations are correctly identified
