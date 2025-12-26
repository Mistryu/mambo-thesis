# Makefile for RISC-V Vector Extension Register-Register Instruction Tests
# Compiles test_rvv_reg_reg.S and test_rvv_reg_reg.c into an executable

CC ?= riscv64-unknown-linux-gnu-gcc
CFLAGS = -march=rv64gcv -mabi=lp64d -O2 -g
LDFLAGS = 

# Default target
all: test_rvv_reg_reg

# Build the test executable
test_rvv_reg_reg: test_rvv_reg_reg.S test_rvv_reg_reg.c
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

# Clean build artifacts
clean:
	rm -f test_rvv_reg_reg

.PHONY: all clean

