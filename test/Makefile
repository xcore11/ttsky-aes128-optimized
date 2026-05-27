# Makefile
# See https://docs.cocotb.org/en/stable/quickstart.html for more info
#
# Tiny Tapeout cocotb Makefile for AES-128 project.
# Put this file at:
#   ttsky-verilog-template/test/Makefile
#
# This version is intended for GitHub Actions.
# It does not contain the Windows/Icarus preflight check.

# defaults
SIM ?= icarus
FST ?= -fst
TOPLEVEL_LANG ?= verilog

SRC_DIR = $(PWD)/../src

# Source files in ../src.
# Keep this list matched with project.source_files in info.yaml.
PROJECT_SOURCES = tt_um_aes128_optimized.sv \
                  aes128_optimized.sv \
                  aes_core.sv \
                  mix_columns.sv \
                  sbox.sv \
                  shift_rows.sv

# Your RTL uses SystemVerilog syntax such as .sv, logic, always_ff/always_comb.
# Icarus needs -g2012 for these features.
COMPILE_ARGS += -g2012

ifneq ($(GATES),yes)

# RTL simulation:
SIM_BUILD = sim_build/rtl
VERILOG_SOURCES += $(addprefix $(SRC_DIR)/,$(PROJECT_SOURCES))

else

# Gate level simulation:
SIM_BUILD = sim_build/gl
COMPILE_ARGS += -DGL_TEST
COMPILE_ARGS += -DFUNCTIONAL
COMPILE_ARGS += -DUSE_POWER_PINS
COMPILE_ARGS += -DSIM
COMPILE_ARGS += -DUNIT_DELAY=\#1

VERILOG_SOURCES += $(PDK_ROOT)/sky130A/libs.ref/sky130_fd_sc_hd/verilog/primitives.v
VERILOG_SOURCES += $(PDK_ROOT)/sky130A/libs.ref/sky130_fd_sc_hd/verilog/sky130_fd_sc_hd.v

# this gets copied in by the GDS action workflow
VERILOG_SOURCES += $(PWD)/gate_level_netlist.v

endif

# Allow sharing configuration between design and testbench via `include`:
COMPILE_ARGS += -I$(SRC_DIR)

# Include the testbench sources:
VERILOG_SOURCES += $(PWD)/tb.v
TOPLEVEL = tb

# List test modules to run, separated by commas and without the .py suffix:
# Keep both names for compatibility with different cocotb versions.
MODULE = test
COCOTB_TEST_MODULES = test

# include cocotb's make rules to take care of the simulator setup
include $(shell cocotb-config --makefiles)/Makefile.sim
