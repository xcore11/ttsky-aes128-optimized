# SPDX-FileCopyrightText: © 2024 Tiny Tapeout
# SPDX-License-Identifier: Apache-2.0

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles, Timer


KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")
EXPECTED_CIPHERTEXT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")


async def pulse_uio(dut, bit_index: int, data_byte: int | None = None):
    """Pulse one uio_in command bit for one clock cycle."""
    if data_byte is not None:
        dut.ui_in.value = data_byte

    dut.uio_in.value = 1 << bit_index
    await ClockCycles(dut.clk, 1)

    dut.uio_in.value = 0
    await ClockCycles(dut.clk, 1)


@cocotb.test()
async def test_aes128_wrapper_known_vector(dut):
    dut._log.info("Start AES-128 Tiny Tapeout wrapper test")

    # 100 MHz simulation clock. This is just for simulation.
    clock = Clock(dut.clk, 10, unit="ns")
    cocotb.start_soon(clock.start())

    # Reset.
    dut.ena.value = 1
    dut.ui_in.value = 0
    dut.uio_in.value = 0
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 10)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 2)

    # Clear wrapper counters/status.
    await pulse_uio(dut, 4)

    # Load 128-bit key, MSB byte first.
    for b in KEY:
        await pulse_uio(dut, 0, b)

    # Load 128-bit plaintext, MSB byte first.
    for b in PLAINTEXT:
        await pulse_uio(dut, 1, b)

    # Check ready bit uio_out[7].
    await Timer(1, unit="ns")
    assert int(dut.uio_out.value) & 0x80, "Wrapper did not report ready after key/plaintext load"

    # Start AES.
    await pulse_uio(dut, 2)

    # Wait for done-latched bit uio_out[6].
    done = False
    for _ in range(2000):
        await ClockCycles(dut.clk, 1)
        if int(dut.uio_out.value) & 0x40:
            done = True
            break

    assert done, "AES wrapper did not assert done within timeout"

    # Read ciphertext bytes, MSB byte first.
    observed = []

    for i in range(16):
        await Timer(1, unit="ns")
        observed.append(int(dut.uo_out.value))

        if i != 15:
            await pulse_uio(dut, 3)

    observed_bytes = bytes(observed)

    dut._log.info("Observed ciphertext: %s", observed_bytes.hex())
    dut._log.info("Expected ciphertext: %s", EXPECTED_CIPHERTEXT.hex())

    assert observed_bytes == EXPECTED_CIPHERTEXT, (
        f"Ciphertext mismatch: got {observed_bytes.hex()}, "
        f"expected {EXPECTED_CIPHERTEXT.hex()}"
    )
