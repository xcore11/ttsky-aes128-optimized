## How it works

This project implements an AES-128 encryption accelerator using an iterative, shared-resource hardware architecture. The internal AES block accepts a 128-bit plaintext and a 128-bit key, then produces a 128-bit ciphertext after the encryption rounds complete.

Because Tiny Tapeout has limited external IO pins, the top-level module `tt_um_aes128_optimized` wraps the AES core with an 8-bit byte-loading interface. The key and plaintext are loaded one byte at a time through `ui_in[7:0]`. Control pulses are provided using `uio_in[4:0]`. After the key and plaintext have been loaded, the `start` command begins encryption. When encryption is complete, the `done` status bit is asserted and the ciphertext can be read out one byte at a time on `uo_out[7:0]`.

The internal AES design uses an optimized shared-resource datapath. The design reuses AES functional blocks across multiple cycles instead of fully unrolling all rounds. This reduces logic area compared with a fully parallel implementation, at the cost of requiring more clock cycles per encryption block.

### Pin interface

| Pin | Direction | Function |
|---|---:|---|
| `ui_in[7:0]` | Input | Data byte used when loading key or plaintext |
| `uo_out[7:0]` | Output | Current ciphertext output byte |
| `uio_in[0]` | Input | Pulse high for one clock to load one key byte |
| `uio_in[1]` | Input | Pulse high for one clock to load one plaintext byte |
| `uio_in[2]` | Input | Pulse high for one clock to start encryption |
| `uio_in[3]` | Input | Pulse high for one clock to advance to the next ciphertext byte |
| `uio_in[4]` | Input | Pulse high for one clock to clear wrapper counters/status |
| `uio_out[5]` | Output | AES busy status |
| `uio_out[6]` | Output | Done latched / ciphertext valid |
| `uio_out[7]` | Output | Ready for start after key and plaintext are loaded |

Bytes are loaded and read most-significant byte first.

## How to test

The cocotb testbench loads a known AES-128 test vector through the Tiny Tapeout byte interface. It loads the 128-bit key and 128-bit plaintext byte-by-byte, pulses the start signal, waits for the `done` status, and then reads the 128-bit ciphertext byte-by-byte.

The test checks the following AES-128 vector:

- Key: `000102030405060708090a0b0c0d0e0f`
- Plaintext: `00112233445566778899aabbccddeeff`
- Expected ciphertext: `69c4e0d86a7b0430d8cdb78070b4c55a`

To run the local cocotb test in an environment with Icarus Verilog installed:

```bash
cd test
make clean
make
```

For this project, GitHub Actions can also run the Tiny Tapeout test and hardening workflows automatically after pushing to the repository.

## External hardware

No external hardware is required for the Tiny Tapeout wrapper test. The design only uses the standard Tiny Tapeout digital IO pins.
