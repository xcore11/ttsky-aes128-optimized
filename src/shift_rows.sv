`timescale 1ns/1ps

/*
 * ============================================================
 * File        : shift_rows.sv
 * Description : AES-128 ShiftRows transformation
 *
 * Function:
 *   Performs the AES ShiftRows operation by rearranging the bytes
 *   of the 128-bit AES state.
 *
 * Optimized design choice:
 *   - This module is reused unchanged from the baseline design.
 *   - ShiftRows is only byte rewiring, so it has very low area cost.
 *   - There is no need to make this operation sequential or shared.
 *
 * AES state byte ordering used in this design:
 *
 *   state = {b0,  b1,  b2,  b3,
 *            b4,  b5,  b6,  b7,
 *            b8,  b9,  b10, b11,
 *            b12, b13, b14, b15}
 *
 * This corresponds to the AES 4x4 state matrix:
 *
 *   [ b0   b4   b8   b12 ]
 *   [ b1   b5   b9   b13 ]
 *   [ b2   b6   b10  b14 ]
 *   [ b3   b7   b11  b15 ]
 *
 * ShiftRows rule:
 *   Row 0: no shift
 *   Row 1: shift left by 1 byte
 *   Row 2: shift left by 2 bytes
 *   Row 3: shift left by 3 bytes
 *
 * After ShiftRows:
 *
 *   [ b0   b4   b8   b12 ]
 *   [ b5   b9   b13  b1  ]
 *   [ b10  b14  b2   b6  ]
 *   [ b15  b3   b7   b11 ]
 *
 * Output state ordering after ShiftRows:
 *
 *   state_out = {b0,  b5,  b10, b15,
 *                b4,  b9,  b14, b3,
 *                b8,  b13, b2,  b7,
 *                b12, b1,  b6,  b11}
 *
 * Hardware meaning:
 *   - This module is purely combinational.
 *   - It only rewires byte positions.
 *   - It does not use registers, clocks, arithmetic, or S-boxes.
 *   - It can be reused in both the baseline and optimized designs.
 * ============================================================
 */

module shift_rows
(
    // AES state before ShiftRows.
    input  logic [127:0] state_in,

    // AES state after ShiftRows.
    output logic [127:0] state_out
);

    /*
     * Byte rearrangement for ShiftRows.
     *
     * The state is stored column-by-column.
     *
     * Original state:
     *   Column 0 = {b0,  b1,  b2,  b3}
     *   Column 1 = {b4,  b5,  b6,  b7}
     *   Column 2 = {b8,  b9,  b10, b11}
     *   Column 3 = {b12, b13, b14, b15}
     *
     * After ShiftRows:
     *   Column 0 = {b0,  b5,  b10, b15}
     *   Column 1 = {b4,  b9,  b14, b3}
     *   Column 2 = {b8,  b13, b2,  b7}
     *   Column 3 = {b12, b1,  b6,  b11}
     */
    assign state_out = {
        // Column 0 after ShiftRows: {b0, b5, b10, b15}
        state_in[127:120],
        state_in[87:80],
        state_in[47:40],
        state_in[7:0],

        // Column 1 after ShiftRows: {b4, b9, b14, b3}
        state_in[95:88],
        state_in[55:48],
        state_in[15:8],
        state_in[103:96],

        // Column 2 after ShiftRows: {b8, b13, b2, b7}
        state_in[63:56],
        state_in[23:16],
        state_in[111:104],
        state_in[71:64],

        // Column 3 after ShiftRows: {b12, b1, b6, b11}
        state_in[31:24],
        state_in[119:112],
        state_in[79:72],
        state_in[39:32]
    };

endmodule