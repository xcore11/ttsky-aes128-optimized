`timescale 1ns/1ps

/*
 * ============================================================
 * File        : sbox.sv
 * Description : AES-128 optimized Boolean logic S-box
 *
 * Function:
 *   Implements the AES S-box using optimized combinational
 *   Boolean logic instead of a 256-entry lookup table.
 *
 * AES S-box meaning:
 *   The AES S-box mathematically performs:
 *
 *     1. Multiplicative inverse in GF(2^8)
 *     2. Affine transformation
 *
 *   This file does not explicitly calculate the inverse using
 *   gf_mul or store the S-box table. Instead, it implements the
 *   same input-output mapping using a minimized Boolean network.
 *
 * Optimized design choice:
 *   - Baseline version:
 *       Uses a lookup-table S-box.
 *
 *   - Earlier Boolean/GF version:
 *       Computes GF inverse using gf_mul and exponentiation.
 *       This is correct but can synthesize into large logic.
 *
 *   - This version:
 *       Uses minimized XOR, AND, and NOT Boolean logic.
 *       This is more suitable for low-area synthesis because the
 *       repeated intermediate terms are shared.
 *
 * Important:
 *   - Module name and ports are kept the same as your previous
 *     sbox module.
 *   - This means aes_core_optimized can continue instantiating
 *     sbox without changing its port connections.
 *
 * Verification:
 *   - Test all 256 input values against the standard AES S-box
 *     table before using this in the full AES core.
 * ============================================================
 */

module sbox
(
    // Input byte before AES S-box substitution.
    input  logic [7:0] in_byte,

    // Output byte after AES S-box substitution.
    output logic [7:0] out_byte
);

    /*
     * Internal bit ordering.
     *
     * This Boolean network uses [0:7] indexing internally.
     * Do not change these declarations to [7:0] unless the whole
     * Boolean network is remapped, because the equations depend on
     * this bit order.
     *
     * With logic [0:7], assigning x = in_byte maps the external
     * input byte into the internal bit order expected by this
     * optimized S-box network.
     */
    logic [0:7] x;
    logic [0:7] s;

    /*
     * Intermediate signals.
     *
     * y:
     *   Early linear pre-processing terms.
     *   These are mostly XOR combinations of input bits.
     *
     * t:
     *   Main intermediate network.
     *   This includes both linear XOR terms and nonlinear AND terms.
     *
     * z:
     *   Later nonlinear intermediate terms.
     *   These are mainly AND combinations used before the final
     *   output XOR network.
     *
     * These intermediate signals allow repeated expressions to be
     * shared instead of recalculated many times.
     */
    logic [21:1] y;
    logic [67:0] t;
    logic [17:0] z;

    /*
     * Map external input byte into the internal bit vector.
     *
     * The Boolean equations below operate on x[0] to x[7].
     */
    assign x = in_byte;

    /*
     * ========================================================
     * Stage 1: Linear pre-processing
     *
     * This section creates useful XOR combinations from the input
     * bits. These y and early t values are shared by later parts of
     * the S-box circuit.
     *
     * This stage is called "linear" because XOR-only logic is
     * linear over GF(2).
     * ========================================================
     */

    assign y[14] = x[3] ^ x[5];
    assign y[13] = x[0] ^ x[6];
    assign y[9]  = x[0] ^ x[3];
    assign y[8]  = x[0] ^ x[5];

    assign t[0]  = x[1] ^ x[2];
    assign y[1]  = t[0] ^ x[7];
    assign y[4]  = y[1] ^ x[3];
    assign y[12] = y[13] ^ y[14];
    assign y[2]  = y[1] ^ x[0];
    assign y[5]  = y[1] ^ x[6];
    assign y[3]  = y[5] ^ y[8];

    assign t[1]  = x[4] ^ y[12];
    assign y[15] = t[1] ^ x[5];
    assign y[20] = t[1] ^ x[1];
    assign y[6]  = y[15] ^ x[7];
    assign y[10] = y[15] ^ t[0];
    assign y[11] = y[20] ^ y[9];
    assign y[7]  = x[7] ^ y[11];
    assign y[17] = y[10] ^ y[11];
    assign y[19] = y[10] ^ y[8];
    assign y[16] = t[0] ^ y[11];
    assign y[21] = y[13] ^ y[16];
    assign y[18] = x[0] ^ y[16];

    /*
     * ========================================================
     * Stage 2: Nonlinear core
     *
     * The AES S-box is nonlinear, so XOR-only logic is not enough.
     * The AND gates in this section provide the nonlinear behaviour.
     *
     * These equations implement the main minimized nonlinear part
     * of the AES S-box Boolean network.
     * ========================================================
     */

    assign t[2]  = y[12] & y[15];
    assign t[3]  = y[3] & y[6];
    assign t[4]  = t[3] ^ t[2];
    assign t[5]  = y[4] & x[7];
    assign t[6]  = t[5] ^ t[2];
    assign t[7]  = y[13] & y[16];
    assign t[8]  = y[5] & y[1];
    assign t[9]  = t[8] ^ t[7];
    assign t[10] = y[2] & y[7];
    assign t[11] = t[10] ^ t[7];
    assign t[12] = y[9] & y[11];
    assign t[13] = y[14] & y[17];
    assign t[14] = t[13] ^ t[12];
    assign t[15] = y[8] & y[10];
    assign t[16] = t[15] ^ t[12];

    /*
     * Combine nonlinear terms into the middle representation used
     * by the optimized S-box network.
     */
    assign t[17] = t[4] ^ t[14];
    assign t[18] = t[6] ^ t[16];
    assign t[19] = t[9] ^ t[14];
    assign t[20] = t[11] ^ t[16];

    /*
     * Further mixing of the nonlinear core with selected linear
     * terms. These signals prepare the circuit for the compact
     * inverse/affine-equivalent output stage.
     */
    assign t[21] = t[17] ^ y[20];
    assign t[22] = t[18] ^ y[19];
    assign t[23] = t[19] ^ y[21];
    assign t[24] = t[20] ^ y[18];

    /*
     * Compact nonlinear reduction network.
     *
     * This section continues the minimized Boolean transformation.
     * It is part of the optimized circuit that replaces the direct
     * GF inverse calculation.
     */
    assign t[25] = t[21] ^ t[22];
    assign t[26] = t[21] & t[23];
    assign t[27] = t[24] ^ t[26];
    assign t[28] = t[25] & t[27];
    assign t[29] = t[28] ^ t[22];
    assign t[30] = t[23] ^ t[24];
    assign t[31] = t[22] ^ t[26];
    assign t[32] = t[31] & t[30];
    assign t[33] = t[32] ^ t[24];
    assign t[34] = t[23] ^ t[33];
    assign t[35] = t[27] ^ t[33];
    assign t[36] = t[24] & t[35];
    assign t[37] = t[36] ^ t[34];
    assign t[38] = t[27] ^ t[36];
    assign t[39] = t[29] & t[38];
    assign t[40] = t[25] ^ t[39];
    assign t[41] = t[40] ^ t[37];
    assign t[42] = t[29] ^ t[33];
    assign t[43] = t[29] ^ t[40];
    assign t[44] = t[33] ^ t[37];
    assign t[45] = t[42] ^ t[41];

    /*
     * ========================================================
     * Stage 3: Post-nonlinear AND layer
     *
     * The z signals combine the reduced nonlinear values with
     * earlier linear terms. These form the inputs to the final
     * output XOR network.
     * ========================================================
     */

    assign z[0]  = t[44] & y[15];
    assign z[1]  = t[37] & y[6];
    assign z[2]  = t[33] & x[7];
    assign z[3]  = t[43] & y[16];
    assign z[4]  = t[40] & y[1];
    assign z[5]  = t[29] & y[7];
    assign z[6]  = t[42] & y[11];
    assign z[7]  = t[45] & y[17];
    assign z[8]  = t[41] & y[10];
    assign z[9]  = t[44] & y[12];
    assign z[10] = t[37] & y[3];
    assign z[11] = t[33] & y[4];
    assign z[12] = t[43] & y[13];
    assign z[13] = t[40] & y[5];
    assign z[14] = t[29] & y[2];
    assign z[15] = t[42] & y[9];
    assign z[16] = t[45] & y[14];
    assign z[17] = t[41] & y[8];

    /*
     * ========================================================
     * Stage 4: Final linear output network
     *
     * This stage uses XOR and NOT logic to produce the final
     * AES S-box output bits.
     *
     * The NOT operations are part of the constant addition in the
     * AES affine transformation.
     * ========================================================
     */

    assign t[46] = z[15] ^ z[16];
    assign t[47] = z[10] ^ z[11];
    assign t[48] = z[5] ^ z[13];
    assign t[49] = z[9] ^ z[10];
    assign t[50] = z[2] ^ z[12];
    assign t[51] = z[2] ^ z[5];
    assign t[52] = z[7] ^ z[8];
    assign t[53] = z[0] ^ z[3];
    assign t[54] = z[6] ^ z[7];
    assign t[55] = z[16] ^ z[17];
    assign t[56] = z[12] ^ t[48];
    assign t[57] = t[50] ^ t[53];
    assign t[58] = z[4] ^ t[46];
    assign t[59] = z[3] ^ t[54];
    assign t[60] = t[46] ^ t[57];
    assign t[61] = z[14] ^ t[57];
    assign t[62] = t[52] ^ t[58];
    assign t[63] = t[49] ^ t[58];
    assign t[64] = z[4] ^ t[59];
    assign t[65] = t[61] ^ t[62];
    assign t[66] = z[1] ^ t[63];

    /*
     * Final S-box output bit equations.
     *
     * s[0] to s[7] are the final substituted byte bits.
     */
    assign s[0]  = t[59] ^ t[63];
    assign s[6]  = ~t[56] ^ t[62];
    assign s[7]  = ~t[48] ^ t[60];
    assign t[67] = t[64] ^ t[65];
    assign s[3]  = t[53] ^ t[66];
    assign s[4]  = t[51] ^ t[66];
    assign s[5]  = t[47] ^ t[65];
    assign s[1]  = ~t[64] ^ s[3];
    assign s[2]  = ~t[55] ^ t[67];

    /*
     * Map internal S-box result to external output byte.
     *
     * Keep this assignment unchanged because the internal [0:7]
     * ordering is part of this optimized S-box implementation.
     */
    assign out_byte = s;

endmodule