`timescale 1ns/1ps

/*
 * ============================================================
 * File        : aes_core.sv
 * Description : AES-128 optimized shared-resource encryption core
 *
 * Project     : ECE4063 IC Design Project
 *
 * Architecture:
 *   - AES-128 encryption-only core.
 *   - Optimized multi-cycle shared-resource datapath.
 *   - Only ONE S-box instance is used in the whole core.
 *   - The same S-box is shared between:
 *       1) KeyExpansion SubWord
 *       2) AES state SubBytes
 *   - Only ONE mix_columns_one_column instance is used.
 *   - The MixColumns column unit is reused across the four AES
 *     state columns.
 *   - ShiftRows is kept as combinational byte rewiring because it
 *     has very low area cost.
 *   - AddRoundKey is implemented directly as a 128-bit XOR inside
 *     the core.
 *
 * External interface:
 *   clk        : System clock.
 *   reset_n    : Active-low asynchronous reset.
 *   start      : One-clock pulse to start encryption.
 *   plaintext  : 128-bit plaintext input block.
 *   key        : 128-bit AES key.
 *   ciphertext : 128-bit ciphertext output block.
 *   busy       : High while encryption is running.
 *   done       : One-clock pulse when ciphertext is valid.
 *
 * Main optimization versus baseline:
 *   The baseline design uses parallel hardware:
 *     - 16 S-boxes for SubBytes
 *     - 4 S-boxes for KeyExpansion
 *     - 4 MixColumns column units
 *
 *   This optimized design uses shared hardware:
 *     - 1 shared S-box total
 *     - 1 shared MixColumns column unit
 *     - 1 centralized controller FSM
 *
 * Trade-off:
 *   - Area is reduced because duplicated S-box and MixColumns
 *     hardware is removed.
 *   - Latency increases because SubBytes, KeyExpansion, and
 *     MixColumns are performed across multiple cycles.
 *
 * AES operation sequence:
 *   1. Initial AddRoundKey:
 *        state = plaintext XOR key
 *
 *   2. Rounds 1 to 9:
 *        KeyExpansion
 *        SubBytes
 *        ShiftRows
 *        MixColumns
 *        AddRoundKey
 *
 *   3. Round 10:
 *        KeyExpansion
 *        SubBytes
 *        ShiftRows
 *        AddRoundKey
 *
 * Notes:
 *   - Round 10 skips MixColumns, as required by AES-128.
 *   - The top-level wrapper should instantiate this module as
 *     aes_core_optimized.
 * ============================================================
 */

module aes_core
(
    // System clock.
    input  logic         clk,

    // Active-low asynchronous reset.
    input  logic         reset_n,

    // One-clock pulse to start AES encryption.
    input  logic         start,

    // 128-bit plaintext input block.
    input  logic [127:0] plaintext,

    // 128-bit AES key.
    input  logic [127:0] key,

    // 128-bit ciphertext output block.
    output logic [127:0] ciphertext,

    // High while AES encryption is running.
    output logic         busy,

    // One-clock pulse when ciphertext is valid.
    output logic         done
);

    /*
     * Main AES controller states.
     *
     * ST_IDLE:
     *   Waits for the external start signal.
     *
     * ST_INIT_ADDKEY:
     *   Performs the initial AES AddRoundKey using K0.
     *
     * ST_KEY_ROTWORD:
     *   Prepares RotWord(w3) for AES key expansion.
     *
     * ST_KEY_SUBWORD:
     *   Reuses the single shared S-box for four cycles to generate
     *   SubWord(RotWord(w3)).
     *
     * ST_KEY_MAKE_ROUNDKEY:
     *   Builds the next 128-bit AES round key.
     *
     * ST_SUBBYTES:
     *   Reuses the same shared S-box for sixteen cycles to apply
     *   SubBytes to all 16 AES state bytes.
     *
     * ST_SHIFTROWS:
     *   Applies ShiftRows using combinational byte rewiring.
     *
     * ST_MIXCOLUMNS:
     *   Reuses one MixColumns column block for four cycles.
     *
     * ST_ADDROUNDKEY:
     *   XORs the current AES state with the current round key.
     *
     * ST_DONE:
     *   Pulses done high for one clock cycle.
     */
    typedef enum logic [3:0]
    {
        ST_IDLE,
        ST_INIT_ADDKEY,
        ST_KEY_ROTWORD,
        ST_KEY_SUBWORD,
        ST_KEY_MAKE_ROUNDKEY,
        ST_SUBBYTES,
        ST_SHIFTROWS,
        ST_MIXCOLUMNS,
        ST_ADDROUNDKEY,
        ST_DONE
    } state_t;

    // Current FSM state.
    state_t state;

    /*
     * Current AES state register.
     *
     * This register stores the 128-bit state as it moves through
     * AES rounds.
     */
    logic [127:0] state_reg;

    /*
     * Current AES round key register.
     *
     * At the start, this stores the original key K0.
     * During each round, it is updated to the next generated round key.
     */
    logic [127:0] round_key_reg;

    /*
     * Temporary AES state register.
     *
     * Used to build intermediate results across multiple cycles:
     *   - SubBytes result, one byte at a time
     *   - MixColumns result, one column at a time
     */
    logic [127:0] temp_state_reg;
    logic [127:0] temp_state_next;

    /*
     * AES round counter.
     *
     * Active round values:
     *   1 to 9  : normal AES rounds with MixColumns
     *   10      : final AES round without MixColumns
     */
    logic [3:0] round_reg;

    /*
     * Shared byte counter.
     *
     * Used in:
     *   - ST_KEY_SUBWORD, values 0 to 3
     *   - ST_SUBBYTES, values 0 to 15
     */
    logic [3:0] byte_count;

    /*
     * Shared column counter.
     *
     * Used in ST_MIXCOLUMNS to process four AES columns.
     */
    logic [1:0] col_count;

    /*
     * AES round constant used during key expansion.
     *
     * AES-128 Rcon sequence:
     *   01 -> 02 -> 04 -> 08 -> 10
     *   -> 20 -> 40 -> 80 -> 1b -> 36
     */
    logic [7:0] rcon_reg;

    /*
     * KeyExpansion temporary registers.
     *
     * rot_word_reg:
     *   Stores RotWord(w3).
     *
     * sub_word_reg:
     *   Stores SubWord(RotWord(w3)), built one byte per cycle.
     *
     * sub_word_next:
     *   Next value of sub_word_reg after inserting the current
     *   S-box output.
     *
     * g_word:
     *   SubWord(RotWord(w3)) after Rcon is applied.
     */
    logic [31:0] rot_word_reg;
    logic [31:0] sub_word_reg;
    logic [31:0] sub_word_next;
    logic [31:0] g_word;

    // Current round key words.
    logic [31:0] w0;
    logic [31:0] w1;
    logic [31:0] w2;
    logic [31:0] w3;

    // Next round key words.
    logic [31:0] w4;
    logic [31:0] w5;
    logic [31:0] w6;
    logic [31:0] w7;

    // Next 128-bit AES round key.
    logic [127:0] next_round_key;

    // Shared S-box input and output.
    logic [7:0] sbox_in;
    logic [7:0] sbox_out;

    // Shared MixColumns column input and output.
    logic [31:0] mix_col_in;
    logic [31:0] mix_col_out;

    // Combinational ShiftRows output.
    logic [127:0] shift_rows_out;

    /*
     * One shared S-box instance.
     *
     * This is the only S-box used in the optimized AES core.
     * It is shared between:
     *   - KeyExpansion SubWord
     *   - AES SubBytes
     *
     * For the optimized design, this sbox should be the Boolean/GF
     * logic S-box, not the baseline lookup-table S-box.
     */
    sbox u_shared_sbox
    (
        .in_byte  (sbox_in),
        .out_byte (sbox_out)
    );

    /*
     * One shared MixColumns column datapath.
     *
     * This single block is reused for all four AES columns during
     * normal rounds 1 to 9.
     */
    mix_columns_one_column u_shared_mix_columns_one_column
    (
        .col_in  (mix_col_in),
        .col_out (mix_col_out)
    );

    /*
     * ShiftRows block.
     *
     * ShiftRows only rearranges bytes, so it is kept as a simple
     * combinational block rather than being sequentially shared.
     */
    shift_rows u_shift_rows
    (
        .state_in  (state_reg),
        .state_out (shift_rows_out)
    );

    // Split current round key into four 32-bit words.
    assign w0 = round_key_reg[127:96];
    assign w1 = round_key_reg[95:64];
    assign w2 = round_key_reg[63:32];
    assign w3 = round_key_reg[31:0];

    /*
     * KeyExpansion XOR chaining.
     *
     * AES-128 key schedule:
     *   w4 = w0 XOR g_word
     *   w5 = w1 XOR w4
     *   w6 = w2 XOR w5
     *   w7 = w3 XOR w6
     *
     * g_word is SubWord(RotWord(w3)) after Rcon is applied.
     */
    assign g_word = sub_word_reg ^ {rcon_reg, 24'h000000};

    assign w4 = w0 ^ g_word;
    assign w5 = w1 ^ w4;
    assign w6 = w2 ^ w5;
    assign w7 = w3 ^ w6;

    assign next_round_key = {w4, w5, w6, w7};

    /*
     * Shared S-box input selection.
     *
     * During ST_KEY_SUBWORD:
     *   byte_count[1:0] selects one byte from rot_word_reg.
     *
     * During ST_SUBBYTES:
     *   byte_count selects one byte from state_reg.
     */
    always_comb begin
        sbox_in = 8'h00;

        unique case (state)

            ST_KEY_SUBWORD: begin
                unique case (byte_count[1:0])
                    2'd0:    sbox_in = rot_word_reg[31:24];
                    2'd1:    sbox_in = rot_word_reg[23:16];
                    2'd2:    sbox_in = rot_word_reg[15:8];
                    2'd3:    sbox_in = rot_word_reg[7:0];
                    default: sbox_in = 8'h00;
                endcase
            end

            ST_SUBBYTES: begin
                sbox_in = state_reg[8*byte_count +: 8];
            end

            default: begin
                sbox_in = 8'h00;
            end

        endcase
    end

    /*
     * Build SubWord one byte at a time.
     *
     * This allows key expansion to use the same single S-box rather
     * than four parallel S-boxes.
     */
    always_comb begin
        sub_word_next = sub_word_reg;

        unique case (byte_count[1:0])
            2'd0:    sub_word_next[31:24] = sbox_out;
            2'd1:    sub_word_next[23:16] = sbox_out;
            2'd2:    sub_word_next[15:8]  = sbox_out;
            2'd3:    sub_word_next[7:0]   = sbox_out;
            default: sub_word_next        = sub_word_reg;
        endcase
    end

    /*
     * Build the next temporary AES state.
     *
     * During ST_SUBBYTES:
     *   The current S-box output is written into the selected byte.
     *
     * During ST_MIXCOLUMNS:
     *   The current MixColumns output is written into the selected
     *   32-bit column.
     */
    always_comb begin
        temp_state_next = temp_state_reg;

        unique case (state)

            ST_SUBBYTES: begin
                temp_state_next[8*byte_count +: 8] = sbox_out;
            end

            ST_MIXCOLUMNS: begin
                unique case (col_count)
                    2'd0:    temp_state_next[127:96] = mix_col_out;
                    2'd1:    temp_state_next[95:64]  = mix_col_out;
                    2'd2:    temp_state_next[63:32]  = mix_col_out;
                    2'd3:    temp_state_next[31:0]   = mix_col_out;
                    default: temp_state_next          = temp_state_reg;
                endcase
            end

            default: begin
                temp_state_next = temp_state_reg;
            end

        endcase
    end

    /*
     * Select one AES column for the shared MixColumns block.
     *
     * MixColumns operates on the 128-bit state column-by-column.
     */
    always_comb begin
        unique case (col_count)
            2'd0:    mix_col_in = state_reg[127:96];
            2'd1:    mix_col_in = state_reg[95:64];
            2'd2:    mix_col_in = state_reg[63:32];
            2'd3:    mix_col_in = state_reg[31:0];
            default: mix_col_in = 32'h00000000;
        endcase
    end

    /*
     * Main FSM and datapath registers.
     */
    always_ff @(posedge clk or negedge reset_n) begin

        if (!reset_n) begin
            state          <= ST_IDLE;
            state_reg      <= 128'h0;
            round_key_reg  <= 128'h0;
            temp_state_reg <= 128'h0;
            ciphertext     <= 128'h0;
            round_reg      <= 4'd0;
            byte_count     <= 4'd0;
            col_count      <= 2'd0;
            rcon_reg       <= 8'h00;
            rot_word_reg   <= 32'h0;
            sub_word_reg   <= 32'h0;
            busy           <= 1'b0;
            done           <= 1'b0;
        end

        else begin
            // done is cleared by default so it becomes a one-clock pulse.
            done <= 1'b0;

            unique case (state)

                ST_IDLE: begin
                    busy           <= 1'b0;
                    round_reg      <= 4'd0;
                    byte_count     <= 4'd0;
                    col_count      <= 2'd0;
                    rcon_reg       <= 8'h00;
                    temp_state_reg <= 128'h0;
                    rot_word_reg   <= 32'h0;
                    sub_word_reg   <= 32'h0;

                    if (start) begin
                        /*
                         * Latch input plaintext and key.
                         *
                         * The initial AddRoundKey is performed in
                         * ST_INIT_ADDKEY on the next clock.
                         */
                        busy          <= 1'b1;
                        state_reg     <= plaintext;
                        round_key_reg <= key;
                        state         <= ST_INIT_ADDKEY;
                    end
                end

                ST_INIT_ADDKEY: begin
                    // Initial AES AddRoundKey: state = plaintext XOR K0.
                    state_reg      <= state_reg ^ round_key_reg;
                    round_reg      <= 4'd1;
                    rcon_reg       <= 8'h01;
                    byte_count     <= 4'd0;
                    col_count      <= 2'd0;
                    temp_state_reg <= 128'h0;
                    state          <= ST_KEY_ROTWORD;
                end

                ST_KEY_ROTWORD: begin
                    /*
                     * Prepare RotWord(w3) for key expansion.
                     *
                     * round_key_reg[31:0] is w3.
                     * RotWord rotates the word left by one byte:
                     *   {a0, a1, a2, a3} -> {a1, a2, a3, a0}
                     */
                    rot_word_reg <= {round_key_reg[23:0], round_key_reg[31:24]};
                    sub_word_reg <= 32'h0;
                    byte_count   <= 4'd0;
                    state        <= ST_KEY_SUBWORD;
                end

                ST_KEY_SUBWORD: begin
                    /*
                     * Generate SubWord(RotWord(w3)) using the shared S-box.
                     *
                     * One byte is substituted per clock cycle.
                     */
                    sub_word_reg <= sub_word_next;

                    if (byte_count == 4'd3) begin
                        byte_count <= 4'd0;
                        state      <= ST_KEY_MAKE_ROUNDKEY;
                    end
                    else begin
                        byte_count <= byte_count + 4'd1;
                    end
                end

                ST_KEY_MAKE_ROUNDKEY: begin
                    /*
                     * Store the next AES round key.
                     *
                     * next_round_key is generated using the AES key
                     * schedule XOR chaining.
                     */
                    round_key_reg  <= next_round_key;
                    temp_state_reg <= 128'h0;
                    byte_count     <= 4'd0;
                    state          <= ST_SUBBYTES;
                end

                ST_SUBBYTES: begin
                    /*
                     * Apply SubBytes using the same shared S-box.
                     *
                     * One state byte is substituted per clock cycle.
                     */
                    temp_state_reg <= temp_state_next;

                    if (byte_count == 4'd15) begin
                        state_reg  <= temp_state_next;
                        byte_count <= 4'd0;
                        state      <= ST_SHIFTROWS;
                    end
                    else begin
                        byte_count <= byte_count + 4'd1;
                    end
                end

                ST_SHIFTROWS: begin
                    /*
                     * Register the ShiftRows output.
                     *
                     * In the final round, AES skips MixColumns and
                     * goes directly to AddRoundKey.
                     */
                    state_reg      <= shift_rows_out;
                    temp_state_reg <= 128'h0;
                    col_count      <= 2'd0;

                    if (round_reg == 4'd10) begin
                        state <= ST_ADDROUNDKEY;
                    end
                    else begin
                        state <= ST_MIXCOLUMNS;
                    end
                end

                ST_MIXCOLUMNS: begin
                    /*
                     * Apply MixColumns using one shared column unit.
                     *
                     * One AES column is processed per clock cycle.
                     */
                    temp_state_reg <= temp_state_next;

                    if (col_count == 2'd3) begin
                        state_reg <= temp_state_next;
                        col_count <= 2'd0;
                        state     <= ST_ADDROUNDKEY;
                    end
                    else begin
                        col_count <= col_count + 2'd1;
                    end
                end

                ST_ADDROUNDKEY: begin
                    /*
                     * Complete the current AES round.
                     *
                     * round_key_reg already contains the round key for
                     * this round.
                     */
                    state_reg <= state_reg ^ round_key_reg;

                    if (round_reg == 4'd10) begin
                        /*
                         * Final round complete.
                         *
                         * Since non-blocking assignments update at the end
                         * of the clock edge, ciphertext is assigned using
                         * the same XOR expression directly.
                         */
                        ciphertext <= state_reg ^ round_key_reg;
                        state      <= ST_DONE;
                    end
                    else begin
                        /*
                         * Continue to the next AES round.
                         */
                        round_reg <= round_reg + 4'd1;
                        rcon_reg  <= aes_xtime(rcon_reg);
                        state     <= ST_KEY_ROTWORD;
                    end
                end

                ST_DONE: begin
                    /*
                     * Encryption complete.
                     *
                     * done is pulsed high for one clock cycle and the
                     * core returns to idle.
                     */
                    busy  <= 1'b0;
                    done  <= 1'b1;
                    state <= ST_IDLE;
                end

                default: begin
                    state <= ST_IDLE;
                end

            endcase
        end
    end

    /*
     * Function    : aes_xtime
     * Description : Multiplication by 02 in AES GF(2^8)
     *
     * Purpose:
     *   Updates the AES Rcon sequence used by key expansion:
     *
     *   01 -> 02 -> 04 -> 08 -> 10
     *   -> 20 -> 40 -> 80 -> 1b -> 36
     *
     * Rule:
     *   If the most significant bit is 0:
     *     result = b << 1
     *
     *   If the most significant bit is 1:
     *     result = (b << 1) XOR 8'h1b
     */
    function automatic logic [7:0] aes_xtime
    (
        input logic [7:0] b
    );
        begin
            if (b[7] == 1'b1) begin
                aes_xtime = (b << 1) ^ 8'h1b;
            end
            else begin
                aes_xtime = (b << 1);
            end
        end
    endfunction

endmodule