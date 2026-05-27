`timescale 1ns/1ps

/*
 * ============================================================
 * File        : tt_um_aes128_optimized.sv
 * Description : Tiny Tapeout wrapper for aes128_optimized
 *
 * Purpose:
 *   Tiny Tapeout does not have enough pins to expose the full
 *   128-bit plaintext, 128-bit key, and 128-bit ciphertext ports.
 *   This wrapper loads the key and plaintext one byte at a time,
 *   starts the AES core, then outputs the ciphertext one byte at
 *   a time.
 *
 * Byte order:
 *   Byte 0 is the most significant byte [127:120].
 *   Byte 15 is the least significant byte [7:0].
 *
 * Tiny Tapeout interface mapping:
 *   ui_in[7:0]     : input data byte
 *
 *   uio_in[0]      : load key byte pulse
 *   uio_in[1]      : load plaintext byte pulse
 *   uio_in[2]      : start AES pulse
 *   uio_in[3]      : read next ciphertext byte pulse
 *   uio_in[4]      : clear wrapper counters/status pulse
 *
 *   uo_out[7:0]    : current ciphertext output byte
 *
 *   uio_out[5]     : AES busy
 *   uio_out[6]     : done latched, ciphertext valid
 *   uio_out[7]     : ready for start, key and plaintext loaded
 *
 *   uio[4:0] are inputs, uio[7:5] are outputs.
 * ============================================================
 */

module tt_um_aes128_optimized (
    input  wire [7:0] ui_in,
    output wire [7:0] uo_out,

    input  wire [7:0] uio_in,
    output wire [7:0] uio_out,
    output wire [7:0] uio_oe,

    input  wire       ena,
    input  wire       clk,
    input  wire       rst_n
);

    // Internal 128-bit AES registers.
    reg [127:0] key_reg;
    reg [127:0] plaintext_reg;
    reg [127:0] ciphertext_latched;

    // Byte counters.
    reg [3:0] key_index;
    reg [3:0] plaintext_index;
    reg [3:0] output_index;

    // Status flags.
    reg key_loaded;
    reg plaintext_loaded;
    reg done_latched;

    // Edge detection for command inputs.
    reg load_key_d;
    reg load_plaintext_d;
    reg start_d;
    reg read_next_d;
    reg clear_d;

    wire load_key_pulse;
    wire load_plaintext_pulse;
    wire start_pulse;
    wire read_next_pulse;
    wire clear_pulse;

    assign load_key_pulse       = uio_in[0] & ~load_key_d;
    assign load_plaintext_pulse = uio_in[1] & ~load_plaintext_d;
    assign start_pulse          = uio_in[2] & ~start_d;
    assign read_next_pulse      = uio_in[3] & ~read_next_d;
    assign clear_pulse          = uio_in[4] & ~clear_d;

    // AES core signals.
    wire [127:0] aes_ciphertext;
    wire         aes_busy;
    wire         aes_done;
    wire         ready_for_start;
    wire         aes_start;

    assign ready_for_start = key_loaded & plaintext_loaded & ~aes_busy;
    assign aes_start = start_pulse & ready_for_start;

    // uio[4:0] are command inputs, uio[7:5] are status outputs.
    assign uio_oe  = 8'b1110_0000;
    assign uio_out = {ready_for_start, done_latched, aes_busy, 5'b00000};

    // Current ciphertext byte output. Valid after done_latched = 1.
    assign uo_out = ciphertext_latched[127 - (output_index * 8) -: 8];

    // Keep ena referenced. Tiny Tapeout provides ena, but this wrapper does not need it.
    wire unused_ena;
    assign unused_ena = ena;

    aes128_optimized u_aes128_optimized (
        .clk        (clk),
        .reset_n    (rst_n),
        .start      (aes_start),
        .plaintext  (plaintext_reg),
        .key        (key_reg),
        .ciphertext (aes_ciphertext),
        .busy       (aes_busy),
        .done       (aes_done)
    );

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            key_reg            <= 128'h0;
            plaintext_reg      <= 128'h0;
            ciphertext_latched <= 128'h0;

            key_index          <= 4'd0;
            plaintext_index    <= 4'd0;
            output_index       <= 4'd0;

            key_loaded         <= 1'b0;
            plaintext_loaded   <= 1'b0;
            done_latched       <= 1'b0;

            load_key_d         <= 1'b0;
            load_plaintext_d   <= 1'b0;
            start_d            <= 1'b0;
            read_next_d        <= 1'b0;
            clear_d            <= 1'b0;
        end else begin
            // Register previous command states for rising-edge detection.
            load_key_d       <= uio_in[0];
            load_plaintext_d <= uio_in[1];
            start_d          <= uio_in[2];
            read_next_d      <= uio_in[3];
            clear_d          <= uio_in[4];

            if (clear_pulse) begin
                key_index        <= 4'd0;
                plaintext_index  <= 4'd0;
                output_index     <= 4'd0;
                key_loaded       <= 1'b0;
                plaintext_loaded <= 1'b0;
                done_latched     <= 1'b0;
            end else begin
                // Load key bytes MSB first.
                if (load_key_pulse && !aes_busy) begin
                    key_reg[127 - (key_index * 8) -: 8] <= ui_in;

                    if (key_index == 4'd15) begin
                        key_index  <= 4'd0;
                        key_loaded <= 1'b1;
                    end else begin
                        key_index <= key_index + 4'd1;
                    end

                    done_latched <= 1'b0;
                end

                // Load plaintext bytes MSB first.
                if (load_plaintext_pulse && !aes_busy) begin
                    plaintext_reg[127 - (plaintext_index * 8) -: 8] <= ui_in;

                    if (plaintext_index == 4'd15) begin
                        plaintext_index  <= 4'd0;
                        plaintext_loaded <= 1'b1;
                    end else begin
                        plaintext_index <= plaintext_index + 4'd1;
                    end

                    done_latched <= 1'b0;
                end

                // Capture ciphertext when AES finishes.
                if (aes_done) begin
                    ciphertext_latched <= aes_ciphertext;
                    done_latched       <= 1'b1;
                    output_index       <= 4'd0;
                end

                // Step through ciphertext bytes MSB first.
                if (read_next_pulse && done_latched) begin
                    output_index <= output_index + 4'd1;
                end
            end
        end
    end

endmodule
