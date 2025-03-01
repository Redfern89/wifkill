#include <stdio.h>
#include <stdint.h>

int main (void) {

    uint8_t mask = 0b00111111;
    uint8_t byte_rts = 0b10110100;
    uint8_t byte_cts = 0b11000100;

    uint8_t result = byte_rts & mask;

    printf("rts: %b, masked: %b", byte_rts, result);

    return 0;
}