// Compile: gcc -Wall -Wextra -pedantic varint.c -o varint
#include <stdio.h>
#include <stdint.h>

// Encoding function
int encode_varint(uint64_t i, unsigned char *buf) {
    int idx;

    if (i < 240) {
        buf[0] = (unsigned char)i;
        return 1;
    }

    buf[0] = (unsigned char)i | 240;
    i = (i - 240) >> 4;
    for (idx = 1; i >= 128; ++idx) {
        buf[idx] = (unsigned char)i | 128;
        i = (i - 128) >> 7;
    }
    buf[idx++] = (unsigned char)i;
    return idx;
}

// Decoding function
int decode_varint(unsigned char *buf, unsigned char *end, uint64_t *i) {
    unsigned char *msg = buf;
    int idx = 0;

    if (msg > end)
        return -1;

    if (msg[0] < 240) {
        *i = msg[0];
        return 1;
    }

    *i = msg[0];
    do {
        ++idx;
        if (msg + idx > end)
            return -1;
        *i += (uint64_t)msg[idx] << (4 + 7 * (idx - 1));
    } while (msg[idx] >= 128);
    return (idx + 1);
}

// Test function
void test_varint(uint64_t value) {
    unsigned char encoded[10] = {0};
    uint64_t decoded = 0;

    int encoded_len = encode_varint(value, encoded);
    int decoded_len = decode_varint(encoded, encoded + encoded_len, &decoded);

    printf("Value: %lu\n", value);
    printf("Encoded (%d bytes): ", encoded_len);
    for (int i = 0; i < encoded_len; i++) {
        printf("%02X ", encoded[i]);
    }
    printf("\n");

    if (decoded_len > 0) {
        printf("Decoded: %lu\n", decoded);
    } else {
        printf("Decoding failed!\n");
    }

    printf("--------------------------------------------------\n");
}

int main() {
    test_varint(0);               // Min value
    test_varint(239);             // Max 1-byte value
    test_varint(240);             // Min 2-byte value
    test_varint(241);             // Min 2-byte value
    test_varint(250);             // Min 2-byte value
    test_varint(300);             // Min 2-byte value
    test_varint(2287);            // Max 2-byte value
    test_varint(2288);            // Min 3-byte value
    test_varint(2420);            // Min 3-byte value
    test_varint(264431);          // Max 3-byte value
    test_varint(264432);          // Min 4-byte value
    test_varint(1572912);         // Min 4-byte value
    test_varint(33818863);        // Max 4-byte value
    test_varint(33818864);        // Min 5-byte value
    test_varint(281374384);       // Min 5-byte value
    test_varint(4328786159);      // Max 5-byte value
    test_varint(4328786160);      // Min 6-byte value
    test_varint(4328786161);      // Min 6-byte value
    test_varint(UINT64_MAX);      // Max possible value

    return 0;
}
