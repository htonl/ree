#include <stdio.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    unsigned char byte1 = 0xff;
    unsigned char byte2 = 0xf0;
    unsigned char byte3 = 0x01;
    int i1 = 0xff;
    int i2 = 0xf0;
    int i3 = 0x4201;
    printf("byte1 == i1: %d\n", byte1 == i1);
    printf("byte2 == i2: %d\n", byte2 == i2);
    printf("byte3 == i3: %d\n", byte3 == i3);
    printf("(usigned char) i1: %x\n", (unsigned char)i1);
    printf("(usigned char) i2: %x\n", (unsigned char)i2);
    printf("(usigned char) i3: %x\n", (unsigned char)i3);
    printf("(int) byte1: %x\n", (int)byte1);
    printf("(int) byte2: %x\n", (int)byte2);
    printf("(int) byte3: %x\n", (int)byte3);
    return 0;
}
