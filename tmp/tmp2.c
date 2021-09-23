#include <stdio.h>

struct foo {
    int i;
    int j;
};

struct foo foobar(void) {
    struct foo f;
    f.i = 10;
    f.j = 12;
    return f;
}

void voo(unsigned int *f)
{
    *f++;
}

void set_int(unsigned int *i) {
    *i = 10;
}

int main(void)
{
    unsigned char modrm = 0xD2;
    unsigned char mode;
    unsigned char r;
    unsigned char m;

    mode = modrm >> 6;
    r = (modrm & 0x38) >> 3;
    m = modrm & 0x07;
    
    printf( " mode = %x\n", mode);
    printf( " r = %x\n", r);
    printf( " m = %x\n", m);

    unsigned char disp[4];
    disp[0] = 0x11;
    disp[1] = 0x22;
    disp[2] = 0x33;
    disp[3] = 0x44;

    unsigned int displacement = 0;
    displacement += disp[0];
    displacement += (disp[1] << 8);
    displacement += (disp[2] << 16);
    displacement += (disp[3] << 24);
    printf("%x\n", displacement);

    unsigned int t = 0;
    set_int(&t);
    printf("%d\n", t);

    int i = 0xffffffb1;
    printf("%d\n", i);
    
    struct foo f;
    f = foobar();
    printf("foo.i = %d, foo.j = %d\n", f.i, f.j);

    return 0;

}
