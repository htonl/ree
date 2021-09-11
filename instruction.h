#ifndef _INSTRUCTION_H_
#define _INSTRUCTION_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INSTRUCTION_SIZE sizeof(instruction_t)

typedef struct __attribute__((__packed__)){ 
    unsigned long addr;         /* address of the instruction */
    unsigned char prefix[14];   /* 14 because valid instructions
                                / are < 15 & 1 byte op is req */
    unsigned char opcode[3];    /* Max Opcode is 3 bytes */
    unsigned char modrm;
    unsigned char sib;
    unsigned long displacement; /* These are long for future 64-bit support */
    unsigned long immediate;
    unsigned char *mneumonic;   /* instruction mneumonic  ex. mov eax ebx*/ 
    unsigned char unused[4];    /* Zero padding to 48 bytes 
                                   Makes serializing easier for hashing */
} instruction_t;

instruction_t *insn_new(void);
void insn_free(instruction_t *i);
int insn_add_mneumonic(instruction_t *i);

#endif
