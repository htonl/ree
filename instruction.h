#ifndef _INSTRUCTION_H_
#define _INSTRUCTION_H_

#define INSTRUCTION_SIZE sizeof(instruction_t)

#define REG_EAX 0x000
#define REG_ECX 0x001
#define REG_EDX 0x010
#define REG_EBX 0x011
#define REG_ESP 0x100
#define REG_EBP 0x101
#define REG_ESI 0x110
#define REG_EDI 0x111

/* @brief instruction abstraction
 *
 * This struct is to hold all the data needed to print an
 * instruction.
 *
 * Basic flow:
 * 	1) read an insn from the input file
 * 	2) lookup the prefix/opcode in the hashtable
 * 	3) use hash table results to build instruction_t struct
 * 	4) build tree of instruction_t structs
 * 	5) once EOF of input file, traverse the tree of insn
 */
typedef struct __attribute__((__packed__)){ 
    unsigned long addr;         /* address of the instruction */
    unsigned char prefix[14];   /* 14 because valid instructions
                                / are < 15 & 1 byte op is req */
    unsigned char opcode[3];    /* Max Opcode is 3 bytes */
    unsigned char modrm;
    unsigned char reg;
    unsigned char sib;
    unsigned long displacement; /* These are long for future 64-bit support */
    unsigned long immediate;
    unsigned char *mnemonic;   /* instruction mneumonic  ex. mov eax ebx*/ 
    unsigned char unused[4];    /* Zero padding to 48 bytes */
} instruction_t;

instruction_t *insn_new(void);
void insn_free(instruction_t *i);
int insn_create_mnemonic(instruction_t *i);

inline void insn_set_reg(instruction_t *i, unsigned char reg) {
    i->reg = reg;
}

inline void insn_set_opcode(instruction_t *i, unsigned char *op) {
    switch(op[0]) {
        case 0x48:
            insn_set_reg(op[1]);
            op[1] = 0;
            break;
        case 0x40:
            insn_set_reg(op[1]);
            op[1] = 0;
            break;
        case 0x58:
            insn_set_reg(op[1]);
            op[1] = 0;
            break;
        case 0x50:
            insn_set_reg(op[1]);
            op[1] = 0;
            break;
    memcpy(i->opcode, op, sizeof(i->opcode));
}

inline void insn_set_prefix(instruction_t *i, unsigned char *pre) {
    mempcy(i->prefix, pre, sizeof(i->prefix));
}

inline void insn_set_modrm(instruction_t *i, unsigned char modrm) {
    i->modrm = modrm;
}

inline int insn_set_displacement(instruction_t *i, unsigned long dis) {
    i->displacement = dis;
}

inline int insn_set_immediate(instruction_t *i, unsigned long imm) {
    i->immediate = imm;
}

inline int insn_set_sib(instruction_t *i, unsigned long sib) {
    i->sib = sib;
}

inline int insn_set_addr(instruction_t *i, unsigned long addr) {
    i->addr = addr;
}

#endif
