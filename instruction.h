#ifndef _INSTRUCTION_H_
#define _INSTRUCTION_H_

#define INSTRUCTION_SIZE sizeof(instruction_t)


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
typedef struct { 
    unsigned long addr;         /* address of the instruction */
    unsigned char prefix[14];   /* 14 because valid instructions
                                / are < 15 & 1 byte op is req */
    unsigned char opcode[3];    /* Max Opcode is 3 bytes */
    unsigned char insn_bytes[15];
    unsigned char modrm;
    unsigned char reg;
    unsigned char sib;
    int displacement; /* These are long for future 64-bit support */
    int immediate;
    unsigned char *mnemonic;   /* instruction mneumonic  ex. mov eax ebx*/
    unsigned char is_control_flow;
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

inline int insn_set_sib(instruction_t *i, unsigned long sib) {
    i->sib = sib;
}

inline int insn_set_addr(instruction_t *i, unsigned long addr) {
    i->addr = addr;
}

#endif
