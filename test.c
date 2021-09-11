#include <stdio.h>
#include <stdlib.h>
#include "instruction.h"
#include "tree.h"

int main(void) {
    // Print type sizes
    printf(" ----- Test 1: printing sizes -----\n");
    printf("sizeof(unsigned long): %lu\n", sizeof(unsigned long));
    printf("sizeof(unsigned long long): %lu\n", sizeof(unsigned long long));
    printf("sizeof(unsigned int): %lu\n", sizeof(unsigned int));
    printf("sizeof(unsigned short): %lu\n", sizeof(unsigned short));
    printf("sizeof(INSTRUCTION_SIZE) : %lu\n", INSTRUCTION_SIZE);

    // instructino struct testing
    printf(" ----- Test 2: allocate an instruction -----\n");
    instruction_t *i;
    i = insn_new();
    i->modrm = 0b11001001;
    i->opcode[0] = 0x8b;
    i->displacement = 0xff;
    printf("i.modrm = %x\n", i->modrm);
    printf("i.modrm = %x\n", i->opcode[0]);
    printf("i.modrm = %lx\n", i->displacement);
    insn_free(i);
    
    printf(" ----- Test 2: tree of insn -----\n");
    instruction_t *insns[5];
    node_t *tree;
    tree_init(&tree);
    for (int j = 0; j < 5; j++) {
        insns[j] = insn_new();
        insns[j]->addr = j;
        insns[j]->opcode[0] = 0x50 + j;
        insns[j]->modrm = j;
        tree_insert(&tree, insns[j]);
    }
    tree_traverse(tree);

    return 0;
}
