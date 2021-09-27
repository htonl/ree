#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "instruction.h"

instruction_t *insn_new() {
    instruction_t *i = malloc(INSTRUCTION_SIZE);
    if (!i) {
        printf("%s can't malloc new instruction_t\n", __FUNCTION__);
        return NULL;
    }
    memset(i, 0, INSTRUCTION_SIZE);
    return i;
}

void insn_free(instruction_t *i) {
    if (i->mnemonic != NULL)
        free(i->mnemonic);
    free(i);
}


