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

const char *decode_register(unsigned short reg) {
	switch (reg) {
		case REG_EAX:
			return "eax";
		case REG_EBX:
			return "ebx";
		case REG_ECX:
			return "ecx";
		case REG_EDX:
			return "edx";
		case REG_ESP:
			return "esp";
		case REG_EBP:
			return "ebp";
		case REG_ESI:
			return "esi";
		case REG_EDI:
			return "edi";
		default:
			printf("%s: INVALID REGISTER\n", __FUNCTION__);
			return NULL;
	}
}

/* Pseudocode for parsing an instruction:
 * 
 *
 * parse_next_instruction():
 * call new_instruction() and get empty i.
 * while(not_done):
 *      if byte in prefix:
 *          i->prefix = byte
 *          continue
 *      else if byte in opcodes:
 *          // check for 0x0f (2 byte opcodes)
 *          i->opcode = byte
 *          parse_opcode()
 *      else:
 *          //invalid opcode
 *
 * check if byte is opcode, if so, set opcode in i
 */
