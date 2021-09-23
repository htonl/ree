#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include "hash.h"
#include "tree.h"
#include "instruction.h"

// Max buffer for input file data
// We will continually read, so file can be bigger than this buf
#define FILEBUFSIZE 1024 // TODO 1K ? handle giant file
// Registers
#define REG_EAX 0
#define REG_ECX 1 
#define REG_EDX 2
#define REG_EBX 3
#define REG_ESP 4
#define REG_EBP 5
#define REG_ESI 6
#define REG_EDI 7

void print_usage() {
    printf("Usage: ./ree -i FILENAME\n");
    printf("\n");
}

const char *decode_register(unsigned char reg) {
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

void set_displacement_32(unsigned int *displacement, unsigned char *buf, unsigned int *cur) {
    *displacement += buf[*cur];
    *cur += 1;
    *displacement += (buf[*cur] << 8);
    *cur += 1;
    *displacement += (buf[*cur] << 16);
    *cur += 1;
    *displacement += (buf[*cur] << 24);
    *cur += 1;
}

void set_displacement_8(unsigned int *displacement, unsigned char *buf, unsigned int *cur) {
    *displacement += buf[*cur];
    *cur += 1;
}

/* Shhhh don't tell, I'm not keeping with my own convention...
 * Good thing I'm the only one reading this code ;)
 */
void set_immediate(instruction_t *insn, unsigned char *buf, unsigned int *cur) {
    // retf 0xca & 0xc2 require iw not id
    if (insn->opcode[0] == 0xca || insn->opcode[0] == 0xc2) {
        insn->immediate += buf[*cur];
        *cur += 1;
        insn->immediate += (buf[*cur] << 8);
        *cur += 1;
    } else {
        insn->immediate += buf[*cur];
        *cur += 1;
        insn->immediate += (buf[*cur] << 8);
        *cur += 1;
        insn->immediate += (buf[*cur] << 16);
        *cur += 1;
        insn->immediate += (buf[*cur] << 24);
        *cur += 1;
    }
}

typedef struct modrm {
    unsigned char mode;
    unsigned char r;
    unsigned char m;
} modrm_t;

modrm_t parse_modrm(instruction_t *insn, unsigned char *buf, unsigned int *cur)
{
    modrm_t ret;
    unsigned char modrm = insn->modrm;
    unsigned int displacement = 0;
    // Parse the modrm bytes to get the fields
    ret.mode = modrm >> 6; // Want top 2 bits
    ret.r = (modrm & 0x38) >> 3; // Want next 3 S bits
    ret.m = modrm & 0x07; // Want LS bits
    
    switch (ret.mode) {
        case 0:
            if (ret.m == 5) {
                //special case displacement
                set_displacement_32(&displacement, buf, cur);
                insn_set_displacement(insn, displacement);
            } 
            // memory address in r/m register
            break;
        case 1:
            // r/m operand's mem addr is in r/m + 1-byte displacement
            set_displacement_8(&displacement, buf, cur);
            insn_set_displacement(insn, displacement);
            break;
        case 2:
            set_displacement_32(&displacement, buf, cur);
            insn_set_displacement(insn, displacement);
            break;
        case 3:
            break;
        default:
            fprintf(stderr, "%s: can't get here? ERR parsing modrm mode\n", __FUNCTION__);
    }
    return ret;
}

/* returns the opcode[3] bytes for this instruction
 * Note: Currently either 2-byte opcode (no 3-byte ops are supported)
 * OR the 1-byte opcode + register encoded as byte value
 */
static unsigned char *get_opcode(unsigned char *buf, unsigned int *cur)
{
    unsigned char opcode[3] = {0};
    // Handle 0x0f two byte instructions
    if (buf[*cur] == 0xf0) {
        opcode[0] = buf[*cur];
        *cur += 1;
        opcode[1] = buf[*cur];
        return opcode;
    }
    // Handle reg addition special cases
    // Use second byte of the opcode to store the register byte
    // instruction will handle setting the struct member
    if (buf[*cur] >= 0x48 && buf[*cur] <= 0x4f) {
        opcode[0] = 0x48;
        opcode[1] = buf[*cur] - 0x48;
    } else if (buf[*cur] >= 0x40 && buf[*cur] <= 0x47) {
        opcode[0] = 0x40;
        opcode[1] = buf[*cur] - 0x40;
    } else if (buf[*cur] >= 0x58 && buf[*cur] <= 0x5f) {
        opcode[0] = 0x58;
        opcode[1] = buf[*cur] - 0x58;
    } else if (buf[*cur] >= 0x50 && buf[*cur] <= 0x57) {
        opcode[0] = 0x50;
        opcode[1] = buf[*cur] - 0x50;
    } else if (buf[*cur] >= 0xb8 && buf[*cur] <= 0xbf) {
        opcode[0] = 0xb8;
        opcode[1] = buf[*cur] - 0xb8;
    } else {
        // Nothing special just take the *current byte
        opcode[0] = buf[*cur]
    }
    return opcode
}

// Returns the updated cur pointer
static unsigned int fill_from_hash(instruction_t *insn, unsigned char *buf, unsigned int *cur)
{
    unsigned char modrm_byte = 0;
    hash_entry_t *he;
    he = hash_lookup(insn->opcode);
    if (!he) {
        fprintf(stderr, "%s: unrecognized instruction: %x", __FUNCTION__, insn->opcode);
        return -1;
    }
    if (NULL == he->next) {
        // opcode match already given, and no next so only hash hit.
        goto fill;
    }
    /* 2 cases: 1) We need to also match on a prefix / value
     *          2) We have a collision between 2 distinct opcodes
     *
     * If we are case 1, then he->prefix will be >= 0, since multiple
     * opcode entries need to have unique prefixes.
     *
     * If we are case 2, then we already have the right he. Since there is
     * only 1 entry in this list with this opcode. This is also check in the
     * prefix check, since if it is unique, prefix will be -1 (or r).
     */
    if (he->prefix >= 0) {
        modrm_byte = buf[*cur];
        *cur += 1;
        while(he) {
            if (modrm_byte == he->prefix) // This comparison should be fine. 
                break;               // modrm will be upcasted to int
            he = he->next;           // TODO not sure about other arch's
        }
    }
fill:
    modrm_t modrm;
    char *mnemonic;
    // *he should be right
    // Parse based on op encoding of the opcode
    switch (he->encoding) {
        case M:
            // did we already set modrm_byte?
            if (he->prefix < 0)
                modrm_byte = buf[*cur++];
            insn_set_modrm(insn, modrm_byte);
            modrm = parse_modrm(insn, buf, cur);
            // We should have everything to build the mnemonic
            
            // Allocate a buffer for the mnemonic 64 seems like a safe bet
            mnemonic = malloc(64); // TODO why 64???
            if (!mnemonic) {
                fprintf(stderr, "%s: OOM allocating mnemonic\n", __FUNCTION__);
                exit(-1);
            }
            switch (modrm.mode) {
                case 0: // 00
                    if (modrm.m == 5) {        
                        snprintf(mnemonic, sizeof(mnemonic), "%s [%08x]",
                                he->opcode_name, insn->displacement);
                    }
                    snprintf(mnemonic, sizeof(mnemonic), "%s [%s]",
                            he->opcode_name, decode_register(modrm.m));
                    break;
                case 1: // 01
                    snprintf(mnemonic, sizeof(mnemonic), "%s [%s + %02x]",
                            he->opcode_name, decode_register(modrm.m),
                            insn->displacement);
                    break;
                case 2: // 10
                    snprintf(mnemonic, sizeof(mnemonic), "%s [%s + %08x]",
                            he->opcode_name, decode_register(modrm.m));
                    break;
                case 3: // 11
                    snprintf(mnemonic, sizeof(mnemonic), "%s %s",
                            he->opcde_name, decode_register(modrm.m));
                    break;
                default:
                    fprintf(stderr, "%s: Can't get here\n", __FUNCTION__);
                    exit(-1);
            }
            break; // CASE M
        case MR:
            // did we already set modrm_byte?
            if (he->prefix < 0)
                modrm_byte = buf[*cur++];
            insn_set_modrm(insn, modrm_byte);
            modrm = parse_modrm(insn, buf, cur);
            // We should have everything to build the mnemonic
            
            // Allocate a buffer for the mnemonic
            // guess is 64 bytes
            mnemonic = malloc(64);
            if (!mnemonic) {
                fprintf(stderr, "%s: OOM allocating mnemonic\n", __FUNCTION__);
                exit(-1);
            }
            switch (modrm.mode) {
                case 0: // 00
                    if (modrm.m == 5) {        
                        snprintf(mnemonic, sizeof(mnemonic), "%s [%08x], %s",
                                he->opcode_name, insn->displacement, decode_register(modrm.r));
                    }
                    snprintf(mnemonic, sizeof(mnemonic), "%s [%s], %s",
                            he->opcode_name, decode_register(modrm.m), decode_register(modrm.r));
                    break;
                case 1: // 01
                    snprintf(mnemonic, sizeof(mnemonic), "%s [%s + %02x], %s",
                            he->opcode_name, decode_register(modrm.m),
                            insn->displacement, decode_register(modrm.r));
                    break;
                case 2: // 10
                    snprintf(mnemonic, sizeof(mnemonic), "%s [%s + %08x], %s",
                            he->opcode_name, decode_register(modrm.m), decode_register(modrm.r));
                    break;
                case 3: // 11
                    snprintf(mnemonic, sizeof(mnemonic), "%s %s, %s",
                            he->opcde_name, decode_register(modrm.m), decode_register(modrm.r));
                    break;
                default:
                    fprintf(stderr, "%s: Can't get here\n", __FUNCTION__);
                    exit(-1);
            }
            break;
        case MI:
            // did we already set modrm_byte?
            if (he->prefix < 0)
                modrm_byte = buf[*cur++];
            insn_set_modrm(insn, modrm_byte);
            modrm = parse_modrm(insn, buf, cur);
            /* Immediate must be next in the buffer because parse_modrm
             * handles the displacement for us
             */
            set_immediate(insn, buf, cur);
            // We should have everything to build the mnemonic
            
            // Allocate a buffer for the mnemonic
            // guess is 64 bytes
            mnemonic = malloc(64);
            if (!mnemonic) {
                fprintf(stderr, "%s: OOM allocating mnemonic\n", __FUNCTION__);
                exit(-1);
            }
            switch (modrm.mode) {
                case 0: // 00
                    if (modrm.m == 5) {        
                        snprintf(mnemonic, sizeof(mnemonic), "%s [%08x], %08x",
                                he->opcode_name, insn->displacement, insn->immediate);
                    }
                    snprintf(mnemonic, sizeof(mnemonic), "%s [%s], %08x",
                            he->opcode_name, decode_register(modrm.m), insn->immediate);
                    break;
                case 1: // 01
                    snprintf(mnemonic, sizeof(mnemonic), "%s [%s + %02x], %08x",
                            he->opcode_name, decode_register(modrm.m),
                            insn->displacement, insn->immediate);
                    break;
                case 2: // 10
                    snprintf(mnemonic, sizeof(mnemonic), "%s [%s + %08x], %08x",
                            he->opcode_name, decode_register(modrm.m), insn->immediate);
                    break;
                case 3: // 11
                    snprintf(mnemonic, sizeof(mnemonic), "%s %s, %08x",
                            he->opcde_name, decode_register(modrm.m), insn->immediate);
                    break;
                default:
                    fprintf(stderr, "%s: Can't get here\n", __FUNCTION__);
                    exit(-1);
            }
            break;
        case RM:
            // did we already set modrm_byte?
            if (he->prefix < 0)
                modrm_byte = buf[*cur++];
            insn_set_modrm(insn, modrm_byte);
            modrm = parse_modrm(insn, buf, cur);
            // We should have everything to build the mnemonic
            
            // Allocate a buffer for the mnemonic
            // guess is 64 bytes
            mnemonic = malloc(64);
            if (!mnemonic) {
                fprintf(stderr, "%s: OOM allocating mnemonic\n", __FUNCTION__);
                exit(-1);
            }
            switch (modrm.mode) {
                case 0: // 00
                    if (modrm.m == 5) {        
                        snprintf(mnemonic, sizeof(mnemonic), "%s [%08x], %s",
                                he->opcode_name, insn->displacement, decode_register(modrm.r));
                    }
                    snprintf(mnemonic, sizeof(mnemonic), "%s [%s], %s",
                            he->opcode_name, decode_register(modrm.m), decode_register(modrm.r));
                    break;
                case 1: // 01
                    snprintf(mnemonic, sizeof(mnemonic), "%s [%s + %02x], %s",
                            he->opcode_name, decode_register(modrm.m),
                            insn->displacement, decode_register(modrm.r));
                    break;
                case 2: // 10
                    snprintf(mnemonic, sizeof(mnemonic), "%s [%s + %08x], %s",
                            he->opcode_name, decode_register(modrm.m), decode_register(modrm.r));
                    break;
                case 3: // 11
                    snprintf(mnemonic, sizeof(mnemonic), "%s %s, %s",
                            he->opcde_name, decode_register(modrm.m), decode_register(modrm.r));
                    break;
                default:
                    fprintf(stderr, "%s: Can't get here\n", __FUNCTION__);
                    exit(-1);
            }
            break;
        case RMI:
            // did we already set modrm_byte?
            if (he->prefix < 0)
                modrm_byte = buf[*cur++];
            insn_set_modrm(insn, modrm_byte);
            modrm = parse_modrm(insn, buf, cur);
            // We should have everything to build the mnemonic
            
            // Allocate a buffer for the mnemonic
            // 9 for the addr, 15 max bytes of instruction, max mnemonic (safe
            // guess is 64 bytes)
            mnemonic = malloc(9 + 15 + 64);
            if (!mnemonic) {
                fprintf(stderr, "%s: OOM allocating mnemonic\n", __FUNCTION__);
                exit(-1);
            }
            break;
        case O:
        case OI:
        case ZO:
        case I:
        case D:
        default:
    }

}

unsigned int disass_buf(unsigned char *buf) {
    unsigned int prev = 0, cur = 0, addr = 0;
    unsigned char opcode[3];
    int ret;
    instruction_t *insn;
    while (cur < FILEBUFSIZE) {
        insn = malloc(sizeof(instruction_t));
        if (NULL == insn) {
            fprintf(stderr, "%s Unable to allocate next instruction\n", __FUNCTION__);
            exit(1);
        }
        insn_set_addr(insn, addr);
        opcode = get_opcode(buf, &cur);
        // Advance cur by 1 byte as we read 1 (or 2) bytes and advanced
        // accordingly
        cur += 1;
        insn_set_opcode(insn, opcode);
        // fill in what we know from the hashtable entry for this opcode
        // fill_from_hash needs the data buf in case there is a prefix to parse
        prev = cur;
        ret = fill_from_hash(insn, buf, &cur);
        addr += (cur - prev);
        if (ret < 0)
            goto err;
    }
    return 0;
}

void disass_file(filename) {
    FILE *fp;
    unsigned char *buffer;

    fp = fopen(filename, "rb");
    if (NULL == fp) {
        fprintf(stderr, "%s: Cannot open input file: %s\n", __FUNCTION__, filename);
        exit(1);
    }
    buffer = malloc(FILEBUFSIZE);
    if (NULL == buffer) {
        fprintf(stderr, "%s: Cannot allocate file buffer: %s\n", __FUNCTION__, filename);
        exit(1);
    }
    while(next) {
        fread(buffer, FILEBUFSIZE, 1, fp);
        next = disass_buf(buffer);
    }
    fclose(fp);
}

int main(int argc, char **argv) {
    char *filename = NULL;
    int c, ret;
    // Parse arguments
    while ((c = getopt (argc, argv, "i:")) != -1)
    switch (c)
      {
      case 'i':
        filename = optarg;
        break;
      case '?':
        if (optopt == 'c')
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        else if (isprint (optopt))
          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf (stderr,
                   "Unknown option character `\\x%x'.\n",
                   optopt);
        return 1;
      default:
        abort ();
      }
    if (NULL == filename) {
        fprintf (stderr, "Filename not provided\n");
        print_usage();
        abort();
    }
    printf("Disassembling filename: %s\n", filename);
    ret = build_hashtable();
    disass_file(filename);
    
    if (ret) {
        fprintf(stderr, "Error building the hashtable, check instructions.txt\n");
        abort();
    }
}
