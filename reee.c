#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include "hash.h"
#include "tree.h"
#include "instruction.h"

// Max buffer for input file data
// We will continually read, so file can be bigger than this buf
#define FILEBUFSIZE 10 * 1024 // TODO 1K ? handle giant file
#define MAXMNEMONICSIZE 8 * 8 //in bytes
// Registers
#define REG_EAX 0
#define REG_ECX 1 
#define REG_EDX 2
#define REG_EBX 3
#define REG_ESP 4
#define REG_EBP 5
#define REG_ESI 6
#define REG_EDI 7

node_t *insn_tree; // Binary tree to hold the instruction_t's before we print them

void print_usage() {
    printf("Usage: ./ree -i FILENAME\n");
    printf("\n");
}

const char *decode_register(unsigned char reg) {
#ifdef DEBUG
    printf("%s\n", __FUNCTION__);
#endif
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
#ifdef DEBUG
    printf("%s\n", __FUNCTION__);
#endif
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
#ifdef DEBUG
    printf("%s\n", __FUNCTION__);
#endif
    *displacement += buf[*cur];
    *cur += 1;
}

/* Shhhh don't tell, I'm not keeping with my own convention...
 * Good thing I'm the only one reading this code ;)
 */
void set_immediate(instruction_t *insn, unsigned char *buf, unsigned int *cur) {
#ifdef DEBUG
    printf("%s\n", __FUNCTION__);
#endif
    if (insn->opcode[0] == 0x74 || insn->opcode[0] == 0x75) {
        insn->immediate += buf[*cur];
        *cur += 1;
    } else if (insn->opcode[0] == 0xca || insn->opcode[0] == 0xc2) {
    // retf 0xca & 0xc2 require iw not id
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

typedef struct {
    unsigned char mode;
    unsigned char r;
    unsigned char m;
} modrm_t;

modrm_t parse_modrm(instruction_t *insn, unsigned char *buf, unsigned int *cur)
{
    modrm_t ret;
    unsigned char modrm = insn->modrm;
    unsigned int displacement = 0;
#ifdef DEBUG
    printf("%s\n", __FUNCTION__);
#endif
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
 * OR the 1-byte opcode + register prefix encoded as byte value
 */
static unsigned int set_opcode(instruction_t *insn, unsigned char *buf, unsigned int *cur)
{
    unsigned char opcode[3] = {0};
#ifdef DEBUG
    printf("%s\n", __FUNCTION__);
#endif
    // Handle 0x0f two byte instructions
    if (buf[*cur] == 0xf0) {
        opcode[0] = buf[*cur];
        *cur += 1;
        opcode[1] = buf[*cur];
    }
    // Handle reg addition special cases
    // Use second byte of the opcode to store the register byte
    // instruction will handle setting the struct member
    else if (buf[*cur] >= 0x48 && buf[*cur] <= 0x4f) {
        opcode[0] = 0x48;
        insn->reg = buf[*cur] - 0x48;
    } else if (buf[*cur] >= 0x40 && buf[*cur] <= 0x47) {
        opcode[0] = 0x40;
        insn->reg = buf[*cur] - 0x40;
    } else if (buf[*cur] >= 0x58 && buf[*cur] <= 0x5f) {
        opcode[0] = 0x58;
        insn->reg = buf[*cur] - 0x58;
    } else if (buf[*cur] >= 0x50 && buf[*cur] <= 0x57) {
        opcode[0] = 0x50;
        insn->reg = buf[*cur] - 0x50;
    } else if (buf[*cur] >= 0xb8 && buf[*cur] <= 0xbf) {
        opcode[0] = 0xb8;
        insn->reg = buf[*cur] - 0xb8;
    } else {
        // Nothing special just take the *current byte
        opcode[0] = buf[*cur];
    }
    *cur += 1;
    insn_set_opcode(insn, opcode);
    return 0;
}

// cur properly updated
static unsigned int fill_from_hash(instruction_t *insn, unsigned char *buf, unsigned int *cur)
{
    unsigned char modrm_byte = 0;
    hash_entry_t *he;
    char *mnemonic;
    modrm_t modrm;
#ifdef DEBUG
    printf("%s\n", __FUNCTION__);
#endif

    he = hash_lookup(insn->opcode);
    if (!he) {
        fprintf(stderr, "%s: unrecognized instruction: %02x %02x %02x\n", __FUNCTION__, insn->opcode[0],
                insn->opcode[1], insn->opcode[2]);
        return -1;
    }
    if (NULL == he->next) {
        // opcode match already given, and no next so only hash hit.
        goto fill;
    }
    /* 2 cases right here: 1) We need to also match on a prefix / value
     *                     2) We have a collision between 2 distinct opcodes
     *
     * If we are case 1, then he->prefix will be >= 0, since multiple
     * opcode entries need to have unique prefixes.
     *
     * If we are case 2, then we already have the right *he. Since there is
     * only 1 entry in this list with this opcode. This is also check in the
     * prefix check, since if it is unique, prefix will be -1 (or r).
     */
    // CASE 1
    if (he->prefix >= 0) {
        modrm_byte = buf[*cur];
        *cur += 1;
        while(he) {
            if ((modrm_byte & 0x7) == he->prefix) // TODO This comparison should be fine?
                break;                       
            he = he->next; 
        }
    }
    // CASE 2 no check needed he already good
fill:
    // *he should be right here
    // Parse based on op encoding of the opcode
    switch (he->encoding) {
        case M:
            // did we already set modrm_byte?
            if (he->prefix < 0) {
                // TODO this check is ugly, make this more readable
                modrm_byte = buf[*cur];
                *cur += 1;
            }
            insn_set_modrm(insn, modrm_byte);
            modrm = parse_modrm(insn, buf, cur);
            // We should have everything to build the mnemonic
            
            // Allocate a buffer for the mnemonic 64 seems like a safe bet
            mnemonic = malloc(MAXMNEMONICSIZE); // TODO why 64???
            if (!mnemonic) {
                fprintf(stderr, "%s: OOM allocating mnemonic\n", __FUNCTION__);
                exit(-1);
            }
            switch (modrm.mode) {
                case 0: // 00
                    if (modrm.m == 5) {        
                        snprintf(mnemonic, MAXMNEMONICSIZE, "%s [%08x]",
                                he->opcode_name, insn->displacement);
                    }
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s [%s]",
                            he->opcode_name, decode_register(modrm.m));
                    break;
                case 1: // 01
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s [%s + %02x]",
                            he->opcode_name, decode_register(modrm.m),
                            insn->displacement);
                    break;
                case 2: // 10
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s [%s + %08x]",
                            he->opcode_name, decode_register(modrm.m),
                            insn->displacement);
                    break;
                case 3: // 11
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s %s",
                            he->opcode_name, decode_register(modrm.m));
                    break;
                default:
                    fprintf(stderr, "%s: Can't get here\n", __FUNCTION__);
                    exit(-1);
            }
            break; // CASE M
        case MR:
            // did we already set modrm_byte?
            if (he->prefix < 0) {
                modrm_byte = buf[*cur];
                *cur += 1;
            }
            insn_set_modrm(insn, modrm_byte);
            modrm = parse_modrm(insn, buf, cur);
            // We should have everything to build the mnemonic
            
            // Allocate a buffer for the mnemonic
            // guess is MAXMNEMONICSIZE bytes
            mnemonic = malloc(MAXMNEMONICSIZE);
            if (!mnemonic) {
                fprintf(stderr, "%s: OOM allocating mnemonic\n", __FUNCTION__);
                exit(-1);
            }
            switch (modrm.mode) {
                case 0: // 00
                    if (modrm.m == 5) {        
                        snprintf(mnemonic, MAXMNEMONICSIZE, "%s [%08x], %s",
                                he->opcode_name, insn->displacement, decode_register(modrm.r));
                    }
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s [%s], %s",
                            he->opcode_name, decode_register(modrm.m), decode_register(modrm.r));
                    break;
                case 1: // 01
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s [%s + %02x], %s",
                            he->opcode_name, decode_register(modrm.m),
                            insn->displacement, decode_register(modrm.r));
                    break;
                case 2: // 10
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s [%s + %08x], %s",
                            he->opcode_name, decode_register(modrm.m), insn->displacement,
                            decode_register(modrm.r));
                    break;
                case 3: // 11
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s %s, %s",
                            he->opcode_name, decode_register(modrm.m), decode_register(modrm.r));
                    break;
                default:
                    fprintf(stderr, "%s: Can't get here\n", __FUNCTION__);
                    exit(-1);
            }
            break; // CASE MR
        case MI:
            // did we already set modrm_byte?
            if (he->prefix < 0) {
                modrm_byte = buf[*cur];
                *cur += 1;
            }
            insn_set_modrm(insn, modrm_byte);
            modrm = parse_modrm(insn, buf, cur);
            /* Immediate must be next in the buffer because parse_modrm
             * handles the displacement for us
             */
            set_immediate(insn, buf, cur);
            // We should have everything to build the mnemonic
            
            // Allocate a buffer for the mnemonic
            // guess is 64 bytes
            mnemonic = malloc(MAXMNEMONICSIZE);
            if (!mnemonic) {
                fprintf(stderr, "%s: OOM allocating mnemonic\n", __FUNCTION__);
                exit(-1);
            }
            switch (modrm.mode) {
                case 0: // 00
                    if (modrm.m == 5) {        
                        snprintf(mnemonic, MAXMNEMONICSIZE, "%s [%08x], %08x",
                                he->opcode_name, insn->displacement, insn->immediate);
                    }
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s [%s], %08x",
                            he->opcode_name, decode_register(modrm.m), insn->immediate);
                    break;
                case 1: // 01
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s [%s + %02x], %08x",
                            he->opcode_name, decode_register(modrm.m),
                            insn->displacement, insn->immediate);
                    break;
                case 2: // 10
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s [%s + %08x], %08x",
                            he->opcode_name, decode_register(modrm.m), insn->displacement,
                            insn->immediate);
                    break;
                case 3: // 11
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s %s, %08x",
                            he->opcode_name, decode_register(modrm.m), insn->immediate);
                    break;
                default:
                    fprintf(stderr, "%s: Can't get here\n", __FUNCTION__);
                    exit(-1);
            }
            break; // CASE MI
        case RM:
            // did we already set modrm_byte?
            if (he->prefix < 0) {
                modrm_byte = buf[*cur];
                *cur += 1;
            }
            insn_set_modrm(insn, modrm_byte);
            modrm = parse_modrm(insn, buf, cur);
            // We should have everything to build the mnemonic
            
            // Allocate a buffer for the mnemonic
            // guess is 64 bytes
            mnemonic = malloc(MAXMNEMONICSIZE);
            if (!mnemonic) {
                fprintf(stderr, "%s: OOM allocating mnemonic\n", __FUNCTION__);
                exit(-1);
            }
            switch (modrm.mode) {
                case 0: // 00
                    if (modrm.m == 5) {        
                        snprintf(mnemonic, MAXMNEMONICSIZE, "%s %s, [%08x]",
                                he->opcode_name, decode_register(modrm.r), insn->displacement);
                    }
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s %s, [%s]",
                            he->opcode_name, decode_register(modrm.r), decode_register(modrm.m));
                    break;
                case 1: // 01
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s %s, [%s + %02x]",
                            he->opcode_name, decode_register(modrm.m),
                            decode_register(modrm.r), insn->displacement);
                    break;
                case 2: // 10
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s %s, [%s + %08x]",
                            he->opcode_name, decode_register(modrm.r), decode_register(modrm.m),
                            insn->displacement);
                    break;
                case 3: // 11
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s %s, %s",
                            he->opcode_name, decode_register(modrm.m), decode_register(modrm.r));
                    break;
                default:
                    fprintf(stderr, "%s: Can't get here\n", __FUNCTION__);
                    exit(-1);
            }
            break; // CASE RM
        case RMI:
            // did we already set modrm_byte?
            if (he->prefix < 0) {
                modrm_byte = buf[*cur];
                *cur += 1;
            }
            insn_set_modrm(insn, modrm_byte);
            modrm = parse_modrm(insn, buf, cur);
            /* Immediate must be next in the buffer because parse_modrm
             * handles the displacement for us
             */
            set_immediate(insn, buf, cur);
            // We should have everything to build the mnemonic
            
            // Allocate a buffer for the mnemonic
            // guess is 64 bytes)
            mnemonic = malloc(MAXMNEMONICSIZE);
            if (!mnemonic) {
                fprintf(stderr, "%s: OOM allocating mnemonic\n", __FUNCTION__);
                exit(-1);
            }
            switch (modrm.mode) {
                case 0: // 00
                    if (modrm.m == 5) {        
                        snprintf(mnemonic, MAXMNEMONICSIZE, "%s %s, [%08x], %08x",
                                he->opcode_name, decode_register(modrm.r), insn->displacement,
                                insn->immediate);
                    }
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s %s, [%s], %08x",
                            he->opcode_name, decode_register(modrm.r), decode_register(modrm.m),
                            insn->immediate);
                    break;
                case 1: // 01
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s %s, [%s + %02x], %08x",
                            he->opcode_name, decode_register(modrm.m),
                            decode_register(modrm.r), insn->displacement,
                            insn->immediate);
                    break;
                case 2: // 10
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s %s, [%s + %08x], %08x",
                            he->opcode_name, decode_register(modrm.r), decode_register(modrm.m),
                            insn->displacement, insn->immediate);
                    break;
                case 3: // 11
                    snprintf(mnemonic, MAXMNEMONICSIZE, "%s %s, %s, %08x",
                            he->opcode_name, decode_register(modrm.m), decode_register(modrm.r),
                            insn->immediate);
                    break;
                default:
                    fprintf(stderr, "%s: Can't get here\n", __FUNCTION__);
                    exit(-1);
            }
            break; // CASE RMI
        case O:
            // Easier case, no modrm to parse
            // Just append opcode_name and the decoded register (stored in
            // opcode[1]
            mnemonic = malloc(MAXMNEMONICSIZE);
            if (!mnemonic) {
                fprintf(stderr, "%s: OOM allocating mnemonic\n", __FUNCTION__);
                exit(-1);
            }
            snprintf(mnemonic, MAXMNEMONICSIZE, "%s %s", he->opcode_name,
                    decode_register(insn->reg));
            break; // CASE O
        case OI:
            // Easier case again, no modrm to parse
            // Just grab immediate first, then just like O case
            set_immediate(insn, buf, cur);
            mnemonic = malloc(MAXMNEMONICSIZE);
            if (!mnemonic) {
                fprintf(stderr, "%s: OOM allocating mnemonic\n", __FUNCTION__);
                exit(-1);
            }
            snprintf(mnemonic, MAXMNEMONICSIZE, "%s %s, %08x", he->opcode_name,
                    decode_register(insn->reg), insn->immediate);
            break; // CASE OI
        case ZO:
            // Simplest case, no operands
            mnemonic = malloc(MAXMNEMONICSIZE);
            if (!mnemonic) {
                fprintf(stderr, "%s: OOM allocating mnemonic\n", __FUNCTION__);
                exit(-1);
            }
            snprintf(mnemonic, MAXMNEMONICSIZE, "%s", he->opcode_name);
            break; // CASE ZO
        case I:
            // Just an immediate value
            set_immediate(insn, buf, cur);
            mnemonic = malloc(MAXMNEMONICSIZE);
            if (!mnemonic) {
                fprintf(stderr, "%s: OOM allocating mnemonic\n", __FUNCTION__);
                exit(-1);
            }
            snprintf(mnemonic, MAXMNEMONICSIZE, "%s %08x", he->opcode_name,
                    insn->immediate);
            break; // CASE I
        case D:
            // These are CF instructions for now just
            // print the cd as ib/id
            set_immediate(insn, buf, cur);
            mnemonic = malloc(MAXMNEMONICSIZE);
            if (!mnemonic) {
                fprintf(stderr, "%s: OOM allocating mnemonic\n", __FUNCTION__);
                exit(-1);
            }
            if (he->opcode[0] == 0x74 || he->opcode[0] == 0x75) {
                snprintf(mnemonic, MAXMNEMONICSIZE, "%s %02x", he->opcode_name,
                    insn->immediate);
            } else {
                snprintf(mnemonic, MAXMNEMONICSIZE, "%s %08x", he->opcode_name,
                    insn->immediate);
            }
            break; // CASE I

        default:
            fprintf(stderr, "%s: default op_encoding. Can't get here\n", __FUNCTION__);
    }
    insn->mnemonic = mnemonic;
    return 0;
}

unsigned int disass_buf(unsigned char *buf, unsigned int filesize) {
    unsigned int cur = 0, addr = 0;
    unsigned char opcode[3];
    int ret;
    instruction_t *insn;
#ifdef DEBUG
    printf("%s\n", __FUNCTION__);
#endif
    while (cur < FILEBUFSIZE && cur < filesize) {
        insn = insn_new();
        if (NULL == insn) {
            fprintf(stderr, "%s Unable to allocate next instruction\n", __FUNCTION__);
            exit(1);
        }
        insn_set_addr(insn, addr);
        set_opcode(insn, buf, &cur);
        // fill in what we know from the hashtable entry for this opcode
        // fill_from_hash needs the data buf in case there is a prefix to parse
        ret = fill_from_hash(insn, buf, &cur); // TODO error handling on bad ret
        addr += (cur - insn->addr);
        tree_insert(&insn_tree, insn);
    }
    return 0;
}

void disass_file(char *filename) {
    FILE *fp;
    unsigned char *buffer;
    unsigned int filesize;
    int next = 1;

#ifdef DEBUG
    printf("%s\n", __FUNCTION__);
#endif
    fp = fopen(filename, "rb");
    if (NULL == fp) {
        fprintf(stderr, "%s: Cannot open input file: %s\n", __FUNCTION__, filename);
        exit(1);
    }
    // get file size
    fseek(fp, 0L, SEEK_END);
    filesize = ftell(fp);
    rewind(fp);
    buffer = malloc(FILEBUFSIZE);
    if (NULL == buffer) {
        fprintf(stderr, "%s: Cannot allocate file buffer: %s\n", __FUNCTION__, filename);
        exit(1);
    }
    while(next) {
        fread(buffer, FILEBUFSIZE, 1, fp);
        next = disass_buf(buffer, filesize);
        tree_traverse(insn_tree);
        tree_free(insn_tree);
    }
    fclose(fp);
}

int main(int argc, char **argv) {
    char *filename = NULL;
    int c, ret;
    // Parse arguments
#ifdef DEBUG
    printf("%s\n", __FUNCTION__);
#endif
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
    // build the hashtable of supported instructions
    ret = build_hashtable();
    // initialize the instruction tree
    insn_tree = NULL;
    disass_file(filename);
    
    if (ret) {
        fprintf(stderr, "Error building the hashtable, check instructions.txt\n");
        abort();
    }
}
