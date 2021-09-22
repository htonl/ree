#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include "hash.h"
#include "tree.h"
#include "instruction.h"

// Max buffer for input file data
#define FILEBUFSIZE 10 * 1024 // TODO 10K ? handle giant file
// Registers
#define REG_EAX 0x000
#define REG_ECX 0x001
#define REG_EDX 0x010
#define REG_EBX 0x011
#define REG_ESP 0x100
#define REG_EBP 0x101
#define REG_ESI 0x110
#define REG_EDI 0x111

void print_usage() {
    printf("Usage: ./ree -i FILENAME\n");
    printf("\n");
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

void set_displacement(unsigned int *displacement, unsigned char *buf, unsigned int *cur) {
    *displacement += buf[*cur];
    *cur += 1;
    *displacement += (buf[*cur] << 8);
    *cur += 1;
    *displacement += (buf[*cur] << 16);
    *cur += 1;
    *displacement += (buf[*cur] << 24);
}
    

static unsigned char parse_modrm(instruction_t *insn, unsigned char *buf, unsigned int *cur, enum op_encoding encoding)
{
    unsigned char mode, r, m;
    unsigned 
    unsigned char modrm = insn->modrm;
    unsigned int displacement = 0;
    // Parse the modrm bytes to get the fields
    mode = modrm >> 6; // Want top 2 bits
    r = (modrm & 0x38) >> 3; // Want next 3 S bits
    m = modrm & 0x07; // Want LS bits
    
    switch (mode) {
        case 0:
            if (m == 5) {
                //special case displacement
                insn_set_displacement(&displacement, buf, cur);
            } else {
                 

     

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
    unsigned char modrm = 0;
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
        modrm = buf[*cur];
        *cur += 1;
        while(he) {
            if (modrm == he->prefix) // This comparison should be fine. 
                break;               // modrm will be upcasted to int
            he = he->next;           // TODO not sure about other arch's
        }
    }
fill:
    // *he should be right
    // Parse based on op encoding of the opcode
    switch (he->encoding) {
        // Do we have a modrm byte?
        case M:
        case MR:
        case MI:
        case R:
        case RM:
        case RMI:
            // did we already set local var:modrm?
            if (he->prefix < 0)
                modrm = buf[*cur++];
            insn_set_modrm(insn, modrm);
            parse_modrm(insn);
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
