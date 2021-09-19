#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include "hash.h"
#include "tree.h"
#include "instruction.h"
#define FILEBUFSIZE 10 * 1024 // TODO 10K ? handle giant file

void print_usage() {
    printf("Usage: ./ree -i FILENAME\n");
    printf("\n");
}

static unsigned char *get_opcode(unsigned char *buf, unsigned int *cur) {
    unsigned char opcode[3] = {0};
    // Handle 0x0f two byte instructions
    if (buf[cur] == 0xf0) {
        opcode[0] = buf[*cur];
        opcode[1] = buf[*cur++];
        return opcode;
    }
    // Handle reg addition special cases
    // Use second byte of the opcode to store the register byte
    // instruction will handle setting the struct member
    if (buf[cur] >= 0x48 && buf[cur] <= 0x4f) {
        opcode[0] = 0x48;
        opcode[1] = buf[cur] - 0x48;
    } else if (buf[cur] >= 0x40 && buf[cur] <= 0x47) {
        opcode[0] = 0x40;
        opcode[1] = buf[cur] - 0x40;
    } else if (buf[cur] >= 0x58 && buf[cur] <= 0x5f) {
        opcode[0] = 0x58;
        opcode[1] = buf[cur] - 0x58;
    } else if (buf[cur] >= 0x50 && buf[cur] <= 0x57) {
        opcode[0] = 0x50;
        opcode[1] = buf[cur] - 0x50;
    } else {
        // Nothing special just take the current byte
        opcode[0] = buf[cur]
    }
    return opcode
}

unsigned int disass_buf(unsigned char *buf) {
    unsigned int cur = 0, addr = 0;
    unsigned char opcode[3];
    hash_entry_t *he;
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
        cur++;
        insn_set_opcode(insn, opcode);
        // NEXT hash_lookup and continue parsing 
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
