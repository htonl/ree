#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include "hash.h"
#include "tree.h"
#include "instruction.h"

void print_usage() {
    printf("Usage: ./ree -i FILENAME\n");
    printf("\n");
}

int main(int argc, char **argv) {
    FILE *fp;
    char *filename = NULL;
    int c, ret;
    hash_entry_t *tmp;
    unsigned char op[3] = {0};
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
    op[0] = 0x81;
    tmp = hash_lookup(op);
    print_all_entries(tmp);
    op[0] = 0xe8;
    tmp = hash_lookup(op);
    print_all_entries(tmp);
    op[0] = 0xb8;
    tmp = hash_lookup(op);
    print_all_entries(tmp);
    if (ret) {
        fprintf(stderr, "Error building the hashtable, check instructions.txt\n");
        abort();
    }
}
