#ifndef _HASH_H_
#define _HASH_H_
#define HASHFILE "instructions.txt"
#define HASHTABLESIZE 100// big enought for this project
enum op_encoding {
    M,
    MR,
    MI,
    RM,
    RMI,
    O,
    OI,
    ZO,
    I,
    D
};

typedef struct hash_entry {
    unsigned char opcode[3];
    unsigned char opcode_name[16]; // 16 long enough for all supported opcode names
    enum op_encoding encoding;
    int prefix;
    struct hash_entry *next;
} hash_entry_t;

hash_entry_t *hash_lookup(unsigned char *op);
unsigned int get_num_entries(hash_entry_t *);
void print_all_entries(hash_entry_t *tmp);
int build_hashtable(void);

#endif
