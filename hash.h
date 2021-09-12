#ifndef _HASH_H_
#define _HASH_H_
#define HASHFILE "instructions.txt"
#define HASHTABLESIZE 80// big enought for this project
enum op_encoding {
    MR,
    RM,
    MI,
    I,
    O,
    D
};

typedef struct hash_entry {
    unsigned char opcode[3];
    unsigned char opcode_name[16]; // TODO is 16 long enough for all opcode names?
    enum op_encoding encoding;
    struct hash_entry *next;
} hash_entry_t;

hash_entry_t *hash_lookup(unsigned char *op);
int build_hashtable(void);

#endif
