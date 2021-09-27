#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "hash.h"

hash_entry_t hashtable[HASHTABLESIZE];

static unsigned long hash(unsigned int op) {
    op = ((op >> 16) ^ op) * 0x45d9f3b; // TODO cite this
    op = ((op >> 16) ^ op) * 0x45d9f33;
    op = (op >> 16) ^ op;
    return (op % HASHTABLESIZE);
}	

static void init_hashtable() {
    memset(hashtable, 0, sizeof(hashtable));
}

static void copy_entry(hash_entry_t *dest, hash_entry_t *src) {
    memcpy(dest->opcode, src->opcode, 4);
    memcpy(dest->opcode_name, src->opcode_name, 16);
    dest->encoding = src->encoding;
    dest->prefix = src->prefix;
}

static unsigned int get_hashable_op(unsigned char *op) {
    unsigned int hashable_op; 
    hashable_op = op[0];
    hashable_op << 8;
    hashable_op += op[1];
    hashable_op << 8;
    hashable_op += op[2];
    return hashable_op;
}
	
static int hash_insert(hash_entry_t *entry) {
    unsigned long idx;
    unsigned int hashable_op;
    hashable_op = get_hashable_op(entry->opcode);
    idx = hash(hashable_op);
    
    if (hashtable[idx].opcode[0] == 0) {
        // Not a collision
        copy_entry(&hashtable[idx], entry);
        return 0;
    }
    // Hash collision, allocate a new table entry for this op/enc/name
    hash_entry_t *tmp;
    tmp = &hashtable[idx];
    while(tmp->next != NULL)
        tmp = tmp->next;
    tmp->next = malloc(sizeof(hash_entry_t));
    if (!tmp->next) {
        printf("%s: Can't allocate hash_entry\n", __FUNCTION__);
        return -1;
    }
    memset(tmp->next, 0, sizeof(hash_entry_t));
    copy_entry(tmp->next, entry);
    return 0;
}

static enum op_encoding strtoop_encoding(char *tok) {
    enum op_encoding ret;
    if (!strncmp(tok,"M",strlen(tok))) {
        ret = M;
    } else if(!strncmp(tok,"MR",strlen(tok))) {
        ret = MR;
    } else if(!strncmp(tok,"MI",strlen(tok))) {
        ret = MI;
    } else if(!strncmp(tok,"RM",strlen(tok))) {
        ret = RM;
    } else if(!strncmp(tok,"RMI",strlen(tok))) {
        ret = RMI;
    } else if(!strncmp(tok,"I",strlen(tok))) {
        ret = I;
    } else if(!strncmp(tok,"O",strlen(tok))) {
        ret = O;
    } else if(!strncmp(tok,"OI",strlen(tok))) {
        ret = OI;
    } else if(!strncmp(tok,"ZO",strlen(tok))) {
        ret = ZO;
    } else if(!strncmp(tok,"D",strlen(tok))) {
        ret = D;
    } else {
        ret = -1;
    }
    return ret;
}

static int op_cmp(unsigned char *op1, unsigned char *op2) {
    int i;
    for (i = 0; i < 3; i++) {
        if (op1[i] != op2[i]) {
            return -1;
        }
    }
    return 0;
}

unsigned int get_num_entries(hash_entry_t *tmp) {
    unsigned int count = 1;
    if (!tmp)
        return 0;
    if (!tmp->next)
        return 1;
    while (tmp) {
        tmp = tmp->next;
        count++;
    }
    return count;
}

// Returns a pointer to the first hash match with same opcode
//
// Caller must parse the returned list for collisions
hash_entry_t *hash_lookup(unsigned char *op) {
    unsigned char zero[3] = {0};
    unsigned long idx;
    unsigned int hashable_op;
    hash_entry_t *tmp;
    hashable_op = get_hashable_op(op);
    idx = hash(hashable_op);
    // edge case, opcode is 0x00 not a valid opcode for this assignment
    if (!strncmp(hashtable[idx].opcode, zero, 3))
        return NULL;
    if (!strncmp(hashtable[idx].opcode, op, 3))
        return &hashtable[idx];
    else {
        tmp = &hashtable[idx];
        while(tmp && strncmp(tmp->opcode, op, 3)) {
            tmp = tmp->next;
        }
        return tmp;
    }
}

int build_hashtable(void) {
    FILE *fp;
    char *tok, *line = NULL;
    int op_counter = 0;
    size_t len = 0;
    ssize_t read;
    hash_entry_t *he;
    // Need temp holder of a hash_entry 
    he = malloc(sizeof(hash_entry_t));
    if (NULL == he) {
        fprintf(stderr, "%s: cannot allocate hash_entry\n", __FUNCTION__);
        exit(-1);
    }
    memset(he, 0, sizeof(hash_entry_t));
    fp = fopen(HASHFILE, "r");
    if (NULL == fp) {
        fprintf(stderr, "%s: Error opening instructions.txt\n", __FUNCTION__);
        exit(-1);
    }
    init_hashtable();
    while ((read = getline(&line, &len, fp)) != -1) {
        he->prefix = -2;
        while ((tok = strsep(&line, ",")) != NULL) {
            if ('0' == tok[0] && 'x' == tok[1]) {
                //this is opcode byte
                he->opcode[op_counter] = (unsigned char)strtoul(tok, NULL, 16);
                op_counter++;
            } else if (tok[0] == 'I' || tok[0] == 'M' ||
                       tok[0] == 'R' || tok[0] == 'O' ||
                       tok[0] == 'D' || tok[0] == 'Z') {
                he->encoding = strtoop_encoding(tok);
            } else if (!strchr(tok, '\n')){
                // If no new line, this is the opcode name
                memcpy(he->opcode_name, tok, sizeof(he->opcode_name));
            } else if (tok[0] != '\n'){
                // Only set prefix if there is one
                if (tok[0] == 'r') {
                    he->prefix = -1;
                }
                else {
                    tok[1] = '\0';
                    he->prefix = atoi(tok);
                }
            }
        }
        hash_insert(he);
        op_counter = 0;
        memset(he, 0, sizeof(hash_entry_t));
    }
    fclose(fp);
    if (line)
        free(line);
    return 0;
}

static void print_entry(hash_entry_t *tmp) {
    printf("Opcode: %x%x%x, Name: %s, Mode: %d, prefix: %d\n",
            tmp->opcode[0], tmp->opcode[1], tmp->opcode[2], tmp->opcode_name,
            tmp->encoding, tmp->prefix);
}

void print_all_entries(hash_entry_t *tmp) {
    while (tmp) {
        print_entry(tmp);
        tmp = tmp->next;
    }
}
