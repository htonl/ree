#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "hash.h"

hash_entry_t hashtable[HASHTABLESIZE];

static unsigned long hash(unsigned char op) {
    op = ((op >> 16) ^ op) * 0x45d9f3b;
    op = ((op >> 16) ^ op) * 0x45d9f3b;
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
    switch (tok[0]) {
        case 'D':
            ret = D;
            break;
        case 'O':
            ret = O;
            break;
        case'I':
            ret = I;
            break;
        case 'R':
            ret = RM;
            break;
        case 'M':
            if (tok[1] == 'I') {
                ret = MI;
                break;
            }
            else {
                ret = MR;
                break;
            }
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

hash_entry_t *hash_lookup(unsigned char *op) {
    unsigned long idx;
    unsigned int hashable_op;
    hashable_op = get_hashable_op(op);
    hash_entry_t *tmp;
    idx = hash(hashable_op);
    if (!op_cmp(hashtable[idx].opcode, op))
        // Found it
        return &hashtable[idx]; 
    tmp = hashtable[idx].next;
    if (!tmp)
        // op not in hashtable
        return NULL;
    while(tmp != NULL) {
        if (!op_cmp(tmp->opcode, op))
            // collision but found
            return tmp;
        tmp = tmp->next;
    }
    // Not found
    return NULL;
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
        return -1;
    }
    memset(he, 0, sizeof(hash_entry_t));
    fp = fopen(HASHFILE, "r");
    if (NULL == fp) {
        fprintf(stderr, "%s: Error opening instructions.txt\n", __FUNCTION__);
        return -1;
    }
    init_hashtable();
    while ((read = getline(&line, &len, fp)) != -1) {
        while ((tok = strsep(&line, ",")) != NULL) {
            if ('0' == tok[0]) {
                //this is opcode byte
                he->opcode[op_counter] = (unsigned char)strtoul(tok, NULL, 16);
                op_counter++;
               }
            else if (tok[0] == 'I' || tok[0] == 'M' ||
                     tok[0] == 'R' || tok[0] == 'O' ||
                     tok[0] == 'D') {
                he->encoding = strtoop_encoding(tok);
            }
            else {
                memcpy(he->opcode_name, tok, sizeof(he->opcode_name));
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






