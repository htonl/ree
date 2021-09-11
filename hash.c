#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "hash.h"

hash_entry_t hashtable[HASHTABLESIZE];

unsigned long hash(unsigned char op) {
    op = ((op >> 16) ^ op) * 0x45d9f3b;
    op = ((op >> 16) ^ op) * 0x45d9f3b;
    op = (op >> 16) ^ op;
    return (op % HASHTABLESIZE);
}	

void init_hashtable() {
    memset(hashtable, 0, sizeof(hashtable));
}

void copy_entry(hash_entry_t *dest, hash_entry_t *src) {
    memcpy(dest->opcode, src->opcode, 4);
    memcpy(dest->opcode_name, src->opcode_name, 16);
    dest->encoding = src->encoding;
}
	
int hash_insert(hash_entry_t *entry) {
    unsigned long idx;
    idx = hash(entry->opcode[0]);
    
    if (hashtable[idx].opcode[0] == 0) {
        // Not a collision
        // TODO is this a strong enough guarantee?
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

hash_entry_t *hash_lookup(unsigned char op) {
    unsigned long idx;
    idx = hash(op);
    return &hashtable[idx]; // TODO up to the caller to deal with collisions
}
	
/*
void create_hashtable(char *filename) {
	FILE *fp;
	memset(hashtable, 0, sizeof(hashtable));
*/
