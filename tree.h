#ifndef __TREE_H_
#define __TREE_H_

#include "instruction.h"

typedef struct node {
    instruction_t *insn;
    struct node *left;
    struct node *right;
} node_t;

int tree_insert(node_t **tree, instruction_t *insn);
int tree_add_label(node_t *tree, unsigned int addr, char *label);
void tree_traverse(node_t *tree);
void tree_free(node_t *tree);

#endif
