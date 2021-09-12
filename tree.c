#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "tree.h"

/* @brief Insert node into binary tree
 *
 * @param tree the tree inserting into
 * @param insn the instruction to insert into the tree
 *
 * Tree uses the addr of the isntruction for placement.
 * Traversal then takes place from addr 0 -> n
 */
int tree_insert(node_t **tree, instruction_t *insn) {
    node_t *tmp;
    // Allocate a new node (this is either going to be node 1
    // or a new node inserted into the tree
    node_t *new_node = malloc(sizeof(struct node));
    if (NULL == new_node) {
        printf("%s out of memory allocation new node\n", __FUNCTION__);
        return -1;
    }
    memset(new_node, 0, sizeof(struct node));
    new_node->insn = insn;
    
    if (*tree == NULL) {
    	// tree is empty, inserting first node
        *tree = new_node;
        return 0;
    }
    tmp = *tree;
    while (1) {
    	// find where to insert the node
        if (insn->addr > tmp->insn->addr) {
            if (NULL == tmp->right) {
                tmp->right = new_node;
                goto done;
            }
            tmp = tmp->right;
        }
        else if (insn->addr < tmp->insn->addr) {
            if (NULL == tmp->left) {
                tmp->left = new_node;
                goto done;
            }
            tmp = tmp->left;
        }
    }
    return -1; // Can't get here?
done:
    return 0;
}

/* 
 * @brief simple traversal from smallest to largest node
 * @param tree to traverse
 */
void tree_traverse(node_t *tree) {
    if (tree != NULL) {
        tree_traverse(tree->left);
        printf("%lx, %x, %x\n", tree->insn->addr,
                               tree->insn->opcode[0] & 0xff,
                               tree->insn->modrm & 0xff);
        tree_traverse(tree->right);
    }
}

/* 
 * @brief Destroy and free the whole tree 
 * @param tree to free
 */
void tree_free(node_t *tree) {
    if (tree != NULL) {
        tree_free(tree->left);
        tree_free(tree->right);
        insn_free(tree->insn);
        free(tree);
    }
}
