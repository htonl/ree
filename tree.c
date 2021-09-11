#include "tree.h"

int tree_insert(node_t **tree, instruction_t *insn) {
    node_t *tmp;
    node_t *new_node = malloc(sizeof(struct node));
    if (NULL == new_node) {
        printf("%s out of memory allocation new node\n", __FUNCTION__);
        return -1;
    }
    memset(new_node, 0, sizeof(struct node));
    new_node->insn = insn;

    tmp = *tree;
    // tree is empty, inserting first node
    if (tmp == NULL) {
        *tree = new_node;
        return 0;
    }
    // find where to insert the node
    while (1) {
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

void tree_traverse(node_t *tree) {
    if (tree != NULL) {
        tree_traverse(tree->left);
        printf("%lx, %x, %x\n", tree->insn->addr,
                               tree->insn->opcode[0] & 0xff,
                               tree->insn->modrm & 0xff);
        tree_traverse(tree->right);
    }
}

