#ifndef __LIST_H_
#define __LIST_H_

typedef struct lnode {
    unsigned int addr;
    char label_name[17]; // offset_12345678h\0
    struct lnode *next;
} list_node_t;

list_node_t *list_add(list_node_t *list, unsigned int addr);
list_node_t *list_search(list_node_t *list, unsigned int addr);
void list_destroy(list_node_t *list);
    
#endif
