#include "list.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

list_node_t *list_add(list_node_t *list, unsigned int addr)
{
    list_node_t *new_node;
    if (NULL == list) {
        // First node
        list = malloc(sizeof(list_node_t));
        if (NULL == list) {
            fprintf(stderr, "%s: couldn't allocate memory for list node\n",
                    __FUNCTION__);
            return list;
        }
        list->addr = addr;
        snprintf(list->label_name, sizeof(list->label_name), "offset_%08xh",
                addr);
        list->next = NULL;
        return list;
    } else {
       new_node = malloc(sizeof(list_node_t));
       if (NULL == new_node) {
            fprintf(stderr, "%s: couldn't allocate memory for list node\n",
                    __FUNCTION__);
            return list;
        }
        new_node->addr = addr;
        snprintf(new_node->label_name, sizeof(new_node->label_name), "offset_%08xh",
                addr);
        new_node->next = list;
        return new_node;
    }
}

list_node_t *list_search(list_node_t *list, unsigned int addr)
{
    list_node_t *tmp;
    tmp = list;
    if (NULL == tmp)
        return NULL; // empty list, not found

    while (tmp != NULL) {
        if (tmp->addr == addr)
            return tmp; // found
        tmp = tmp->next;
    }
    // Not found
    return NULL;
}

void list_destroy(list_node_t *list) {
    list_node_t *tmp, *next;
    tmp = list;
    if (NULL == tmp)
        return;
    while(tmp != NULL) {
       next = tmp->next;
       free(tmp);
       tmp = next;
    }
}

