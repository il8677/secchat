#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "linkedList.h"

struct Node {
    struct Node* next;
    char * name;
    char * contents[];
}

void list_add(Node* head, char* name, char* data, uint16_t datalen) {
    struct Node *node = (struct Node *) malloc (sizeof(struct Node));
    node->name = name;
    node->data = data;
    //datalen?
    while(head->next != NULL) head = head->next;
    head->next = node;
}