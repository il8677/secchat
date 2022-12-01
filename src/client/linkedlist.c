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
    node->contents = data;
    node->next = NULL;
    //datalen?
    while(head->next != NULL) head = head->next;
    head->next = node;
}

void list_del(Node* head, char*name) {
    while(head->next != null){
        if(head->next.name == name) {
            head->next = head->next.next; 
            break;
        }
        head = head->next;
    }

}