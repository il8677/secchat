#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#include "linkedList.h"

struct node {
    node* next;
    char* name;
    char contents[];
};

void list_free(node* head) {
    node* temp = head;
    while (head->next != NULL) {
        head = head->next;
        free(temp);
        temp = head;
    }
    free(head);
}

void list_add(node* head, char* name, char* data, uint16_t datalen) {
    struct node *node = (struct node *) malloc (sizeof(struct node));
    node->name = name;
    node->next = NULL;
    memcpy(node->contents, data, datalen);
    
    while(head->next != NULL) head = head->next;
    head->next = node;
}

void list_del(node* head, char*name) {
    while(head->next != NULL){
        if(head->next.name == name) {
            node* temp;
            temp = head->next;
            head->next = head->next.next;
            free(temp);
            break;
        }
        head = head->next;
    }
}

node* list_init() {
    struct node* node = (struct node *) malloc (sizeof(struct node));
    node->name = NULL;
    node->next = NULL;
    return node;
}