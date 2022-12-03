#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#include "linkedList.h"

void node_free(Node* node){
    free(node->key);    
    free(node);
}

void list_free(Node* head) {
    Node* last = head;
    while (head->next != NULL) {
        head = head->next;
        node_free(last);
        last = head;
    }
    free(head);
}

int list_add(Node* head, const char* key, void* data, uint16_t datalen) {
    while(head->next != NULL) {
        if(head->key != NULL && strcmp(key, head->key) == 0) return 1; // Don't insert something that already exists
        head = head->next;
    }
    struct Node *node = malloc(sizeof(struct Node)+datalen);
    node->key = strdup(key);
    node->next = NULL;
    memcpy(node->contents, data, datalen);

    head->next = node;

    return 0;
}

void list_del(Node* head, const char* key) {
    while(head != NULL && head->next != NULL){
        if(strcmp(head->next->key, key) == 0) {
            Node* temp;
            temp = head->next;
            head->next = head->next->next;
            node_free(temp);
        }
        head = head->next;
    }
}

void list_exec(Node* head, const char* key, list_cb_t cb, void* userData, char doDelete){
    while(head != NULL && head->next != NULL){
        if(strcmp(head->next->key, key) == 0) {
            cb(head->next, userData);
            if(doDelete){
                Node* temp;
                temp = head->next;
                head->next = head->next->next;
                node_free(temp);
            }
        }
        head = head->next;
    }
}

Node* list_init() {
    struct Node* node = (struct Node *) malloc (sizeof(struct Node));
    node->key = NULL;
    node->next = NULL;
    return node;
}

Node* list_find(Node* head, const char* key) {
    head = head->next; // Skip dummy head
    if(head == NULL) return NULL;

    while(head->next != NULL){
        if(strcmp(head->key, key)==0) return head;
        head = head->next;
    }
    return NULL;
}