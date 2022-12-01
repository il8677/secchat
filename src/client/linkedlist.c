#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#include "linkedList.h"

struct Node {
    Node* next;

    char* key;
    char contents[];
};

void list_free(Node* head) {
    Node* temp = head;
    while (head->next != NULL) {
        head = head->next;
        free(temp);
        temp = head;
    }
    free(head);
}

void list_add(Node* head, char* key, char* data, uint16_t datalen) {
    struct Node *node = (struct Node *) malloc (sizeof(struct Node));
    node->key = key;
    node->next = NULL;
    memcpy(node->contents, data, datalen);
    
    while(head->next != NULL) head = head->next;
    head->next = node;
}

void list_del(Node* head, char*key) {
    while(head->next != NULL){
        if(head->next.key == key) {
            Node* temp;
            temp = head->next;
            head->next = head->next.next;
            free(temp);
            break;
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

Node* list_exist(Node* head, char* key) {
    while(head->next != NULL){
        if(head->key == key) return head;
        head = head->next;
    }
    return NULL;
}