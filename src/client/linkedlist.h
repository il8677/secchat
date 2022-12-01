#ifndef _LINKEDLIST_H_
#define _LINKEDLIST_H_

typedef struct Node Node;

Node* list_init();
void list_free(Node* head);

void list_add(Node* head, char* key, char* data, uint16_t datalen);
void list_del(Node* head, char*key);

Node* list_exist(Node* head, char* key);

#endif