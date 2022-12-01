#ifndef _LINKEDLIST_H_
#define _LINKEDLIST_H_

typedef struct Node Node;

struct Node *list_add(Node* head, char* name, char* data, uint16_t datalen);

#endif