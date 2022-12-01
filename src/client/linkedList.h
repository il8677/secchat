#ifndef _LINKEDLIST_H_
#define _LINKEDLIST_H_

typedef struct node node;

void list_add(node* head, char* name, char* data, uint16_t datalen);

void list_del(node* head, char*name);

node* list_init();

void list_free(node* head);

#endif