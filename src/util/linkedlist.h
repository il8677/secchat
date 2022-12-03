#ifndef _LINKEDLIST_H_
#define _LINKEDLIST_H_

#include <stdbool.h>

typedef struct Node Node;
typedef void(*list_cb_t)(Node* node, void* usr);

struct Node {
    Node* next;

    char* key;
    char contents[];
};

Node* list_init();
void list_free(Node* head);

/// @brief Add to a linked list
/// @return 1 if failed
int list_add(Node* head, const char* key, void* data, uint16_t datalen);
void list_del(Node* head, const char* key);

/// @brief Executes a callback across a list
/// @param head the head of the list 
/// @param key the key to execute on
/// @param cb the callback to use
/// @param userData arbitrary data to pass into the function
/// @param doDelete boolean: delete flag after exec
void list_exec(Node* head, const char* key, list_cb_t cb, void* userData, char doDelete);
void list_exec_all(Node* head, list_cb_t cb, void* userData, char doDelete);

Node* list_find(Node* head, const char* key);

#endif