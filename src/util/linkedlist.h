#ifndef _LINKEDLIST_H_
#define _LINKEDLIST_H_

#include <stdbool.h>

typedef struct Node Node;

// Callback used in the exec functions
typedef void(*list_cb_t)(Node* node, void* usr);

struct Node {
    Node* next;

    char* key; // The key of the node
    char contents[]; // The contents of the node
};

/// @brief Initializes an empty node
/// @return The head (dummy) node
Node* list_init();

/// @brief Frees an entire list
/// @param head The head of the list
void list_free(Node* head);

/// @brief Adds a node to a list
/// @param head The head of the list
/// @param key The key of the node
/// @param data The data to store in the node
/// @param datalen The length of the data
/// @param unique If the insertion should check if the key is unique
/// @return 1 if the key was not unique and the unique flag was set
int list_add(Node* head, const char* key, void* data, uint16_t datalen, char unique);

/// @brief Deletes a key from a list
void list_del(Node* head, const char* key);

/// @brief Executes a callback across a list
/// @param head the head of the list 
/// @param key the key to execute on
/// @param cb the callback to use
/// @param userData arbitrary data to pass into the callback
/// @param doDelete boolean: delete flag after exec
void list_exec(Node* head, const char* key, list_cb_t cb, void* userData, char doDelete);

/// @brief Executes a callback across the entire list
/// @param cb The callback to use 
/// @param userData arbitrary data to pass into the callback
/// @param doDelete boolean: delete flag after exec
void list_exec_all(Node* head, list_cb_t cb, void* userData, char doDelete);

Node* list_find(Node* head, const char* key);

#endif