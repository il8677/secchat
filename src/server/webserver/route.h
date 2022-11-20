#ifndef ROUTE_H
#define ROUTE_H

struct api_state;

typedef struct www_route www_route;

// Callback to a POST request, returns 1 for success, -1 for failure, takes in the body of the post, and a pointer to an API msg
typedef int(*post_cb_t)(const char* body, struct api_state* state);

/// @brief Initializes a new GET www_route object
/// @param path Path of the route
/// @param filepath Path of the file to serve
/// @return the www_route object
www_route* www_route_init(const char* path, const char* filepath);
/// @brief Adds a new GET www_route object to a route list
/// @param head The head of the list
/// @param path The path of the route
/// @param filepath Path of the file to serve
void www_route_initadd(www_route* head, const char* path, const char* filepath);

/// @brief Initializes a new POST www_route object
/// @param path Path of the route
/// @param cb Pointer to a callback function
/// @return the www_route object
www_route* www_route_post_init(const char* path, post_cb_t cb);
/// @brief Adds a new POST www_route object to a route list
/// @param path Path of the route
/// @param cb Pointer to a callback function
/// @return the www_route object
void www_route_post_initadd(www_route* head, const char* path, post_cb_t cb);


void www_route_free(www_route* head);

/// @brief Finds a GET route
/// @param head the head of the routes
/// @param path the path to look for
/// @return string containing the file to serve
char* www_route_find(www_route* head, const char* path);

/// @brief Adds a route to a head list
/// @param head The head of the list
/// @param newRoute The route to add
void www_route_add(www_route* head, www_route* newRoute);
/// @brief Finds a POST route
/// @param head the head of the routes
/// @param path 
/// @return A post_cb_t or NULL if none 
post_cb_t www_route_find_post(www_route* head, const char* path);
#endif