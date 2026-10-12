#ifndef GW_H
#define GW_H

// Function prototypes for GraphQL-related functions
int graphql(char *path, bool gobuster, char *target_url);
int csrf(char *target_url);

#endif // GW_H