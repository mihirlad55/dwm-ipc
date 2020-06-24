#ifndef IPC_H_
#define IPC_H_

#include <stdint.h>


int create_socket(const char* filename);

int ipc_register_client(int fd);

int ipc_accept_client(int sock_fd, struct epoll_event *event);

int ipc_read_client(int fd);

int ipc_remove_client(int fd);


#endif /* IPC_H_ */
