#ifndef IPC_CLIENT_H_
#define IPC_CLIENT_H_

#include <stdlib.h>
#include <sys/epoll.h>
#include <stdio.h>

typedef struct IPCClient IPCClient;
struct IPCClient {
  int fd;
  int subscriptions;

  char *buffer;
  uint32_t buffer_size;

  struct epoll_event event;
  IPCClient *next;
  IPCClient *prev;
};

typedef IPCClient* IPCClientList;

IPCClient* ipc_client_new(int fd);

void ipc_list_add_client(IPCClientList list, IPCClient *nc);

void ipc_list_remove_client(IPCClientList list, IPCClient *c);

IPCClient* ipc_list_get_client(IPCClientList list, int fd);

#endif // IPC_CLIENT_H_

