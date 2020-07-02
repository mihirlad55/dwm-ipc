#include "IPCClient.h"

IPCClient*
ipc_client_new(int fd)
{
  IPCClient* c = (IPCClient*)malloc(sizeof(IPCClient));

  if (c == NULL) return NULL;

  c->buffer_size = 0;
  c->buffer = NULL;
  c->fd = fd;
  c->event.data.fd = fd;
  c->next = NULL;
  c->prev = NULL;
  c->subscriptions = 0;

  return c;
}

void
ipc_list_add_client(IPCClientList list, IPCClient *nc)
{
  fprintf(stderr, "Adding client with fd %d to list\n", nc->fd);

  if (list == NULL) {
    list = nc;
  } else {
    IPCClient *c;
    for (c = list; c && c->next; c = c->next)
      ;
    c->next = nc;
    nc->prev = c;
  }
}

void
ipc_list_remove_client(IPCClientList list, IPCClient *c)
{
  for (c = list; c && c->next; c = c->next)
    ;

  IPCClient *cprev = c->prev;
  IPCClient *cnext = c->next;

  if (cprev != NULL) cprev->next = c->next;
  if (cnext != NULL) cnext->prev = c->prev;
  if (c == list)
    list = c->next;
}

IPCClient*
ipc_list_get_client(IPCClientList list, int fd)
{
  for (IPCClient *c = list; c; c = c->next) {
    if (c->fd == fd) return c;
  }

  return NULL;
}
