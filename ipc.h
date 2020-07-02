#ifndef IPC_H_
#define IPC_H_

#include "types.h"
#include <stdint.h>
#include <sys/epoll.h>
#include <yajl/yajl_gen.h>

#define IPC_MAGIC "DWM-IPC"
#define IPC_MAGIC_ARR                                                          \
  { 'D', 'W', 'M', '-', 'I', 'P', 'C' }
#define IPC_MAGIC_LEN 7 // Not including null char

enum {
  IPC_TYPE_RUN_COMMAND = 0,
  IPC_TYPE_GET_MONITORS = 1,
  IPC_TYPE_GET_TAGS = 2,
  IPC_TYPE_GET_LAYOUTS = 3,
  IPC_TYPE_GET_DWM_CLIENT = 4,
  IPC_TYPE_SUBSCRIBE = 5,
  IPC_TYPE_EVENT = 6
};

enum { IPC_EVENT_TAG_CHANGE = 1, IPC_EVENT_SELECTED_CLIENT_CHANGE = 2 };

enum { IPC_ACTION_UNSUBSCRIBE = 0, IPC_ACTION_SUBSCRIBE = 1 };

typedef struct dwm_ipc_header {
  uint8_t magic[IPC_MAGIC_LEN];
  uint32_t size;
  uint8_t type;
} __attribute((packed)) dwm_ipc_header_t;

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

typedef union {
  void (*single_param_func)(const Arg *);
  void (*array_param_func)(const Arg *, int);
} ArgFunction;

typedef struct {
  const char *command_name;
  ArgFunction func;
  const unsigned int argc;
} IPCCommand;

int ipc_init(const char *socket_path, const int epoll_fd, IPCCommand commands[],
             int commands_len);

IPCClient *ipc_list_get_client(int fd);

int ipc_accept_client(int sock_fd, struct epoll_event *event);

int ipc_read_client(int fd, uint8_t *msg_type, uint32_t *msg_size,
                    uint8_t **msg);

int ipc_drop_client(int fd);

int ipc_command_stoi(const char *command);

void ipc_prepare_send_message(IPCClient *c, const uint8_t msg_type,
                              const uint32_t msg_size, const char *msg);

int ipc_push_pending(IPCClient *c);

void ipc_prepare_reply_failure(IPCClient *c, int msg_type);

void ipc_prepare_reply_success(IPCClient *c, int msg_type);

void ipc_cleanup(int socket_fd);

int ipc_parse_run_command(const uint8_t *msg, char **name, int *argc,
                          Arg *args[]);

int ipc_run_command(const char *name, Arg *args, const int argc);

void ipc_get_monitors(IPCClient *c, Monitor *selmon);

void ipc_get_tags(IPCClient *c, const char *tags[], const int tags_len);

void ipc_get_layouts(IPCClient *c, const Layout layouts[],
                     const int layouts_len);

int ipc_parse_get_client(const uint8_t *msg, Window *win);

void ipc_get_client(IPCClient *ipc_client, Client *dwm_client);

int ipc_is_client_registered(int fd);

int ipc_event_stoi(const char *subscription);

int ipc_parse_subscribe(const uint8_t *msg, int *action);

int ipc_subscribe(IPCClient *c, int event, int action);

void ipc_tag_change_event(int mon_num, TagState old_state, TagState new_state);

void ipc_selected_client_change_event(Client *old_client, Client *new_client,
                                      int mon_num);

#endif /* IPC_H_ */
