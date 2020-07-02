#ifndef IPC_H_
#define IPC_H_

#include "IPCClient.h"
#include "types.h"
#include <stdint.h>
#include <sys/epoll.h>
#include <yajl/yajl_gen.h>

#define IPC_MAGIC "DWM-IPC"
#define IPC_MAGIC_ARR                                                          \
  { 'D', 'W', 'M', '-', 'I', 'P', 'C' }
#define IPC_MAGIC_LEN 7 // Not including null char

typedef enum IPCMessageType {
  IPC_TYPE_RUN_COMMAND = 0,
  IPC_TYPE_GET_MONITORS = 1,
  IPC_TYPE_GET_TAGS = 2,
  IPC_TYPE_GET_LAYOUTS = 3,
  IPC_TYPE_GET_DWM_CLIENT = 4,
  IPC_TYPE_SUBSCRIBE = 5,
  IPC_TYPE_EVENT = 6
} IPCMessageType;

typedef enum IPCEvent {
  IPC_EVENT_TAG_CHANGE = 1,
  IPC_EVENT_SELECTED_CLIENT_CHANGE = 2,
} IPCEvent;

typedef enum IPCSubscriptionAction {
  IPC_ACTION_UNSUBSCRIBE = 0,
  IPC_ACTION_SUBSCRIBE = 1
} IPCSubscriptionAction;

typedef struct dwm_ipc_header {
  uint8_t magic[IPC_MAGIC_LEN];
  uint32_t size;
  uint8_t type;
} __attribute((packed)) dwm_ipc_header_t;

typedef union ArgFunction {
  void (*single_param)(const Arg *);
  void (*array_param)(const Arg *, int);
} ArgFunction;

typedef struct IPCCommand {
  const char *command_name;
  ArgFunction func;
  const unsigned int argc;
} IPCCommand;

int ipc_init(const char *socket_path, const int epoll_fd, IPCCommand commands[],
             int commands_len);

IPCClient *ipc_get_client(int fd);

int ipc_accept_client(int sock_fd, struct epoll_event *event);

int ipc_read_client(int fd, IPCMessageType *msg_type, uint32_t *msg_size,
                    char **msg);

int ipc_drop_client(int fd);

int ipc_command_stoi(const char *command);

void ipc_prepare_send_message(IPCClient *c, const IPCMessageType msg_type,
                              const uint32_t msg_size, const char *msg);

int ipc_push_pending(IPCClient *c);

void ipc_prepare_reply_failure(IPCClient *c, IPCMessageType msg_type);

void ipc_prepare_reply_success(IPCClient *c, IPCMessageType msg_type);

void ipc_cleanup(int socket_fd);

int ipc_run_command(IPCClient *ipc_client, char *msg);

void ipc_get_monitors(IPCClient *c, Monitor *selmon);

void ipc_get_tags(IPCClient *c, const char *tags[], const int tags_len);

void ipc_get_layouts(IPCClient *c, const Layout layouts[],
                     const int layouts_len);

int ipc_parse_get_dwm_client(const char *msg, Window *win);

void ipc_get_dwm_client(IPCClient *ipc_client, Client *dwm_client);

int ipc_is_client_registered(int fd);

int ipc_event_stoi(const char *subscription);

int ipc_subscribe(IPCClient *c, const char *msg);

void ipc_tag_change_event(int mon_num, TagState old_state, TagState new_state);

void ipc_selected_client_change_event(Client *old_client, Client *new_client,
                                      int mon_num);

#endif /* IPC_H_ */
