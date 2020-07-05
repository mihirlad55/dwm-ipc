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

#define IPCCOMMAND(FUNC, ARGC, TYPES)                                          \
  { #FUNC, {FUNC }, ARGC, (ArgType[ARGC])TYPES }

extern const uint32_t MAX_MESSAGE_SIZE;

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
  IPC_EVENT_LAYOUT_CHANGE = 4
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

typedef enum ArgType {
  ARG_TYPE_NONE = 0,
  ARG_TYPE_UINT = 1,
  ARG_TYPE_SINT = 2,
  ARG_TYPE_FLOAT = 3,
  ARG_TYPE_PTR = 4,
  ARG_TYPE_STR = 5
} ArgType;

typedef union ArgFunction {
  void (*single_param)(const Arg *);
  void (*array_param)(const Arg *, int);
} ArgFunction;

typedef struct IPCCommand {
  char *command_name;
  ArgFunction func;
  unsigned int argc;
  ArgType *arg_types;
} IPCCommand;

int ipc_init(const char *socket_path, const int p_epoll_fd,
    IPCCommand commands[], const int commands_len);

IPCClient *ipc_get_client(int fd);

int ipc_accept_client();

int ipc_read_client(IPCClient *c, IPCMessageType *msg_type, uint32_t *msg_size,
                    char **msg);

int ipc_drop_client(IPCClient *c);

void ipc_prepare_send_message(IPCClient *c, const IPCMessageType msg_type,
                              const uint32_t msg_size, const char *msg);

int ipc_push_pending(IPCClient *c);

void ipc_prepare_reply_failure(IPCClient *c, IPCMessageType msg_type,
                               const char *format, ...);

void ipc_prepare_reply_success(IPCClient *c, IPCMessageType msg_type);

void ipc_cleanup(int socket_fd);

int ipc_run_command(IPCClient *ipc_client, char *msg);

void ipc_get_monitors(IPCClient *c, Monitor *selmon);

void ipc_get_tags(IPCClient *c, const char *tags[], const int tags_len);

void ipc_get_layouts(IPCClient *c, const Layout layouts[],
                     const int layouts_len);

int ipc_get_dwm_client(IPCClient *ipc_client, const char *msg,
                       const Monitor *mons);

int ipc_is_client_registered(int fd);

int ipc_subscribe(IPCClient *c, const char *msg);

void ipc_tag_change_event(int mon_num, TagState old_state, TagState new_state);

void ipc_selected_client_change_event(Client *old_client, Client *new_client,
                                      int mon_num);

void ipc_layout_change_event(const int mon_num, const char *old_symbol,
                             const char *new_symbol);

void ipc_send_events(Monitor *mons);

int ipc_handle_client_epoll_event(struct epoll_event *ev, Monitor *mons,
    const char *tags[], const int tags_len, const Layout *layouts,
    const int layouts_len);

int ipc_handle_socket_epoll_event(struct epoll_event *ev);

#endif /* IPC_H_ */
