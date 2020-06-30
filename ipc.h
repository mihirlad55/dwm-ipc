#ifndef IPC_H_
#define IPC_H_

#include "types.h"
#include <stdint.h>
#include <yajl/yajl_gen.h>
#include <sys/epoll.h>

#define IPC_MAGIC "DWM-IPC"
#define IPC_MAGIC_ARR                                                          \
  { 'D', 'W', 'M', '-', 'I', 'P', 'C' }
#define IPC_MAGIC_LEN 7 // Not including null char

#define ystr(str) yajl_gen_string(gen, (unsigned char *)str, strlen(str))

enum {
  IPC_TYPE_RUN_COMMAND = 0,
  IPC_TYPE_GET_MONITORS = 1,
  IPC_TYPE_GET_TAGS = 2,
  IPC_TYPE_GET_LAYOUTS = 3,
  IPC_TYPE_GET_CLIENT = 4,
  IPC_TYPE_SUBSCRIBE = 5,
  IPC_TYPE_EVENT = 6
};

enum {
  IPC_COMMAND_VIEW = 0,
  IPC_COMMAND_TOGGLE_VIEW = 1,
  IPC_COMMAND_TAG = 2,
  IPC_COMMAND_TOGGLE_TAG = 3,
  IPC_COMMAND_TAG_MONITOR = 4,
  IPC_COMMAND_FOCUS_MONITOR = 5,
  IPC_COMMAND_FOCUS_STACK = 6,
  IPC_COMMAND_ZOOM = 7,
  IPC_COMMAND_SPAWN = 8,
  IPC_COMMAND_INC_NMASTER = 9,
  IPC_COMMAND_KILL_CLIENT = 10,
  IPC_COMMAND_TOGGLE_FLOATING = 11,
  IPC_COMMAND_SET_MFACT = 12,
  IPC_COMMAND_SET_LAYOUT = 13,
  IPC_COMMAND_QUIT = 14
};

enum { IPC_EVENT_TAG_CHANGE = 1, IPC_EVENT_WINDOW_CHANGE = 2 };

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

int ipc_init(const char *socket_path, const int epoll_fd);

IPCClient *ipc_list_get_client(int fd);

int ipc_accept_client(int sock_fd, struct epoll_event *event);

int ipc_read_client(int fd, uint8_t *msg_type, uint32_t *msg_size,
                    uint8_t **msg);

int ipc_drop_client(int fd);

int ipc_command_stoi(const char *command);

int ipc_parse_run_command(const uint8_t *msg, int *argc, Arg **args[]);

void ipc_prepare_send_message(IPCClient *c, const uint8_t msg_type,
                              const uint32_t msg_size, const char *msg);

int ipc_push_pending(IPCClient *c);

int ipc_get_monitors(Monitor *selmon, unsigned char **buffer, size_t *len);

int ipc_get_tags(unsigned char **buffer, size_t *len, const char *tags[],
                 const int tags_len);

int ipc_get_layouts(unsigned char **buffer, size_t *len, const Layout layouts[],
                    const int layouts_len);

int ipc_parse_get_client(const uint8_t *msg, Window *win);

int ipc_get_client(unsigned char **buffer, size_t *len, Client *c, int mon_num);

int ipc_is_client_registered(int fd);

void ipc_prepare_reply_failure(IPCClient *c, int msg_type);

void ipc_prepare_reply_success(IPCClient *c, int msg_type);

void ipc_cleanup(int socket_fd);

#endif /* IPC_H_ */
