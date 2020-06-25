#ifndef IPC_H_
#define IPC_H_

#include <stdint.h>

#define IPC_MAGIC "DWM-IPC"
#define IPC_MAGIC_LEN 7 // Not including null char

enum {
    IPC_TYPE_RUN_COMMAND = 0,
    IPC_TYPE_GET_TAGS = 1,
    IPC_TYPE_SUBSCRIBE = 2
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

enum {
    IPC_EVENT_TAG_CHANGE,
    IPC_EVENT_WINDOW_CHANGE
};


typedef struct dwm_ipc_header {
  uint8_t magic[IPC_MAGIC_LEN];
  uint32_t size;
  uint8_t type;
} __attribute((packed)) dwm_ipc_header_t;

struct ipc_client {
  int fd;
  int subscriptions;

  char *buffer;
  uint32_t buffer_size;
};

typedef union {
	int i;
	unsigned int ui;
	float f;
	const void *v;
} IPCArg;


int create_socket(const char *filename);

int ipc_register_client(int fd);

int ipc_accept_client(int sock_fd, struct epoll_event *event);

int ipc_read_client(int fd, uint8_t *msg_type, uint32_t *msg_size,
        uint8_t **msg);

// Free msg if successful return of 0
int ipc_recv_message(int fd, uint8_t *msg_type, uint32_t *reply_size,
                     uint8_t **msg);

int ipc_remove_client(int fd);

int command_str_to_int(const char* command);

int ipc_parse_run_command(const uint8_t *msg, int *argc, IPCArg **args[]);

#endif /* IPC_H_ */
