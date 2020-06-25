#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdlib.h>

#define IPC_MAGIC "DWM-IPC"
#define IPC_MAGIC_LEN 7

enum {
    IPC_TYPE_RUN_COMMAND = 0,
    IPC_TYPE_GET_TAGS = 1,
    IPC_TYPE_SUBSCRIBE = 2
};

enum {
    IPC_COMMAND_TAG = 0,
    IPC_COMMAND_TOGGLE_VIEW = 1,
    IPC_COMMAND_TOGGLE_TAG = 2,
    IPC_COMMAND_TAG_MONITOR = 3,
    IPC_COMMAND_FOCUS_MONITOR = 4,
    IPC_COMMAND_KILL_CLIENT = 5,
    IPC_COMMAND_TOGGLE_FLOATING = 6,
    IPC_COMMAND_SET_MFACT = 7,
    IPC_COMMAND_SET_LAYOUT = 8,
    IPC_COMMAND_QUIT = 9
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

int
main(int argc, char *argv[])
{
    struct sockaddr_un addr;

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    puts("Created socket file descriptor");

    memset(&addr, 0, sizeof(struct sockaddr_un));

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, "/tmp/dwm.sock");

    connect(sock, (const struct sockaddr*) &addr, sizeof(struct sockaddr_un));
    puts("Connected to socket");

    dwm_ipc_header_t msg_header;
    strncpy(msg_header.magic, IPC_MAGIC, IPC_MAGIC_LEN);
    msg_header.type = IPC_TYPE_RUN_COMMAND;
    char *msg =
      "{\n"
      "  \"command\": \"toggletag\",\n"
      "  \"args\": [ 4 ]\n"
      "}";
    msg_header.size = strlen(msg) + 1;

    uint8_t buffer[sizeof(dwm_ipc_header_t) + msg_header.size];
    memcpy(buffer, &msg_header, sizeof(dwm_ipc_header_t));
    memcpy(buffer + sizeof(dwm_ipc_header_t), msg, msg_header.size);

    write(sock, buffer, sizeof(dwm_ipc_header_t) + msg_header.size);
}


