#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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

enum { IPC_EVENT_TAG_CHANGE = 1, IPC_EVENT_SELECTED_CLIENT_CHANGE = 2 };

enum { IPC_ACTION_UNSUBSCRIBE = 0, IPC_ACTION_SUBSCRIBE = 1 };

typedef struct dwm_ipc_header {
  uint8_t magic[IPC_MAGIC_LEN];
  uint32_t size;
  uint8_t type;
} __attribute((packed)) dwm_ipc_header_t;


static int ipc_recv_message(int fd, uint8_t *msg_type, uint32_t *reply_size,
                            uint8_t **reply) {
  uint32_t read_bytes = 0;
  const int32_t to_read = sizeof(dwm_ipc_header_t);
  char header[to_read];
  char *walk = header;

  // Try to read header
  while (read_bytes < to_read) {
    int n = read(fd, header + read_bytes, to_read - read_bytes);

    if (n == 0) {
      if (read_bytes == 0) {
        fprintf(stderr, "Unexpectedly reached EOF while reading header.");
        fprintf(stderr, "Read %" PRIu32 " bytes, expected %" PRIu32 " bytes.",
                read_bytes, *reply_size);
        return -2;
      } else {
        fprintf(stderr, "Unexpectedly reached EOF while reading header.");
        fprintf(stderr, "Read %" PRIu32 " bytes, expected %" PRIu32 " bytes.",
                read_bytes, *reply_size);
        return -3;
      }
    } else if (n == -1) {
      return -1;
    }

    read_bytes += n;
  }

  // Check if magic string in header matches
  if (memcmp(walk, IPC_MAGIC, IPC_MAGIC_LEN) != 0) {
    fprintf(stderr, "Invalid magic string. Got '%.*s', expected '%s'",
            IPC_MAGIC_LEN, walk, IPC_MAGIC);
    return -3;
  }

  walk += IPC_MAGIC_LEN;

  // Extract reply size
  memcpy(reply_size, walk, sizeof(uint32_t));
  walk += sizeof(uint32_t);

  // Extract message type
  memcpy(msg_type, walk, sizeof(uint8_t));
  walk += sizeof(uint8_t);

  (*reply) = malloc(*reply_size);

  read_bytes = 0;
  while (read_bytes < *reply_size) {
    const int n = read(fd, *reply + read_bytes, *reply_size - read_bytes);

    if (n == 0) {
      fprintf(stderr, "Unexpectedly reached EOF while reading payload.");
      fprintf(stderr, "Read %" PRIu32 " bytes, expected %" PRIu32 " bytes.",
              read_bytes, *reply_size);
      free(*reply);
      return -2;
    } else if (n == -1) {
      // TODO: Should we return and wait for another epoll event?
      // This would require saving the partial read in some way.
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
        continue;
      free(*reply);
      return -1;
    }

    read_bytes += n;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  struct sockaddr_un addr;

  int sock = socket(AF_UNIX, SOCK_STREAM, 0);
  puts("Created socket file descriptor");

  memset(&addr, 0, sizeof(struct sockaddr_un));

  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, "/tmp/dwm.sock");

  connect(sock, (const struct sockaddr *)&addr, sizeof(struct sockaddr_un));
  puts("Connected to socket");

  /*char *msg = "{\n"
              "  \"client_window_id\": 8388614\n"
              "}";*/
  /*char *msg =
    "{\n"
    "  \"command\": \"focusstack\",\n"
    "  \"args\": [ 1 ]\n"
    "}";*/
  char *msg =
    "{\n"
    "  \"event\": \"tag_change_event\",\n"
    "  \"action\": \"subscribe\"\n"
    "}";

  dwm_ipc_header_t msg_header = {
    .magic = IPC_MAGIC_ARR,
    .type = IPC_TYPE_SUBSCRIBE,
    .size = strlen(msg) + 1
  };

  uint8_t buffer[sizeof(dwm_ipc_header_t) + msg_header.size];
  memcpy(buffer, &msg_header, sizeof(dwm_ipc_header_t));
  memcpy(buffer + sizeof(dwm_ipc_header_t), msg, msg_header.size);

  write(sock, buffer, sizeof(dwm_ipc_header_t) + msg_header.size);

  uint8_t msg_type;
  uint32_t msg_size;
  uint8_t *reply;

  ipc_recv_message(sock, &msg_type, &msg_size, &reply);
  printf("%s\n", reply);

  while (1) {
    ipc_recv_message(sock, &msg_type, &msg_size, &reply);
    printf("%s\n", reply);
  }
}

