#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <yajl/yajl_gen.h>
#include <ctype.h>

#define IPC_MAGIC "DWM-IPC"
#define IPC_MAGIC_ARR                                                          \
  { 'D', 'W', 'M', '-', 'I', 'P', 'C' }
#define IPC_MAGIC_LEN 7 // Not including null char

#define IPC_EVENT_TAG_CHANGE "tag_change_event"
#define IPC_EVENT_SELECTED_CLIENT_CHANGE "selected_client_change_event"
#define IPC_EVENT_LAYOUT_CHANGE "layout_change_event"

#define ystr(str) yajl_gen_string(gen, (unsigned char *)str, strlen(str))

typedef unsigned long Window;

const char *DEFAULT_SOCKET_PATH = "/tmp/dwm.sock";
static int sock_fd = -1;

typedef enum IPCMessageType {
  IPC_TYPE_RUN_COMMAND = 0,
  IPC_TYPE_GET_MONITORS = 1,
  IPC_TYPE_GET_TAGS = 2,
  IPC_TYPE_GET_LAYOUTS = 3,
  IPC_TYPE_GET_DWM_CLIENT = 4,
  IPC_TYPE_SUBSCRIBE = 5,
  IPC_TYPE_EVENT = 6
} IPCMessageType;


typedef struct dwm_ipc_header {
  uint8_t magic[IPC_MAGIC_LEN];
  uint32_t size;
  uint8_t type;
} __attribute((packed)) dwm_ipc_header_t;


static int
recv_message(uint8_t *msg_type, uint32_t *reply_size, uint8_t **reply)
{
  uint32_t read_bytes = 0;
  const int32_t to_read = sizeof(dwm_ipc_header_t);
  char header[to_read];
  char *walk = header;

  // Try to read header
  while (read_bytes < to_read) {
    int n = read(sock_fd, header + read_bytes, to_read - read_bytes);

    if (n == 0) {
      if (read_bytes == 0) {
        fprintf(stderr, "Unexpectedly reached EOF while reading header.");
        fprintf(stderr, "Read %" PRIu32 " bytes, expected %" PRIu32 " bytes.\n",
                read_bytes, *reply_size);
        return -2;
      } else {
        fprintf(stderr, "Unexpectedly reached EOF while reading header.");
        fprintf(stderr, "Read %" PRIu32 " bytes, expected %" PRIu32 " bytes.\n",
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
    fprintf(stderr, "Invalid magic string. Got '%.*s', expected '%s'\n",
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
    const int n = read(sock_fd, *reply + read_bytes, *reply_size - read_bytes);

    if (n == 0) {
      fprintf(stderr, "Unexpectedly reached EOF while reading payload.");
      fprintf(stderr, "Read %" PRIu32 " bytes, expected %" PRIu32 " bytes.\n",
              read_bytes, *reply_size);
      free(*reply);
      return -2;
    } else if (n == -1) {
      if (errno == EINTR || errno == EAGAIN)
        continue;
      free(*reply);
      return -1;
    }

    read_bytes += n;
  }

  return 0;
}

static int
read_socket(IPCMessageType *msg_type, uint32_t *msg_size, char **msg)
{
  int ret = -1;

  while (ret != 0) {
    ret = recv_message((uint8_t *)msg_type, msg_size, (uint8_t **)msg);

    if (ret < 0) {
      if (ret == -1 && (errno == EINTR || errno == EAGAIN))
        continue;

      fprintf(stderr, "Error receiving response from socket. ");
      fprintf(stderr, "The connection might have been lost.\n");
      exit(2);
    }
  }

  return 0;
}

static void
connect_to_socket()
{
  struct sockaddr_un addr;

  int sock = socket(AF_UNIX, SOCK_STREAM, 0);

  memset(&addr, 0, sizeof(struct sockaddr_un));

  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, DEFAULT_SOCKET_PATH);

  connect(sock, (const struct sockaddr *)&addr, sizeof(struct sockaddr_un));

  sock_fd = sock;
}

static int
send_message(IPCMessageType msg_type, uint32_t msg_size, uint8_t *msg)
{
  dwm_ipc_header_t header = {
    .magic = IPC_MAGIC_ARR,
    .size = msg_size,
    .type = msg_type
  };

  size_t header_size = sizeof(dwm_ipc_header_t);

  uint8_t buffer[header_size + header.size];
  memcpy(buffer, &header, header_size);
  memcpy(buffer + header_size, msg, header.size);

  write(sock_fd, buffer, header_size + header.size);

  return 0;
}

static int
is_float(const char *s)
{
  size_t len = strlen(s);
  int is_dot_used = 0;

  for (int i = 0; i < len; i++) {
    if (isdigit(s[i]))
      continue;
    else if (!is_dot_used && s[i] == '.' && i != 0 && i != len - 1) {
      is_dot_used = 1;
      continue;
    } else
      return 0;
  }

  return 1;
}

static int
is_unsigned_int(const char *s)
{
  size_t len = strlen(s);

  for (int i = 0; i < len; i++) {
    if (isdigit(s[i]))
      continue;
    else
      return 0;
  }

  return 1;
}

static int
is_signed_int(const char *s)
{
  size_t len = strlen(s);

  for (int i = 0; i < len; i++) {
    if (isdigit(s[i]))
      continue;
    else if (i == 0 && s[i] == '-') {
      continue;
    } else
      return 0;
  }

  return 1;
}

static int
run_command(const char *name, char *args[], int argc)
{
  const unsigned char *msg;
  size_t msg_size;

  yajl_gen gen = yajl_gen_alloc(NULL);

  yajl_gen_map_open(gen);
  ystr("command"); ystr(name);
  ystr("args");

  yajl_gen_array_open(gen);

  for (int i = 0; i < argc; i++) {
    if (is_signed_int(args[i])) {
      long long num = atoll(args[i]);
      yajl_gen_integer(gen, num);
    } else if (is_float(args[i])) {
      float num = atof(args[i]);
      yajl_gen_double(gen, num);
    } else {
      ystr(args[i]);
    }
  }
  yajl_gen_array_close(gen);

  yajl_gen_map_close(gen);

  yajl_gen_get_buf(gen, &msg, &msg_size);

  send_message(IPC_TYPE_RUN_COMMAND, msg_size, (uint8_t *)msg);

  IPCMessageType reply_type;
  uint32_t reply_size;
  char *reply;

  read_socket(&reply_type, &reply_size, &reply);

  printf("%.*s\n", reply_size, reply);
  free(reply);

  yajl_gen_free(gen);

  return 0;
}

static int
get_monitors()
{
  send_message(IPC_TYPE_GET_MONITORS, 1, (uint8_t *)"");
  IPCMessageType msg_type;
  uint32_t msg_size;
  char *msg;

  read_socket(&msg_type, &msg_size, &msg);

  printf("%.*s\n", msg_size, msg);
  free(msg);

  return 0;
}

static int
get_tags()
{
  send_message(IPC_TYPE_GET_TAGS, 1, (uint8_t *)"");
  IPCMessageType msg_type;
  uint32_t msg_size;
  char *msg;

  read_socket(&msg_type, &msg_size, &msg);

  printf("%.*s\n", msg_size, msg);
  free(msg);

  return 0;
}

static int
get_layouts()
{
  send_message(IPC_TYPE_GET_LAYOUTS, 1, (uint8_t *)"");
  IPCMessageType msg_type;
  uint32_t msg_size;
  char *msg;

  read_socket(&msg_type, &msg_size, &msg);

  printf("%.*s\n", msg_size, msg);
  free(msg);

  return 0;
}

static int
get_dwm_client(Window win)
{
  const unsigned char *msg;
  size_t msg_size;

  yajl_gen gen = yajl_gen_alloc(NULL);

  yajl_gen_map_open(gen);
  ystr("client_window_id"); yajl_gen_integer(gen, win);
  yajl_gen_map_close(gen);

  yajl_gen_get_buf(gen, &msg, &msg_size);

  send_message(IPC_TYPE_GET_DWM_CLIENT, msg_size, (uint8_t *)msg);

  IPCMessageType reply_type;
  uint32_t reply_size;
  char *reply;

  read_socket(&reply_type, &reply_size, &reply);

  printf("%.*s\n", reply_size, reply);

  yajl_gen_free(gen);
  free(reply);

  return 0;
}

static int
subscribe(const char *event)
{
  const unsigned char *msg;
  size_t msg_size;

  yajl_gen gen = yajl_gen_alloc(NULL);

  yajl_gen_map_open(gen);
  ystr("event"); ystr(event);
  ystr("action"); ystr("subscribe");
  yajl_gen_map_close(gen);

  yajl_gen_get_buf(gen, &msg, &msg_size);

  send_message(IPC_TYPE_SUBSCRIBE, msg_size, (uint8_t *)msg);

  IPCMessageType reply_type;
  uint32_t reply_size;
  char *reply;

  yajl_gen_free(gen);

  read_socket(&reply_type, &reply_size, &reply);
  printf("%.*s\n", reply_size, reply);
  free(reply);

  return 0;
}

static void
print_usage(const char *name)
{
  printf("usage: %s <command> [...]\n", name);
  puts("");
  puts("Commands:");
  puts("  run_command <name> [args...]    Run an IPC command");
  puts("");
  puts("  get_monitors                    Get monitor properties");
  puts("");
  puts("  get_tags                        Get list of tags");
  puts("");
  puts("  get_layouts                     Get list of layouts");
  puts("");
  puts("  get_dwm_client <window_id>      Get dwm client proprties");
  puts("");
  puts("  subscribe [events...]           Subscribe to specified events");
  puts("                                  Options: "IPC_EVENT_TAG_CHANGE",");
  puts("                                  "IPC_EVENT_LAYOUT_CHANGE",");
  puts("                                  "IPC_EVENT_SELECTED_CLIENT_CHANGE);
  puts("");
  puts("  help                            Display this message");
  puts("");
}

int
main(int argc, char *argv[])
{
  if (argc < 2) {
    fprintf(stderr, "Expected an argument, got none.\n");
    fprintf(stderr, "usage: %s <command> [...]\n", argv[0]);
    fprintf(stderr, "Try '%s help'\n", argv[0]);
    return 1;
  }

  connect_to_socket();
  if (sock_fd == -1) {
    fprintf(stderr, "Failed to connect to socket\n");
    return 1;
  }

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "help") == 0) {
      print_usage(argv[0]);
      return 0;
    } else if (strcmp(argv[i], "run_command") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "Error: No command specified\n");
        return 1;
      }
      char *command = argv[i];
      char **command_args = argv + ++i;
      int command_argc = argc - i;
      run_command(command, command_args, command_argc);
      return 0;
    } else if (strcmp(argv[i], "get_monitors") == 0) {
      get_monitors();
      return 0;
    } else if (strcmp(argv[i], "get_tags") == 0) {
      get_tags();
      return 0;
    } else if (strcmp(argv[i], "get_layouts") == 0) {
      get_layouts();
      return 0;
    } else if (strcmp(argv[i], "get_dwm_client") == 0) {
      if (++i < argc) {
        if (is_unsigned_int(argv[i])) {
          Window win = atol(argv[i]);
          get_dwm_client(win);
        } else {
          fprintf(stderr, "Error: expected unsigned integer argument\n");
          fprintf(stderr, "usage: %s <command> [...]\n", argv[0]);
          fprintf(stderr, "Try '%s help'\n", argv[0]);
          return 1;
        }
      } else {
        fprintf(stderr, "Error: expected the window id\n");
        fprintf(stderr, "usage: %s <command> [...]\n", argv[0]);
        fprintf(stderr, "Try '%s help'\n", argv[0]);
        return 1;
      }
      return 0;
    } else if (strcmp(argv[i], "subscribe") == 0) {
      for (int j = ++i; j < argc; j++) {
        subscribe(argv[j]);
      }
      while (1) {
        IPCMessageType reply_type;
        uint32_t reply_size;
        char *reply;

        read_socket(&reply_type, &reply_size, &reply);
        printf("%s\n", reply);
        free(reply);
      }
    } else {
      fprintf(stderr, "Invalid argument '%s'\n", argv[i]);
      fprintf(stderr, "usage: %s <command> [...]\n", argv[0]);
      fprintf(stderr, "Try '%s help'\n", argv[0]);
      return 1;
    }
  }
}
