#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <yajl/yajl_tree.h>

#include "ipc.h"

int
ipc_create_socket(const char *filename)
{
  fputs("In create socket function\n", stderr);
  struct sockaddr_un addr;
  const size_t addr_size = sizeof(struct sockaddr_un);
  const int sock_type = SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC;

  // In case socket file exists
  unlink(filename);

  // For portability clear the addr structure, since some implementations have
  // nonstandard fields in the structure
  memset(&addr, 0, addr_size);

  // TODO: Make parent directories to file
  // TODO: Resolve tilde

  addr.sun_family = AF_LOCAL;
  strcpy(addr.sun_path, filename);

  const int sock_fd = socket(AF_LOCAL, sock_type, 0);
  if (sock_fd == -1) {
    fputs("Failed to create socket\n", stderr);
    return -1;
  }

  if (bind(sock_fd, (const struct sockaddr *)&addr, addr_size) == -1) {
    fputs("Failed to bind socket\n", stderr);
    return -1;
  }

  if (listen(sock_fd, 5) < 0) {
    fputs("Failed to listen for connections on socket\n", stderr);
    return -1;
  }

  return sock_fd;
}

int
ipc_register_client(int fd)
{
  fprintf(stderr, "%s%d\n", "New client at fd: ", fd);

  return 0;
}

int
ipc_accept_client(int sock_fd, struct epoll_event *event)
{
  fputs("In accept client function\n", stderr);
  int fd = -1;

  if (event->events & EPOLLIN) {
    struct sockaddr_un client_addr;
    socklen_t len;

    // For portability clear the addr structure, since some implementations
    // have nonstandard fields in the structure
    memset(&client_addr, 0, sizeof(struct sockaddr_un));

    fd = accept(sock_fd, (struct sockaddr *)&client_addr, &len);
    if (fd < 0) {
      if (errno != EINTR) {
        fputs("Failed to accept IPC connection from client", stderr);
        return -1;
      }
    }

    ipc_register_client(fd);
  }

  return fd;
}

int
ipc_recv_message(int fd, uint8_t *msg_type, uint32_t *reply_size,
                     uint8_t **reply)
{
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

int
ipc_read_client(int fd, uint8_t *msg_type, uint32_t *msg_size, uint8_t **msg)
{
  int ret = ipc_recv_message(fd, msg_type, msg_size, msg);

  if (ret < 0) {
    // Will happen if these errors occur while reading header
    if (ret == -1 &&
        (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
      return -2;

    return -1;
  }


  fprintf(stderr, "[fd %d] ", fd);
  fprintf(stderr, "Received message: '%s' ", (char *)(*msg));
  fprintf(stderr, "Message type: %" PRIu8 " ", *msg_type);
  fprintf(stderr, "Message size: %" PRIu32 "\n", *msg_size);

  return 0;
}

int
ipc_drop_client(int fd)
{
  int res = close(fd);
  // TODO: Remove client from queue

  if (res == 0) {
    fprintf(stderr, "Successfully removed client on fd %d\n", fd);
  } else if (res < 0 && res != EINTR) {
    fprintf(stderr, "Failed to close fd %d\n", fd);
  }

  return res;
}

int
ipc_command_str_to_int(const char* command)
{
  int command_num = -1;

  if (strcmp(command, "view") == 0)
    command_num = IPC_COMMAND_VIEW;
  else if (strcmp(command, "toggleview") == 0)
    command_num = IPC_COMMAND_TOGGLE_VIEW;
  else if (strcmp(command, "tag") == 0)
    command_num = IPC_COMMAND_TAG;
  else if (strcmp(command, "toggletag") == 0)
    command_num = IPC_COMMAND_TOGGLE_TAG;
  else if (strcmp(command, "tagmon") == 0)
    command_num = IPC_COMMAND_TAG_MONITOR;
  else if (strcmp(command, "focusmon") == 0)
    command_num = IPC_COMMAND_FOCUS_MONITOR;
  else if (strcmp(command, "focusstack") == 0)
    command_num = IPC_COMMAND_FOCUS_STACK;
  else if (strcmp(command, "zoom") == 0)
    command_num = IPC_COMMAND_ZOOM;
  else if (strcmp(command, "spawn") == 0)
    command_num = IPC_COMMAND_SPAWN;
  else if (strcmp(command, "incnmaster") == 0)
    command_num = IPC_COMMAND_INC_NMASTER;
  else if (strcmp(command, "killclient") == 0)
    command_num = IPC_COMMAND_KILL_CLIENT;
  else if (strcmp(command, "togglefloating") == 0)
    command_num = IPC_COMMAND_TOGGLE_FLOATING;
  else if (strcmp(command, "setmfact") == 0)
    command_num = IPC_COMMAND_SET_MFACT;
  else if (strcmp(command, "setlayout") == 0)
    command_num = IPC_COMMAND_SET_LAYOUT;
  else if (strcmp(command, "quit") == 0)
    command_num = IPC_COMMAND_QUIT;

  return command_num;
}

int
ipc_parse_run_command(const uint8_t *msg, int *argc, Arg **args[])
{
  char error_buffer[100];
  yajl_val parent = yajl_tree_parse((char*)msg, error_buffer, 100);

  if (parent == NULL) {
    fputs("Failed to parse command from client\n", stderr);
    fprintf(stderr, "%s\n", error_buffer);
    return -1;
  }

  // Format:
  // {
  //   "command": "<command name>"
  //   "args": [ "arg1", "arg2" ]
  // }
  const char *command_path[] = {"command", 0};
  yajl_val command_val = yajl_tree_get(parent, command_path, yajl_t_string);

  if (command_val == NULL) {
    fputs("No command key found in client message\n", stderr);
    return -1;
  }

  const char* command = YAJL_GET_STRING(command_val);
  fprintf(stderr, "Received command: %s\n", command);

  int command_num;
  if ((command_num = ipc_command_str_to_int(command)) < 0)
      return -1;

  const char *args_path[] = {"args", 0};
  yajl_val args_val = yajl_tree_get(parent, args_path, yajl_t_array);

  if (args_val == NULL) {
    fputs("No args key found in client message\n", stderr);
    return -1;
  }

  *argc = args_val->u.array.len;

  if (*argc == 0) {
    *args = (Arg**)(malloc(sizeof(Arg*)));
    (*args)[0] = (Arg*)(malloc(sizeof(Arg)));
    (*args)[0]->f = 0;
    argc++;
  } else if (*argc > 0) {
    *args = (Arg**)(malloc(sizeof(Arg*) * (*argc)));

    for (int i = 0; i < *argc; i++) {
      yajl_val arg_val = args_val->u.array.values[i];

      (*args)[i] = (Arg*)malloc(sizeof(Arg));

      if (YAJL_IS_NUMBER(arg_val)) {
        if (YAJL_IS_INTEGER(arg_val)) {
          if (YAJL_GET_INTEGER(arg_val) < 0) {
            (*args)[i]->i = YAJL_GET_INTEGER(arg_val);
            fprintf(stderr, "i=%d\n", (*args)[i]->i);
          } else {
            (*args)[i]->ui = YAJL_GET_INTEGER(arg_val);
            fprintf(stderr, "ui=%d\n", (*args)[i]->i);
          }
        } else {
          (*args)[i]->f = (float)YAJL_GET_DOUBLE(arg_val);
          fprintf(stderr, "f=%f\n", (*args)[i]->f);
        }
      } else if (YAJL_IS_STRING(arg_val)) {
        char* arg_s = YAJL_GET_STRING(arg_val);
        size_t arg_s_size = (strlen(arg_s) + 1) * sizeof(char);
        (*args)[i]->v = (void*)malloc(arg_s_size);
        strcpy((char*)(*args)[i], arg_s);
      }
    }
  }

  yajl_tree_free(parent);

  return command_num;
}

// TODO: Cleanup socket
