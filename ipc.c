#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <yajl/yajl_tree.h>
#include <yajl/yajl_gen.h>
#include <stdarg.h>

#include "ipc.h"
#include "util.h"
#include "IPCClient.h"
#include "yajl_dumps.h"

static IPCClientList ipc_clients = NULL;
static int epoll_fd = -1;
static int sock_fd = -1;
static IPCCommand *ipc_commands;
static int ipc_commands_len;
// Max size is 1 MB
const uint32_t MAX_MESSAGE_SIZE = 1000000;

static int
ipc_create_socket(const char *filename)
{
  struct sockaddr_un addr;
  char *normal_filename;
  char *parent;
  const size_t addr_size = sizeof(struct sockaddr_un);
  const int sock_type = SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC;

  normalizepath(filename, &normal_filename);

  // In case socket file exists
  unlink(normal_filename);

  // For portability clear the addr structure, since some implementations have
  // nonstandard fields in the structure
  memset(&addr, 0, addr_size);

  parentdir(normal_filename, &parent);
  // Create parent directories
  mkdirp(parent);
  free(parent);

  addr.sun_family = AF_LOCAL;
  strcpy(addr.sun_path, normal_filename);
  free(normal_filename);

  sock_fd = socket(AF_LOCAL, sock_type, 0);
  if (sock_fd == -1) {
    fputs("Failed to create socket\n", stderr);
    return -1;
  }

  fprintf(stderr, "Created socket at %s\n", addr.sun_path);

  if (bind(sock_fd, (const struct sockaddr *)&addr, addr_size) == -1) {
    fputs("Failed to bind socket\n", stderr);
    return -1;
  }

  fprintf(stderr, "Socket binded\n");

  if (listen(sock_fd, 5) < 0) {
    fputs("Failed to listen for connections on socket\n", stderr);
    return -1;
  }

  fprintf(stderr, "Now listening for connections on socket\n");

  return sock_fd;
}

static int
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

  if (*reply_size > MAX_MESSAGE_SIZE) {
    fprintf(stderr, "Message too long: %"PRIu32" bytes. ", *reply_size);
    fprintf(stderr, "Maximum message size is: %d\n", MAX_MESSAGE_SIZE);
    return -4;
  }

  // Extract message type
  memcpy(msg_type, walk, sizeof(uint8_t));
  walk += sizeof(uint8_t);

  (*reply) = malloc(*reply_size);

  read_bytes = 0;
  while (read_bytes < *reply_size) {
    const int n = read(fd, *reply + read_bytes, *reply_size - read_bytes);

    if (n == 0) {
      fprintf(stderr, "Unexpectedly reached EOF while reading payload.");
      fprintf(stderr, "Read %" PRIu32 " bytes, expected %" PRIu32 " bytes.\n",
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

static ssize_t
ipc_write_message(int fd, const void *buf, size_t count)
{
  size_t written = 0;

  while (written < count) {
    const ssize_t n = write(fd, (uint8_t*)buf + written, count - written);

    if (n == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return written;
      else if (errno == EINTR)
        continue;
      else
        return n;
    }

    written += n;
    fprintf(stderr, "Wrote %d/%d to client at fd %d\n", (int)written, (int)count, fd);
  }

  return written;
}

static void
ipc_event_init_message(yajl_gen *gen)
{
  *gen = yajl_gen_alloc(NULL);
  yajl_gen_config(*gen, yajl_gen_beautify, 1);
}

static void
ipc_event_prepare_send_message(yajl_gen gen, IPCEvent event)
{
  const unsigned char *buffer;
  size_t len = 0;

  yajl_gen_get_buf(gen, &buffer, &len);
  len++; // For null char

  for (IPCClient *c = ipc_clients; c; c = c->next) {
    if (c->subscriptions & event) {
      fprintf(stderr, "Sending selected client change event to fd %d\n", c->fd);
      ipc_prepare_send_message(c, IPC_TYPE_EVENT, len, (char *)buffer);
    }
  }

  // Not documented, but this frees temp_buffer
  yajl_gen_free(gen);
}

static void
ipc_reply_init_message(yajl_gen *gen)
{
  *gen = yajl_gen_alloc(NULL);
  yajl_gen_config(*gen, yajl_gen_beautify, 1);
}

static void
ipc_reply_prepare_send_message(yajl_gen gen, IPCClient *c, IPCMessageType
    msg_type)
{
  const unsigned char *buffer;
  size_t len = 0;

  yajl_gen_get_buf(gen, &buffer, &len);
  len++; // For null char

  ipc_prepare_send_message(c, msg_type, len, (const char*)buffer);

  // Not documented, but this frees temp_buffer
  yajl_gen_free(gen);
}

static int
ipc_get_ipc_command(const char* name, IPCCommand *ipc_command)
{
  for (int i = 0; i < ipc_commands_len; i++) {
    if (strcmp(ipc_commands[i].command_name, name) == 0) {
      *ipc_command = ipc_commands[i];
      return 0;
    }
  }

  return -1;
}

static int
ipc_parse_run_command(char *msg, char **name, unsigned int *argc,
    Arg *args[])
{
  char error_buffer[1000];
  yajl_val parent = yajl_tree_parse(msg, error_buffer, 1000);

  if (parent == NULL) {
    fputs("Failed to parse command from client\n", stderr);
    fprintf(stderr, "%s\n", error_buffer);
    fprintf(stderr, "Tried to parse: %s\n", msg);
    return -1;
  }

  // Format:
  // {
  //   "command": "<command name>"
  //   "args": [ "arg1", "arg2", ... ]
  // }
  const char *command_path[] = {"command", 0};
  yajl_val command_val = yajl_tree_get(parent, command_path, yajl_t_string);

  if (command_val == NULL) {
    fputs("No command key found in client message\n", stderr);
    yajl_tree_free(parent);
    return -1;
  }

  const char* command = YAJL_GET_STRING(command_val);
  const size_t command_size = sizeof(char) * (strlen(command) + 1);
  *name = (char*)malloc(command_size);
  strcpy(*name, command);
  fprintf(stderr, "Received command: %s\n", command);

  IPCCommand ipc_command;
  if (ipc_get_ipc_command(*name, &ipc_command) < 0) {
    fprintf(stderr, "IPC Command %s not found\n", *name);
    yajl_tree_free(parent);
    return -1;
  }

  const char *args_path[] = {"args", 0};
  yajl_val args_val = yajl_tree_get(parent, args_path, yajl_t_array);

  if (args_val == NULL) {
    fputs("No args key found in client message\n", stderr);
    yajl_tree_free(parent);
    return -1;
  }

  *argc = args_val->u.array.len;

  // TODO: Refactor this and make it less ugly. Maybe split into functions
  if (*argc == 0 && ipc_command.argc == 1 &&
      *ipc_command.arg_types == ARG_TYPE_NONE) {
    *args = (Arg*)(malloc(sizeof(Arg)));
    (*args)[0].f = 0;
    (*argc)++;
  } else if (*argc > 0 && *argc == ipc_command.argc) {
    *args = (Arg*)calloc(*argc, sizeof(Arg));

    for (int i = 0; i < *argc; i++) {
      yajl_val arg_val = args_val->u.array.values[i];
      ArgType exp_type = ipc_command.arg_types[i];

      if (YAJL_IS_NUMBER(arg_val)) {
        if (YAJL_IS_INTEGER(arg_val)) {
          if (YAJL_GET_INTEGER(arg_val) <= 0 && exp_type == ARG_TYPE_SINT) {
            (*args)[i].i = YAJL_GET_INTEGER(arg_val);
            fprintf(stderr, "i=%d\n", (*args)[i].i);
          } else if (YAJL_GET_INTEGER(arg_val) > 0 &&
                     (exp_type == ARG_TYPE_SINT || exp_type == ARG_TYPE_UINT)) {
            (*args)[i].ui = YAJL_GET_INTEGER(arg_val);
            fprintf(stderr, "ui=%d\n", (*args)[i].i);
          } else if (YAJL_GET_INTEGER(arg_val) && exp_type == ARG_TYPE_PTR) {
            (*args)[i].v = (void*)YAJL_GET_INTEGER(arg_val);
            fprintf(stderr, "v=%p\n", (*args)[i].v);
          } else {
            fprintf(stderr, "Invalid arg: expected ArgType %d\n",  exp_type);
            yajl_tree_free(parent);
            return -1;
          }
        } else if (exp_type == ARG_TYPE_FLOAT) {
          (*args)[i].f = (float)YAJL_GET_DOUBLE(arg_val);
          fprintf(stderr, "f=%f\n", (*args)[i].f);
        } else {
          fprintf(stderr, "Invalid arg: expected ArgType %d\n",  exp_type);
          yajl_tree_free(parent);
          return -1;
        }
      } else if (YAJL_IS_STRING(arg_val) && exp_type == ARG_TYPE_STR) {
        char* arg_s = YAJL_GET_STRING(arg_val);
        size_t arg_s_size = (strlen(arg_s) + 1) * sizeof(char);
        (*args)[i].v = (char*)malloc(arg_s_size);
        strcpy((char*)(*args)[i].v, arg_s);
      }
      else {
        fprintf(stderr, "Invalid arg: expected ArgType %d\n",  exp_type);
        yajl_tree_free(parent);
        return -1;
      }
    }
  } else {
    fprintf(stderr, "Got %d args for command %s, expected %d", *argc, *name,
        ipc_command.argc);
    yajl_tree_free(parent);
    return -1;
  }

  yajl_tree_free(parent);

  return 0;
}

static int
ipc_parse_subscribe(const char *msg, IPCSubscriptionAction *subscribe, IPCEvent *event)
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
  //   "event": "<event name>"
  //   "action": "<subscribe|unsubscribe>"
  // }
  const char *event_path[] = {"event", 0};
  yajl_val event_val = yajl_tree_get(parent, event_path, yajl_t_string);

  if (event_val == NULL) {
    fputs("No 'event' key found in client message\n", stderr);
    return -1;
  }

  const char* event_str = YAJL_GET_STRING(event_val);
  fprintf(stderr, "Received event: %s\n", event_str);

  if (ipc_event_stoi(event_str, event) < 0)
    return -1;

  const char *action_path[] = {"action", 0};
  yajl_val action_val = yajl_tree_get(parent, action_path, yajl_t_string);

  if (action_val == NULL) {
    fputs("No 'action' key found in client message\n", stderr);
    return -1;
  }

  const char* action = YAJL_GET_STRING(action_val);

  if (strcmp(action, "subscribe") == 0)
    *subscribe = IPC_ACTION_SUBSCRIBE;
  else if (strcmp(action, "unsubscribe") == 0)
    *subscribe = IPC_ACTION_UNSUBSCRIBE;
  else {
    fputs("Invalid action specified for subscription\n", stderr);
    return -1;
  }

  yajl_tree_free(parent);

  return 0;
}

static int
ipc_parse_get_dwm_client(const char *msg, Window *win)
{
  char error_buffer[100];

  yajl_val parent = yajl_tree_parse(msg, error_buffer, 100);

  if (parent == NULL) {
    fputs("Failed to parse message from client\n", stderr);
    fprintf(stderr, "%s\n", error_buffer);
    return -1;
  }

  // Format:
  // {
  //   "client_window_id": <client window id>
  // }
  const char *win_path[] = {"client_window_id", 0};
  yajl_val win_val = yajl_tree_get(parent, win_path, yajl_t_number);

  if (win_val == NULL) {
    fputs("No client window id found in client message\n", stderr);
    return -1;
  }

  *win = YAJL_GET_INTEGER(win_val);

  yajl_tree_free(parent);

  return 0;
}

int
ipc_init(const char *socket_path, const int p_epoll_fd,
    IPCCommand commands[], const int commands_len)
{
  struct epoll_event event;

  // Initialize struct to 0
  memset(&event, 0, sizeof(event));

  int socket_fd = ipc_create_socket(socket_path);
  if (socket_fd < 0) return -1;;

  ipc_commands = commands;
  ipc_commands_len = commands_len;

  epoll_fd = p_epoll_fd;

  event.data.fd = socket_fd;
  event.events = EPOLLIN;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket_fd, &event)) {
    fputs("Failed to add sock file descripttor to epoll", stderr);
    return -1;
  }

  return socket_fd;
}

IPCClient*
ipc_get_client(int fd)
{
  return ipc_list_get_client(ipc_clients, fd);
}

int
ipc_accept_client(struct epoll_event *event)
{
  fputs("In accept client function\n", stderr);
  int fd = -1;

  if (event->events & EPOLLIN) {
    struct sockaddr_un client_addr;
    socklen_t len = 0;

    // For portability clear the addr structure, since some implementations
    // have nonstandard fields in the structure
    memset(&client_addr, 0, sizeof(struct sockaddr_un));

    fd = accept(sock_fd, (struct sockaddr *)&client_addr, &len);
    if (fd < 0 && errno != EINTR) {
      fputs("Failed to accept IPC connection from client", stderr);
      return -1;
    }

    IPCClient *nc = ipc_client_new(fd);
    if (nc == NULL) return -1;

    nc->event.data.fd = fd;
    nc->event.events = EPOLLIN | EPOLLHUP;

    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &nc->event);

    ipc_list_add_client(&ipc_clients, nc);

    fprintf(stderr, "%s%d\n", "New client at fd: ", fd);
  }

  return fd;
}

int
ipc_read_client(IPCClient *c, IPCMessageType *msg_type, uint32_t *msg_size, char **msg)
{
  int ret = ipc_recv_message(c->fd, (uint8_t *)msg_type, msg_size,
      (uint8_t **)msg);

  if (ret < 0) {
    // Will happen if these errors occur while reading header
    if (ret == -1 &&
        (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
      return -2;

    fprintf(stderr, "Error reading message: dropping client at fd %d\n", c->fd);
    ipc_drop_client(c);

    return -1;
  }

  size_t len = *msg_size;
  nullterminate(msg, &len);
  *msg_size = len;

  fprintf(stderr, "[fd %d] ", c->fd);
  fprintf(stderr, "Received message: '%.*s' ", *msg_size, *msg);
  fprintf(stderr, "Message type: %" PRIu8 " ", *msg_type);
  fprintf(stderr, "Message size: %" PRIu32 "\n", *msg_size);

  return 0;
}

int
ipc_drop_client(IPCClient *c)
{
  int res = close(c->fd);

  if (res == 0) {
    struct epoll_event ev;

    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, c->fd, &ev);
    ipc_list_remove_client(&ipc_clients, c);
    free(c);

    fprintf(stderr, "Successfully removed client on fd %d\n", c->fd);
  } else if (res < 0 && res != EINTR) {
    fprintf(stderr, "Failed to close fd %d\n", c->fd);
  }

  return res;
}

int
ipc_run_command(IPCClient *ipc_client, char *msg)
{
  char *name;
  unsigned int argc;
  Arg *args;
  IPCCommand ipc_command;

  if (ipc_parse_run_command(msg, &name, &argc, &args) < 0) {
    ipc_prepare_reply_failure(ipc_client, IPC_TYPE_RUN_COMMAND,
        "Failed to parse run command");
    return -1;
  }

  ipc_get_ipc_command(name, &ipc_command);

  if (argc == 1)
    ipc_command.func.single_param(args);
  else if (argc > 1)
    ipc_command.func.array_param(args, argc);

  fprintf(stderr, "Called function for command %s\n", ipc_command.command_name);
  for (int i = 0; i < argc; i++) {
    if (ipc_command.arg_types[i] == ARG_TYPE_STR)
      free((void *)args[i].v);
  }

  ipc_prepare_reply_success(ipc_client, IPC_TYPE_RUN_COMMAND);
  free(args);
  free(name);
  return 0;
}

void
ipc_prepare_send_message(IPCClient *c, const IPCMessageType msg_type,
                         const uint32_t msg_size, const char *msg)
{
  dwm_ipc_header_t header = {
    .magic = IPC_MAGIC_ARR,
    .type = msg_type,
    .size = msg_size
  };

  uint32_t header_size = sizeof(dwm_ipc_header_t);
  uint32_t packet_size = header_size + msg_size;

  if (c->buffer_size == 0)
    c->buffer = (char*)malloc(c->buffer_size + packet_size);
  else
    c->buffer = (char*)realloc(c->buffer, c->buffer_size + packet_size);

  memcpy(c->buffer + c->buffer_size, &header, header_size);
  c->buffer_size += header_size;

  memcpy(c->buffer + c->buffer_size, msg, msg_size);
  c->buffer_size += msg_size;

  c->event.events |= EPOLLOUT;
  epoll_ctl(epoll_fd, EPOLL_CTL_MOD, c->fd, &c->event);
}

int
ipc_push_pending(IPCClient *c)
{
  const ssize_t n = ipc_write_message(c->fd, c->buffer, c->buffer_size);

  if (n < 0) return n;

  // TODO: Deal with client timeouts

  if (n == c->buffer_size) {
      c->buffer_size = 0;
      free(c->buffer);
      if (c->event.events & EPOLLOUT) {
        c->event.events -= EPOLLOUT;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, c->fd, &c->event);
      }
      return n;
  }

  c->buffer_size -= n;
  memmove(c->buffer, c->buffer + n, c->buffer_size);
  c->buffer = (char*)realloc(c->buffer, c->buffer_size);

  return n;
}

void
ipc_get_monitors(IPCClient *c, Monitor *mons)
{
  yajl_gen gen;
  ipc_reply_init_message(&gen);
  yajl_gen_array_open(gen);

  for (Monitor *mon = mons; mon; mon = mon->next)
    dump_monitor(gen, mon);

  yajl_gen_array_close(gen);

  ipc_reply_prepare_send_message(gen, c, IPC_TYPE_GET_MONITORS);
}

void
ipc_get_tags(IPCClient *c, const char *tags[], const int tags_len)
{
  yajl_gen gen;
  ipc_reply_init_message(&gen);

  dump_tags(gen, tags, tags_len);

  ipc_reply_prepare_send_message(gen, c, IPC_TYPE_GET_TAGS);
}

void
ipc_get_layouts(IPCClient *c, const Layout layouts[], const int layouts_len)
{
  yajl_gen gen;
  ipc_reply_init_message(&gen);

  dump_layouts(gen, layouts, layouts_len);

  ipc_reply_prepare_send_message(gen, c, IPC_TYPE_GET_LAYOUTS);
}

int ipc_get_dwm_client(IPCClient *ipc_client, const char *msg,
    const Monitor *mons)
{
  Window win;

  if (ipc_parse_get_dwm_client(msg, &win) < 0)
    return -1;

	for (const Monitor *m = mons; m; m = m->next)
		for (Client *c = m->clients; c; c = c->next)
      if (c->win == win) {
        yajl_gen gen;
        ipc_reply_init_message(&gen);

        dump_client(gen, c);

        ipc_reply_prepare_send_message(gen, ipc_client,
            IPC_TYPE_GET_DWM_CLIENT);

        return 0;
      }

  ipc_prepare_reply_failure(ipc_client, IPC_TYPE_GET_DWM_CLIENT,
      "Client with window id %d not found", win);
  return -1;
}

int
ipc_event_stoi(const char *subscription, IPCEvent *event)
{
  if (strcmp(subscription, "tag_change_event") == 0)
    *event = IPC_EVENT_TAG_CHANGE;
  else if (strcmp(subscription, "selected_client_change_event") == 0)
    *event = IPC_EVENT_SELECTED_CLIENT_CHANGE;
  else if (strcmp(subscription, "layout_change_event") == 0)
    *event = IPC_EVENT_LAYOUT_CHANGE;
  else
    return -1;
  return 0;
}

int
ipc_subscribe(IPCClient *c, const char *msg)
{
  IPCSubscriptionAction action = IPC_ACTION_SUBSCRIBE;
  IPCEvent event = 0;

  if (ipc_parse_subscribe(msg, &action, &event)) {
    ipc_prepare_reply_failure(c, IPC_TYPE_SUBSCRIBE, "Event does not exist");
    return -1;
  }

  if (action == IPC_ACTION_SUBSCRIBE) {
    fprintf(stderr, "Subscribing client on fd %d to %d\n", c->fd, event);
    c->subscriptions |= event;
  } else if (action == IPC_ACTION_UNSUBSCRIBE) {
    fprintf(stderr, "Unsubscribing client on fd %d to %d\n", c->fd, event);
    c->subscriptions ^= event;
  } else {
    ipc_prepare_reply_failure(c, IPC_TYPE_SUBSCRIBE,
        "Invalid subscription action");
    return -1;
  }

  ipc_prepare_reply_success(c, IPC_TYPE_SUBSCRIBE);
  return 0;
}

void
ipc_prepare_reply_failure(IPCClient *c, IPCMessageType msg_type,
    const char* format, ...)
{
  va_list args;
  yajl_gen gen;

  size_t len = vsnprintf(NULL, 0, format, args);
  char buffer[len + 1];

  ipc_reply_init_message(&gen);

  va_start(args, format);
  vsnprintf(buffer, len + 1, format, args);
  dump_error_message(gen, buffer);

  ipc_reply_prepare_send_message(gen, c, msg_type);
  fprintf(stderr, "[fd %d] Error: %s\n", c->fd, buffer);

  va_end(args);
}

void
ipc_prepare_reply_success(IPCClient *c, IPCMessageType msg_type)
{
  const char *success_msg = "{\"result\":\"success\"}";
  const size_t msg_len = strlen(success_msg) + 1; // +1 for null char

  ipc_prepare_send_message(c, msg_type, msg_len, success_msg);
}

void
ipc_tag_change_event(int mon_num, TagState old, TagState new)
{
  yajl_gen gen;
  ipc_event_init_message(&gen);
  dump_tag_event(gen, mon_num, old, new);
  ipc_event_prepare_send_message(gen, IPC_EVENT_TAG_CHANGE);
}

void
ipc_selected_client_change_event(Client *old_client, Client *new_client,
    int mon_num)
{
  yajl_gen gen;
  ipc_event_init_message(&gen);
  dump_client_change_event(gen, old_client, new_client, mon_num);
  ipc_event_prepare_send_message(gen, IPC_EVENT_SELECTED_CLIENT_CHANGE);
}

void
ipc_layout_change_event(const int mon_num, const char *old_symbol,
    const char *new_symbol)
{
  yajl_gen gen;
  ipc_event_init_message(&gen);
  dump_layout_change_event(gen, mon_num, old_symbol, new_symbol);
  ipc_event_prepare_send_message(gen, IPC_EVENT_LAYOUT_CHANGE);
}

int
ipc_is_client_registered(int fd)
{
  return (ipc_get_client(fd) != NULL);
}

void
ipc_cleanup(int sock_fd)
{
  IPCClient *c = ipc_clients;
  while (c) {
    IPCClient *next = c->next;
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, c->fd, &c->event);

    if (c->buffer_size != 0) free(c->buffer);

    free(c);
    c = next;
  }

  shutdown(sock_fd, SHUT_RDWR);
}
