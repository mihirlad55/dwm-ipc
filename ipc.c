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

#include "ipc.h"

static IPCClient *ipc_client_head;

static IPCClient*
ipc_init_client(int fd)
{
  IPCClient* c = (IPCClient*)malloc(sizeof(IPCClient));

  if (c == NULL) return NULL;

  c->buffer_size = 0;
  c->buffer = NULL;
  c->fd = fd;
  c->next = NULL;
  c->prev = NULL;
  c->subscriptions = 0;

  return c;
}

static void
ipc_list_add_client(IPCClient *nc)
{
  fprintf(stderr, "Adding client with fd %d to list\n", nc->fd);
  if (ipc_client_head == NULL) {
    ipc_client_head = nc;
  } else {
    IPCClient *c;
    for (c = ipc_client_head; c && c->next; c = c->next);
    c->next = nc;
    nc->prev = c;
  }
}

static void
ipc_list_remove_client(IPCClient *c)
{
  for (c = ipc_client_head; c && c->next; c = c->next);

  IPCClient *cprev = c->prev;
  IPCClient *cnext = c->next;

  if (cprev != NULL) cprev->next = c->next;
  if (cnext != NULL) cnext->prev = c->prev;
  if (c == ipc_client_head) ipc_client_head = c->next;
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

static int
dump_client(yajl_gen gen, Client *c)
{
  yajl_gen_map_open(gen);

  ystr("name"); ystr(c->name);
  ystr("mina"); yajl_gen_double(gen, c->mina);
  ystr("maxa"); yajl_gen_double(gen, c->maxa);
  ystr("tags"); yajl_gen_integer(gen, c->tags);
  ystr("window_id"); yajl_gen_integer(gen, c->win);

  ystr("size");
  yajl_gen_map_open(gen);
  ystr("x"); yajl_gen_integer(gen, c->x);
  ystr("y"); yajl_gen_integer(gen, c->y);
  ystr("width"); yajl_gen_integer(gen, c->w);
  ystr("height"); yajl_gen_integer(gen, c->h);
  yajl_gen_map_close(gen);

  ystr("old_size");
  yajl_gen_map_open(gen);
  ystr("x"); yajl_gen_integer(gen, c->oldx);
  ystr("y"); yajl_gen_integer(gen, c->oldy);
  ystr("width"); yajl_gen_integer(gen, c->oldw);
  ystr("height"); yajl_gen_integer(gen, c->oldh);
  yajl_gen_map_close(gen);

  ystr("size_hints");
  yajl_gen_map_open(gen);
  ystr("base_width"); yajl_gen_integer(gen, c->basew);
  ystr("base_height"); yajl_gen_integer(gen, c->baseh);
  ystr("increase_width"); yajl_gen_integer(gen, c->incw);
  ystr("increase_height"); yajl_gen_integer(gen, c->inch);
  ystr("max_width"); yajl_gen_integer(gen, c->maxw);
  ystr("max_height"); yajl_gen_integer(gen, c->maxh);
  ystr("min_width"); yajl_gen_integer(gen, c->minw);
  ystr("min_height"); yajl_gen_integer(gen, c->minh);
  yajl_gen_map_close(gen);

  ystr("border");
  yajl_gen_map_open(gen);
  ystr("border_width"); yajl_gen_integer(gen, c->bw);
  ystr("old_border_width"); yajl_gen_integer(gen, c->oldbw);
  yajl_gen_map_close(gen);

  ystr("states");
  yajl_gen_map_open(gen);
  ystr("is_fixed"); yajl_gen_bool(gen, c->isfixed);
  ystr("is_floating"); yajl_gen_bool(gen, c->isfloating);
  ystr("is_urgent"); yajl_gen_bool(gen, c->isurgent);
  ystr("is_fullscreen"); yajl_gen_bool(gen, c->isfullscreen);
  ystr("never_focus"); yajl_gen_bool(gen, c->neverfocus);
  ystr("old_state"); yajl_gen_bool(gen, c->oldstate);
  yajl_gen_map_close(gen);

  yajl_gen_map_close(gen);

  return 0;
}

static int
dump_monitor(yajl_gen gen, Monitor *mon)
{
  yajl_gen_map_open(gen);

  ystr("layout_symbol"); ystr(mon->ltsymbol);
  ystr("mfact"); yajl_gen_double(gen, mon->mfact);
  ystr("nmaster"); yajl_gen_integer(gen, mon->nmaster);
  ystr("num"); yajl_gen_integer(gen, mon->num);
  ystr("bar_y"); yajl_gen_integer(gen, mon->by);
  ystr("selected_tags"); yajl_gen_integer(gen, mon->seltags);
  ystr("selected_layout"); yajl_gen_integer(gen, mon->sellt);
  ystr("show_bar"); yajl_gen_bool(gen, mon->showbar);
  ystr("top_bar"); yajl_gen_bool(gen, mon->topbar);

  ystr("screen");
  yajl_gen_map_open(gen);
  ystr("x"); yajl_gen_integer(gen, mon->mx);
  ystr("y"); yajl_gen_integer(gen, mon->my);
  ystr("width"); yajl_gen_integer(gen, mon->mw);
  ystr("height"); yajl_gen_integer(gen, mon->mh);
  yajl_gen_map_close(gen);

  ystr("window");
  yajl_gen_map_open(gen);
  ystr("x"); yajl_gen_integer(gen, mon->wx);
  ystr("y"); yajl_gen_integer(gen, mon->wy);
  ystr("width"); yajl_gen_integer(gen, mon->ww);
  ystr("height"); yajl_gen_integer(gen, mon->wh);
  yajl_gen_map_close(gen);

  ystr("tag_set");
  yajl_gen_array_open(gen);
  yajl_gen_integer(gen, mon->tagset[0]);
  yajl_gen_integer(gen, mon->tagset[1]);
  yajl_gen_array_close(gen);

  ystr("Layouts");
  yajl_gen_array_open(gen);
  ystr(mon->lt[0]->symbol);
  ystr(mon->lt[1]->symbol);
  yajl_gen_array_close(gen);

  ystr("selected_client");
  dump_client(gen, mon->sel);

  ystr("stack");
  yajl_gen_array_open(gen);
  for (Client* c = mon->clients; c; c = c->snext)
    dump_client(gen, c);
  yajl_gen_array_close(gen);

  yajl_gen_map_close(gen);

  return 0;
}

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

IPCClient*
ipc_list_get_client(int fd)
{
  for (IPCClient *c = ipc_client_head; c; c = c->next) {
    if (c->fd == fd) return c;
  }

  return NULL;
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

    IPCClient *nc = ipc_init_client(fd);
    if (nc == NULL) return -1;

    ipc_list_add_client(nc);

    fprintf(stderr, "%s%d\n", "New client at fd: ", fd);
  }

  return fd;
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
  IPCClient *c = ipc_list_get_client(fd);
  ipc_list_remove_client(c);

  free(c);

  int res = close(fd);

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

void
ipc_prepare_send_message(IPCClient *c, uint8_t msg_type, uint32_t msg_size,
    uint8_t *msg)
{
  dwm_ipc_header_t header = {
    .magic = IPC_MAGIC_ARR,
    .type = msg_type,
    .size = msg_size
  };

  uint32_t header_size = sizeof(dwm_ipc_header_t);
  uint32_t packet_size = header_size + msg_size;

  c->buffer = (char*)realloc(c->buffer, c->buffer_size + packet_size);

  memcpy(c->buffer + c->buffer_size, &header, header_size);
  c->buffer_size += header_size;

  memcpy(c->buffer + c->buffer_size, msg, msg_size);
  c->buffer_size += msg_size;
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
      return n;
  }

  c->buffer_size -= n;
  memmove(c->buffer, c->buffer + n, c->buffer_size);
  c->buffer = (char*)realloc(c->buffer, c->buffer_size);

  return n;
}

int
ipc_get_monitors(Monitor *selmon, unsigned char **buffer, size_t *len)
{
  const unsigned char *temp_buffer;

  yajl_gen gen = yajl_gen_alloc(NULL);
  yajl_gen_config(gen, yajl_gen_beautify, 1);

  yajl_gen_array_open(gen);

  for (Monitor *mon = selmon; mon; mon = mon->next)
    dump_monitor(gen, mon);

  yajl_gen_array_close(gen);

  yajl_gen_get_buf(gen, &temp_buffer, len);

  *buffer = (unsigned char*)malloc(sizeof(unsigned char*) * (*len));
  memmove(*buffer, temp_buffer, *len);

  // Not documented, but this frees temp_buffer
  yajl_gen_free(gen);

  return 0;
}

void
ipc_cleanup(int sock_fd)
{
  IPCClient *c = ipc_client_head;
  while (c) {
    IPCClient *next = c->next;

    if (c->buffer_size != 0) free(c->buffer);

    free(c);
    c = next;
  }

  shutdown(sock_fd, SHUT_RDWR);
}
