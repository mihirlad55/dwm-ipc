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

static IPCClient *ipc_client_head = NULL;
static int epoll_fd = -1;

static int
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

static IPCClient*
ipc_init_client(int fd)
{
  IPCClient* c = (IPCClient*)malloc(sizeof(IPCClient));

  if (c == NULL) return NULL;

  c->buffer_size = 0;
  c->buffer = NULL;
  c->fd = fd;
  c->event.data.fd = fd;
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
dump_tags(yajl_gen gen, const char *tags[], int tags_len)
{
  yajl_gen_array_open(gen);
  for (int i = 0; i < tags_len; i++) {
    yajl_gen_map_open(gen);
    ystr("bit_mask"); yajl_gen_integer(gen, 1 << i);
    ystr("name"); ystr(tags[i]);
    yajl_gen_map_close(gen);
  }
  yajl_gen_array_close(gen);
  return 0;
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
  ystr("monitor_number"); yajl_gen_integer(gen, c->mon->num);

  ystr("size");
  yajl_gen_map_open(gen);
  ystr("current");
  yajl_gen_map_open(gen);
  ystr("x"); yajl_gen_integer(gen, c->x);
  ystr("y"); yajl_gen_integer(gen, c->y);
  ystr("width"); yajl_gen_integer(gen, c->w);
  ystr("height"); yajl_gen_integer(gen, c->h);
  yajl_gen_map_close(gen);
  ystr("old");
  yajl_gen_map_open(gen);
  ystr("x"); yajl_gen_integer(gen, c->oldx);
  ystr("y"); yajl_gen_integer(gen, c->oldy);
  ystr("width"); yajl_gen_integer(gen, c->oldw);
  ystr("height"); yajl_gen_integer(gen, c->oldh);
  yajl_gen_map_close(gen);
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
  ystr("current_width"); yajl_gen_integer(gen, c->bw);
  ystr("old_width"); yajl_gen_integer(gen, c->oldbw);
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
  yajl_gen_map_open(gen);
  ystr("old"); yajl_gen_integer(gen, mon->tagset[mon->seltags ^ 1]);
  ystr("current"); yajl_gen_integer(gen, mon->tagset[mon->seltags]);
  yajl_gen_map_close(gen);

  ystr("layout");
  yajl_gen_map_open(gen);
  ystr("old"); ystr(mon->lt[mon->sellt ^ 1]->symbol);
  ystr("current"); ystr(mon->lt[mon->sellt]->symbol);
  yajl_gen_map_close(gen);

  ystr("selected_client"); yajl_gen_integer(gen, mon->sel->win);

  ystr("stack");
  yajl_gen_array_open(gen);
  for (Client* c = mon->clients; c; c = c->snext)
    yajl_gen_integer(gen, c->win);
  yajl_gen_array_close(gen);

  yajl_gen_map_close(gen);

  return 0;
}

static int
dump_layouts(yajl_gen gen, const Layout layouts[], const int layouts_len)
{
  yajl_gen_array_open(gen);

  for (int i = 0; i < layouts_len; i++) {
    ystr(layouts[i].symbol);
  }

  yajl_gen_array_close(gen);

  return 0;
}

static int
dump_tag_state(yajl_gen gen, TagState state)
{
  yajl_gen_map_open(gen);
  ystr("selected"); yajl_gen_integer(gen, state.selected);
  ystr("occupied"); yajl_gen_integer(gen, state.occupied);
  ystr("urgent"); yajl_gen_integer(gen, state.urgent);
  yajl_gen_map_close(gen);

  return 0;
}

static int
dump_tag_event(yajl_gen gen, int mon_num, TagState old, TagState new)
{
  ystr("tag_change_event");
  yajl_gen_map_open(gen);

  ystr("monitor_number"); yajl_gen_integer(gen, mon_num);

  ystr("old"); dump_tag_state(gen, old);

  ystr("new"); dump_tag_state(gen, new);

  yajl_gen_map_close(gen);
  return 0;
}

static int
dump_client_change_event(yajl_gen gen, Client *old_client, Client *new_client,
  int mon_num)
{
  ystr("selected_client_change_event");
  yajl_gen_map_open(gen);

  ystr("moniter_number"); yajl_gen_integer(gen, mon_num);

  ystr("old"); dump_client(gen, old_client);

  ystr("new"); dump_client(gen ,new_client);

  yajl_gen_map_close(gen);
  return 0;
}

static void
ipc_event_init_message(yajl_gen *gen)
{
  *gen = yajl_gen_alloc(NULL);
  yajl_gen_config(*gen, yajl_gen_beautify, 1);

  yajl_gen_map_open(*gen);
}

static void
ipc_event_prepare_send_message(yajl_gen gen)
{
  const unsigned char *buffer;
  size_t len;

  yajl_gen_map_close(gen);

  yajl_gen_get_buf(gen, &buffer, &len);

  for (IPCClient *c = ipc_client_head; c; c = c->next) {
    fprintf(stderr, "Sending selected client change event to fd %d\n", c->fd);
    ipc_prepare_send_message(c, IPC_TYPE_EVENT, len, (char *)buffer);
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
ipc_reply_prepare_send_message(yajl_gen gen, IPCClient *c, uint32_t msg_type)
{
  const unsigned char *buffer;
  size_t len;

  yajl_gen_get_buf(gen, &buffer, &len);

  ipc_prepare_send_message(c, msg_type, len, (const char*)buffer);

  // Not documented, but this frees temp_buffer
  yajl_gen_free(gen);
}

int
ipc_init(const char *socket_path, const int p_epoll_fd)
{
  struct epoll_event event;

  int socket_fd = ipc_create_socket(socket_path);
  if (socket_fd < 0) return -1;;

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
    if (fd < 0 && errno != EINTR) {
      fputs("Failed to accept IPC connection from client", stderr);
      return -1;
    }

    IPCClient *nc = ipc_init_client(fd);
    if (nc == NULL) return -1;

    nc->event.data.fd = fd;
    nc->event.events = EPOLLIN | EPOLLHUP;

    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &nc->event);

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

    fprintf(stderr, "Error reading message: dropping client at fd %d", fd);
    ipc_drop_client(fd);

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

  if (res == 0) {
    struct epoll_event ev;
    IPCClient *c = ipc_list_get_client(fd);

    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ev);
    ipc_list_remove_client(c);
    free(c);

    fprintf(stderr, "Successfully removed client on fd %d\n", fd);
  } else if (res < 0 && res != EINTR) {
    fprintf(stderr, "Failed to close fd %d\n", fd);
  }

  return res;
}

int
ipc_command_stoi(const char* command)
{
  if (strcmp(command, "view") == 0)
    return IPC_COMMAND_VIEW;
  else if (strcmp(command, "toggleview") == 0)
    return IPC_COMMAND_TOGGLE_VIEW;
  else if (strcmp(command, "tag") == 0)
    return IPC_COMMAND_TAG;
  else if (strcmp(command, "toggletag") == 0)
    return IPC_COMMAND_TOGGLE_TAG;
  else if (strcmp(command, "tagmon") == 0)
    return IPC_COMMAND_TAG_MONITOR;
  else if (strcmp(command, "focusmon") == 0)
    return IPC_COMMAND_FOCUS_MONITOR;
  else if (strcmp(command, "focusstack") == 0)
    return IPC_COMMAND_FOCUS_STACK;
  else if (strcmp(command, "zoom") == 0)
    return IPC_COMMAND_ZOOM;
  else if (strcmp(command, "spawn") == 0)
    return IPC_COMMAND_SPAWN;
  else if (strcmp(command, "incnmaster") == 0)
    return IPC_COMMAND_INC_NMASTER;
  else if (strcmp(command, "killclient") == 0)
    return IPC_COMMAND_KILL_CLIENT;
  else if (strcmp(command, "togglefloating") == 0)
    return IPC_COMMAND_TOGGLE_FLOATING;
  else if (strcmp(command, "setmfact") == 0)
    return IPC_COMMAND_SET_MFACT;
  else if (strcmp(command, "setlayout") == 0)
    return IPC_COMMAND_SET_LAYOUT;
  else if (strcmp(command, "quit") == 0)
    return IPC_COMMAND_QUIT;
  else
    return -1;
}

int
ipc_parse_run_command(const uint8_t *msg, int *argc, Arg *args[])
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
  if ((command_num = ipc_command_stoi(command)) < 0)
      return -1;

  const char *args_path[] = {"args", 0};
  yajl_val args_val = yajl_tree_get(parent, args_path, yajl_t_array);

  if (args_val == NULL) {
    fputs("No args key found in client message\n", stderr);
    return -1;
  }

  *argc = args_val->u.array.len;

  if (*argc == 0) {
    *args = (Arg*)(malloc(sizeof(Arg)));
    args[0] = (Arg*)(malloc(sizeof(Arg)));
    args[0]->f = 0;
    argc++;
  } else if (*argc > 0) {
    *args = (Arg*)calloc(*argc, sizeof(Arg));

    for (int i = 0; i < *argc; i++) {
      yajl_val arg_val = args_val->u.array.values[i];

      if (YAJL_IS_NUMBER(arg_val)) {
        if (YAJL_IS_INTEGER(arg_val)) {
          if (YAJL_GET_INTEGER(arg_val) < 0) {
            (*args)[i].i = YAJL_GET_INTEGER(arg_val);
            fprintf(stderr, "i=%d\n", (*args)[i].i);
          } else {
            (*args)[i].ui = YAJL_GET_INTEGER(arg_val);
            fprintf(stderr, "ui=%d\n", (*args)[i].i);
          }
        } else {
          (*args)[i].f = (float)YAJL_GET_DOUBLE(arg_val);
          fprintf(stderr, "f=%f\n", (*args)[i].f);
        }
      } else if (YAJL_IS_STRING(arg_val)) {
        char* arg_s = YAJL_GET_STRING(arg_val);
        size_t arg_s_size = (strlen(arg_s) + 1) * sizeof(char);
        (*args)[i].v = (char*)malloc(arg_s_size);
        strcpy((char*)(*args)[i].v, arg_s);
      }
    }
  }

  yajl_tree_free(parent);

  return command_num;
}

void
ipc_prepare_send_message(IPCClient *c, const uint8_t msg_type,
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
      if (c->event.events & EPOLLOUT)
        c->event.events -= EPOLLOUT;
      epoll_ctl(epoll_fd, EPOLL_CTL_MOD, c->fd, &c->event);
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

int
ipc_parse_get_client(const uint8_t *msg, Window *win)
{
  char error_buffer[100];

  yajl_val parent = yajl_tree_parse((char*)msg, error_buffer, 100);

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

void
ipc_get_client(IPCClient *ipc_client, Client *dwm_client)
{
  yajl_gen gen;
  ipc_reply_init_message(&gen);

  dump_client(gen, dwm_client);

  ipc_reply_prepare_send_message(gen, ipc_client, IPC_TYPE_GET_CLIENT);
}

int
ipc_event_stoi(const char *subscription)
{
  if (strcmp(subscription, "tag_change_event") == 0)
    return IPC_EVENT_TAG_CHANGE;
  else if (strcmp(subscription, "window_change_event") == 0)
    return IPC_EVENT_SELECTED_CLIENT_CHANGE;
  else
    return -1;
}

int
ipc_parse_subscribe(const uint8_t *msg, int *subscribe)
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

  const char* event = YAJL_GET_STRING(event_val);
  fprintf(stderr, "Received event: %s\n", event);

  int event_num;
  if ((event_num = ipc_event_stoi(event)) < 0)
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

  return event_num;
}

int
ipc_subscribe(IPCClient *c, int event, int action)
{
  if (action == IPC_ACTION_SUBSCRIBE) {
    c->subscriptions |= event;
  } else if (action == IPC_ACTION_UNSUBSCRIBE) {
    c->subscriptions ^= event;
  } else {
    ipc_prepare_reply_failure(c, IPC_TYPE_SUBSCRIBE);
    return -1;
  }

  ipc_prepare_reply_success(c, IPC_TYPE_SUBSCRIBE);
  return 0;
}

void
ipc_prepare_reply_failure(IPCClient *c, int msg_type)
{
  const char *failure_msg = "{\"result\":\"failure\"}";
  const size_t msg_len = strlen(failure_msg);

  ipc_prepare_send_message(c, msg_type, msg_len, failure_msg);
}

void
ipc_prepare_reply_success(IPCClient *c, int msg_type)
{
  const char *success_msg = "{\"result\":\"success\"}";
  const size_t msg_len = strlen(success_msg);

  ipc_prepare_send_message(c, msg_type, msg_len, success_msg);
}

void
ipc_tag_change_event(int mon_num, TagState old, TagState new)
{
  yajl_gen gen;
  ipc_event_init_message(&gen);
  dump_tag_event(gen, mon_num, old, new);
  ipc_event_prepare_send_message(gen);
}

void
ipc_selected_client_change_event(Client *old_client, Client *new_client,
    int mon_num)
{
  yajl_gen gen;
  ipc_event_init_message(&gen);
  dump_client_change_event(gen, old_client, new_client, mon_num);
  ipc_event_prepare_send_message(gen);
}

int
ipc_is_client_registered(int fd)
{
  return (ipc_list_get_client(fd) != NULL);
}

void
ipc_cleanup(int sock_fd)
{
  IPCClient *c = ipc_client_head;
  while (c) {
    IPCClient *next = c->next;
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, c->fd, &c->event);

    if (c->buffer_size != 0) free(c->buffer);

    free(c);
    c = next;
  }

  shutdown(sock_fd, SHUT_RDWR);
}
