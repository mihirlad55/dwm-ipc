#ifndef IPC_H_
#define IPC_H_

#ifndef VERSION
#include "types.h"
#endif

#include "IPCClient.h"
#include <stdint.h>
#include <sys/epoll.h>
#include <yajl/yajl_gen.h>

#define IPC_MAGIC "DWM-IPC"
#define IPC_MAGIC_ARR                                                          \
  { 'D', 'W', 'M', '-', 'I', 'P', 'C' }
#define IPC_MAGIC_LEN 7 // Not including null char

#define IPCCOMMAND(FUNC, ARGC, TYPES)                                          \
  { #FUNC, {FUNC }, ARGC, (ArgType[ARGC])TYPES }

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
  IPC_EVENT_LAYOUT_CHANGE = 4,
  IPC_EVENT_SELECTED_MONITOR_CHANGE = 8
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
  char *name;
  ArgFunction func;
  unsigned int argc;
  ArgType *arg_types;
} IPCCommand;

typedef struct IPCParsedCommand {
  char *name;
  Arg *args;
  ArgType *arg_types;
  unsigned int argc;
} IPCParsedCommand;

/**
 * Initialize the IPC socket and the IPC module
 *
 * @param const char* socket_path Path to create the socket at
 * @param const int epoll_fd File descriptor for epoll
 * @param IPCCommand commands[] Address of IPCCommands array defined in config.h
 * @param const int commands_len Length of commands[] array
 *
 * @return int The file descriptor of the socket if it was successfully created,
 *   -1 otherwise
 */
int ipc_init(const char *socket_path, const int p_epoll_fd,
             IPCCommand commands[], const int commands_len);

/**
 * Uninitialize the socket and module. Free allocated memory and restore static
 * variables to their state before ipc_init
 */
void ipc_cleanup();

/**
 * Get the file descriptor of the IPC socket
 *
 * @returns int File descriptor of IPC socket, -1 if socket not created.
 */
int ipc_get_sock_fd();

/**
 * Get address to IPCClient with specified file descriptor
 *
 * @param int fd File descriptor of IPC Client
 *
 * @returns IPCClient* Address to IPCClient with specified file descriptor, -1
 *   otherwise
 */
IPCClient *ipc_get_client(int fd);

/**
 * Check if an IPC client exists with the specified file descriptor
 *
 * @param int fd File descriptor
 *
 * @returns int 1 if client exists, 0 otherwise
 */
int ipc_is_client_registered(int fd);

/**
 * Disconnect an IPCClient from the socket and remove the client from the list
 *   of known connected clients
 *
 * @param IPCClient *c Address of IPCClient
 *
 * @returns 0 if the client's file descriptor was closed successfully, the
 * result of executing close() on the file descriptor otherwise.
 */
int ipc_drop_client(IPCClient *c);

/**
 * Accept an IPC Client requesting to connect to the socket and add it to the
 *   list of clients
 *
 * @returns int File descriptor of new client, -1 on error
 */
int ipc_accept_client();

/**
 * Read an incoming message from an accepted IPC client
 *
 * @param IPCClient *c Address of IPCClient
 * @param IPCMessageType *msg_type Address to IPCMessageType variable which will
 *   be assigned the message type of the received message
 * @param uint32_t *msg_size Address to uint32_t variable which will be assigned
 *   the size of the received message
 * @param char **msg Address to char* variable which will be assigned the
 *   address of the received message. This must be freed using free().
 *
 * @returns int 0 on success, -1 on error reading message, -2 if reading the
 *   message resulted in EAGAIN, EINTR, or EWOULDBLOCK.
 */
int ipc_read_client(IPCClient *c, IPCMessageType *msg_type, uint32_t *msg_size,
                    char **msg);

/**
 * Write any pending buffer of the client to the client's socket
 *
 * @param IPCClient *c Client whose buffer to write
 *
 * @returns int Number of bytes written >= 0, -1 otherwise. errno will still be
 *   set from the write operation.
 */
ssize_t ipc_write_client(IPCClient *c);

/**
 * Prepare a message in the specified client's buffer.
 *
 * @param IPCClient *c Client to prepare message for
 * @param const IPCMessageType msg_type Type of message to prepare
 * @param const uint32_t msg_size Size of the message in bytes. Should not
 *   exceed MAX_MESSAGE_SIZE
 * @param const char *msg Message to prepare (not including header). This
 *   pointer can be freed after the function invocation.
 */
void ipc_prepare_send_message(IPCClient *c, const IPCMessageType msg_type,
                              const uint32_t msg_size, const char *msg);

/**
 * Prepare an error message in the specified client's buffer
 *
 * @param IPCClient *c Client to prepare message for
 * @param IPCMessageType msg_type Type of message
 * @param const char *format Format string following vsprintf
 * @param ... Arguments for format string
 */
void ipc_prepare_reply_failure(IPCClient *c, IPCMessageType msg_type,
                               const char *format, ...);

/**
 * Prepare a success message in the specified client's buffer
 *
 * @param IPCClient *c Client to prepare message for
 * @param IPCMessageType msg_type Type of message
 */
void ipc_prepare_reply_success(IPCClient *c, IPCMessageType msg_type);

/**
 * Send a tag_change_event to all subscribers. Should be called only when there
 * has been a tag state change.
 *
 * @param const int mon_num The index of the monitor (Monitor.num property)
 * @param TagState old_state The old tag state
 * @param TagState new_state The new (now current) tag state
 */
void ipc_tag_change_event(const int mon_num, TagState old_state,
                          TagState new_state);

/**
 * Send a selected_client_change_event to all subscribers. Should be called only
 * when there has been a selected client change.
 *
 * @param const int mon_num The index of the monitor (Monitor.num property)
 * @param Client *old_client The old DWM client selection (Monitor.oldsel)
 * @param Client *new_client The new (now current) DWM client selection
 */
void ipc_selected_client_change_event(const int mon_num, Client *old_client,
                                      Client *new_client);

/**
 * Send a layout_change_event to all subscribers. Should be called only
 * when there has been a layout change.
 *
 * @param int mon_num The index of the monitor (Monitor.num property)
 * @param const char *old_symbol The old layout symbol
 * @param const Layout *old_layout Address to the old Layout
 * @param const char *new_symbol The new (now current) layout symbol
 * @param const Layout *new_layout Address to the new Layout
 */
void ipc_layout_change_event(const int mon_num, const char *old_symbol,
                             const Layout *old_layout, const char *new_symbol,
                             const Layout *new_layout);

/**
 * Send a monitor_change_event to all subscribers. Should be called only
 * when there has been a selected monitor change.
 *
 * @param int last_mon_num The index of the previously selected monitor
 * @param int new_mon_num The index of the newly selected monitor
 */
void ipc_monitor_change_event(const int last_mon_num, const int new_mon_num);

/**
 * Check to see if an event has occured and call the *_change_event functions
 * accordingly
 *
 * @param Monitor *mons Address of Monitor pointing to start of linked list
 * @param Monitor **lastselmon Address of pointer to previously selected monitor
 * @param Monitor *selmon Address of selected Monitor
 */
void ipc_send_events(Monitor *mons, Monitor **lastselmon, Monitor *selmon);

/**
 * Handle an epoll event caused by a registered IPC client. Read, process, and
 * handle any received messages from clients. Write pending buffer to client if
 * the client is ready to receive messages. Drop clients that have sent an
 * EPOLLHUP.
 *
 * @param struct epoll_event *ev Associated epoll event returned by epoll_wait
 * @param Monitor *mons Address of Monitor pointing to start of linked list
 * @param Monitor *selmon Address of selected Monitor
 * @param Monitor **lastselmon Address of pointer to previously selected monitor
 * @param const char *tags[] Array of tag names
 * @param const int tags_len Length of tags array
 * @param const Layout *layouts Array of available layouts
 * @param const int layouts_len Length of layouts array
 *
 * @returns int 0 if event was successfully handled, -1 on any error receiving
 * or handling incoming messages or unhandled epoll event.
 */
int ipc_handle_client_epoll_event(struct epoll_event *ev, Monitor *mons,
                                  Monitor **lastselmon, Monitor *selmon,
                                  const char *tags[], const int tags_len,
                                  const Layout *layouts, const int layouts_len);

/**
 * Handle an epoll event caused by the IPC socket. This function only handles an
 * EPOLLIN event indicating a new client requesting to connect to the socket.
 *
 * @param struct epoll_event *ev Associated epoll event returned by epoll_wait
 *
 * @returns int 0, if the event was successfully handled, -1 if not an EPOLLIN
 * event or if a new IPC client connection request could not be accepted.
 */
int ipc_handle_socket_epoll_event(struct epoll_event *ev);

#endif /* IPC_H_ */
