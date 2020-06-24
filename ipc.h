#ifndef IPC_H_
#define IPC_H_

#include <stdint.h>

#define IPC_MAGIC "DWM-IPC"
#define IPC_MAGIC_LEN 7 // Not including null char


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


int create_socket(const char* filename);

int ipc_register_client(int fd);

int ipc_accept_client(int sock_fd, struct epoll_event *event);

int ipc_read_client(int fd);

// Free msg if successful return of 0
int ipc_recv_message(int fd, uint8_t *msg_type, uint32_t *reply_size,
        uint8_t **msg);

int ipc_remove_client(int fd);


#endif /* IPC_H_ */
