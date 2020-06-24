#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdlib.h>

#define IPC_MAGIC "DWM-IPC"
#define IPC_MAGIC_LEN 7 // Not including null char

typedef struct dwm_ipc_header {
    uint8_t magic[IPC_MAGIC_LEN];
    uint32_t size;
    uint8_t type;
} __attribute((packed)) dwm_ipc_header_t;


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
    msg_header.type = 3;
    char *msg = "TEST MESSAGE. THIS IS A TEST MESSAGE";
    msg_header.size = strlen(msg) + 1;

    uint8_t buffer[sizeof(dwm_ipc_header_t) + msg_header.size];
    memcpy(buffer, &msg_header, sizeof(dwm_ipc_header_t));
    memcpy(buffer + sizeof(dwm_ipc_header_t), msg, msg_header.size);

    write(sock, buffer, sizeof(dwm_ipc_header_t) + msg_header.size);
}


