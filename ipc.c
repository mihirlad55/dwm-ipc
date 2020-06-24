#include <sys/epoll.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include "ipc.h"

int
create_socket(const char* filename)
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

    if (bind(sock_fd, (const struct sockaddr*) &addr, addr_size) == -1) {
        fputs("Failed to bind socket\n", stderr);
        return -1;
    }

    if (listen(sock_fd, 5) < 0) {
        fputs("Failed to listen for connections on socket\n", stderr);
        return -1;
    }
    return sock_fd;
}


// TODO: Cleanup socket
