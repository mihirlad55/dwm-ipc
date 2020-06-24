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

        fd = accept(sock_fd, (struct sockaddr*)&client_addr, &len);
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
ipc_read_client(int fd) {
    int res = 1;
    char buffer[100] = {0};

    while ( (res = read(fd, buffer, 100)) ) {
        fprintf(stderr, "%s\n", buffer);
    }

    return res;
}

int
ipc_remove_client(int fd) {
    int res = close(fd);

    if (res == 0) {
        fprintf(stderr, "Successfully removed client on fd %d\n", fd);
    } else if (res < 0 && res != EINTR) {
        fprintf(stderr, "Failed to close fd %d\n", fd);
    }

    return res;
}

// TODO: Cleanup socket
