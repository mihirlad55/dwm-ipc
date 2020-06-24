#include <sys/epoll.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>

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

int ipc_recv_message(int fd, uint8_t *msg_type, uint32_t *reply_size, uint8_t **reply)
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
                fprintf(stderr, "Read %"PRIu32" bytes, expected %"PRIu32" bytes.",
                        read_bytes, *reply_size);
                return -2;
            } else {
                fprintf(stderr, "Unexpectedly reached EOF while reading header.");
                fprintf(stderr, "Read %"PRIu32" bytes, expected %"PRIu32" bytes.",
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
        fprintf(stderr, "Message so far: %s\n", *reply);
        fprintf(stderr, "Read %"PRIu32" bytes", n);

        if (n == 0) {
            fprintf(stderr, "Unexpectedly reached EOF while reading payload.");
            fprintf(stderr, "Read %"PRIu32" bytes, expected %"PRIu32" bytes.",
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

    fprintf(stderr, "MEssage: %s\n", *reply);
    return 0;
}

int
ipc_read_client(int fd)
{
    uint8_t msg_type;
    uint32_t msg_size;
    uint8_t *msg = NULL;

    int ret = ipc_recv_message(fd, &msg_type, &msg_size, &msg);

    if (ret < 0) {
        // Will happen if these errors occur while reading header
        if (ret == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            return -2;

        // TODO: Remove client
        return -1;
    }

    fprintf(stderr, "Received message: '%s' ", (char*)msg);
    fprintf(stderr, "Message type: %"PRIu8" ", msg_type);
    fprintf(stderr, "Message size: %"PRIu32"\n", msg_size);

    free(msg);
    return 0;
}

int
ipc_remove_client(int fd)
{
    int res = close(fd);

    if (res == 0) {
        fprintf(stderr, "Successfully removed client on fd %d\n", fd);
    } else if (res < 0 && res != EINTR) {
        fprintf(stderr, "Failed to close fd %d\n", fd);
    }

    return res;
}

// TODO: Cleanup socket
