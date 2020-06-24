#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>


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

    char *msg = "TEST MESSAGE";
    size_t len = strlen(msg) + 1;

    write(sock, msg, len);
}


