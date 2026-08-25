#include "connect_scanner.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

static struct {
    const char *target;
    struct in_addr addr;
    int start_port;
    int end_port;
    int next_port;
    pthread_mutex_t lock;
} scan_ctx;

static int scan_port(struct in_addr addr, int port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return -1;

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr = addr;

    int ret = connect(sock, (struct sockaddr *)&sin, sizeof(sin));
    close(sock);
    return ret == 0 ? 0 : -1;
}

static void *worker(void *arg)
{
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&scan_ctx.lock);
        int port = scan_ctx.next_port++;
        pthread_mutex_unlock(&scan_ctx.lock);

        if (port > scan_ctx.end_port)
            break;

        if (scan_port(scan_ctx.addr, port) == 0) {
            printf("Port %d is OPEN\n", port);
        }
    }
    return NULL;
}

int connect_scan(const char *target, int start_port, int end_port, int threads)
{
    struct hostent *he = gethostbyname(target);
    if (!he) {
        fprintf(stderr, "Failed to resolve %s\n", target);
        return -1;
    }
    scan_ctx.target = target;
    scan_ctx.addr = *(struct in_addr *)he->h_addr_list[0];
    scan_ctx.start_port = start_port;
    scan_ctx.end_port = end_port;
    scan_ctx.next_port = start_port;
    pthread_mutex_init(&scan_ctx.lock, NULL);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &scan_ctx.addr, ip_str, sizeof(ip_str));
    printf("Connect scanning %s ports %d-%d (%d threads)\n",
           ip_str, start_port, end_port, threads);

    pthread_t *workers = malloc(sizeof(pthread_t) * threads);
    for (int i = 0; i < threads; i++)
        pthread_create(&workers[i], NULL, worker, NULL);
    for (int i = 0; i < threads; i++)
        pthread_join(workers[i], NULL);

    pthread_mutex_destroy(&scan_ctx.lock);
    free(workers);
    return 0;
}
