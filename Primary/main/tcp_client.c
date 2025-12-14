#include "tcp_client.h"
#include "lwip/sockets.h"
#include "esp_log.h"
#include <arpa/inet.h>
#include <esp_wifi.h>

int tcp_client_connect(const char *server_ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr.s_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        close(sock);
        return -1;
    }
    return sock;
}
