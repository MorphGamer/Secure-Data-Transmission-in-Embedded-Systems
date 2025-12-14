#include "tcp_server.h"
#include "lwip/sockets.h"
#include <esp_wifi.h>
#include "esp_log.h"

int tcp_server_listen(int port) {
    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0) return -1;

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    bind(listen_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(listen_sock, 1);

    ESP_LOGI("TCP", "Server listening on port %d", port);
    int client_sock = accept(listen_sock, NULL, NULL);
    return client_sock;
}
