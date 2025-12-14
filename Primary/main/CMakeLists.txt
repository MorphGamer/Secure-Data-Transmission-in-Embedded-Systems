idf_component_register(SRCS "main.c" "tcp_client.c" "crypto_common.c"
                      INCLUDE_DIRS "."
                      REQUIRES esp_wifi lwip esp_system esp_event nvs_flash esp_event mbedtls esp_netif     )