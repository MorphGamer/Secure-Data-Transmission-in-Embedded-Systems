idf_component_register(SRCS "main.c" "tcp_server.c" "crypto_common.c"
                      INCLUDE_DIRS "." "C:/Users/wdjones/esp"
                      REQUIRES esp_wifi lwip esp_system esp_event nvs_flash esp_event mbedtls esp_netif esp_adc driver)