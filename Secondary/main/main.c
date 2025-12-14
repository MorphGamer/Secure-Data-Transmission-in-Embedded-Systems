#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "lwip/sockets.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"
#include "driver/gpio.h"
#include "crypto_common.h"

// Wifi information
#define WIFI_SSID "WiFiSSID"
#define WIFI_PASS "WiFiPassword"
#define SERVER_PORT 5000

static const char *TAG = "SECONDARY";

// -----------------------------------------------------------------------------
// Wi-Fi AP mode setup
// -----------------------------------------------------------------------------
static void wifi_init_ap(void)
{
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    wifi_config_t ap_config = {
        .ap = {
            .ssid = WIFI_SSID,
            .ssid_len = strlen(WIFI_SSID),
            .channel = 1,
            .password = WIFI_PASS,
            .max_connection = 2,
            .authmode = WIFI_AUTH_WPA_WPA2_PSK
        },
    };
    if (strlen(WIFI_PASS) == 0) {
        ap_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    esp_wifi_start();
}

// -----------------------------------------------------------------------------
// TCP server setup
// -----------------------------------------------------------------------------
static int tcp_server_listen(void)
{
    struct sockaddr_in listen_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    int listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(SERVER_PORT);
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    bind(listen_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr));
    listen(listen_sock, 1);

    ESP_LOGI(TAG, "Waiting for primary...");
    int sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
    close(listen_sock);
    ESP_LOGI(TAG, "Primary connected.");
    return sock;
}

// -----------------------------------------------------------------------------
// ADC Global variables 
// -----------------------------------------------------------------------------
static adc_oneshot_unit_handle_t adc1_handle;
static adc_cali_handle_t adc1_cali_handle;
static bool adc_calibrated = false;

// -----------------------------------------------------------------------------
// ADC initializer
// -----------------------------------------------------------------------------
void adc_init(void)
{
    // ADC Unit Init 
    adc_oneshot_unit_init_cfg_t init_cfg = {
        .unit_id = ADC_UNIT_1,
    };
    ESP_ERROR_CHECK(adc_oneshot_new_unit(&init_cfg, &adc1_handle));
    // Channel Config
    adc_oneshot_chan_cfg_t chan_cfg = {
        .atten = ADC_ATTEN_DB_12, // resolution
        .bitwidth = ADC_BITWIDTH_12,
    };
    ESP_ERROR_CHECK(adc_oneshot_config_channel(
        adc1_handle,   
        ADC_CHANNEL_2, // GPIO 8 on ADC Unit 1
        &chan_cfg
    ));
}

// -----------------------------------------------------------------------------
// TMP36 read helper
// -----------------------------------------------------------------------------
float read_temperature_c(void)
{
    //Read ADC
    int raw;
    ESP_ERROR_CHECK(adc_oneshot_read(
        adc1_handle,
        ADC_CHANNEL_2,
        &raw
    ));

    int voltage_mv = raw * 3300 / 4095;
    // TMP36: 500 mV offset, 10 mV/C
    return (voltage_mv - 500) / 10.0f;
}


// -----------------------------------------------------------------------------
// Main app
// -----------------------------------------------------------------------------
void secondary(void)
{
    //Initialzation
    ESP_LOGI(TAG, "Starting Secondary ESP32-S3...");
    nvs_flash_init();
    wifi_init_ap();
    adc_init();

    int sock = tcp_server_listen();

    // Generate ECC keypair
    mbedtls_pk_context keypair;
    generate_ec_keypair(&keypair);

    // Send our public key
    unsigned char pubkey_buf[65];
    size_t pubkey_len = 0;
    mbedtls_ecp_point_write_binary(
        &mbedtls_pk_ec(keypair)->MBEDTLS_PRIVATE(grp),
        &mbedtls_pk_ec(keypair)->MBEDTLS_PRIVATE(Q),
        MBEDTLS_ECP_PF_UNCOMPRESSED,
        &pubkey_len, pubkey_buf, sizeof(pubkey_buf)
    );
    send(sock, pubkey_buf, pubkey_len, 0);

    // Receive primary’s public key
    unsigned char peer_pub_buf[65];
    recv(sock, peer_pub_buf, sizeof(peer_pub_buf), 0);
    mbedtls_ecp_point peer_pub;
    mbedtls_ecp_point_init(&peer_pub);
    mbedtls_ecp_point_read_binary(
        &mbedtls_pk_ec(keypair)->MBEDTLS_PRIVATE(grp),
        &peer_pub,
        peer_pub_buf,
        sizeof(peer_pub_buf)
    );

    // Derive shared secret - AES key
    unsigned char shared_secret[64];
    size_t secret_len = 0;
    compute_shared_secret(&keypair, &peer_pub, shared_secret, &secret_len);
    unsigned char aes_key[AES_KEY_SIZE];
    kdf_sha256(shared_secret, secret_len, aes_key, AES_KEY_SIZE);

    // Wait for request
    uint8_t buffer[AES_IV_SIZE + AES_TAG_SIZE + 64] = {0};
    uint8_t recv_iv[AES_IV_SIZE], recv_tag[AES_TAG_SIZE];
    unsigned char plain_temp[64] = {0};
    unsigned char recv_ciphertext[64];


    // [ IV | TAG | CIPHERTEXT ]
    size_t received = recv(sock, buffer, sizeof(buffer), 0);
    if (received < (AES_IV_SIZE + AES_TAG_SIZE)) {
        ESP_LOGE(TAG,
                 "Failed to receive encrypted temperature header (got %d bytes)",
                 (int)received);
    } else {
        // Parse IV and tag
        memcpy(recv_iv, buffer, AES_IV_SIZE);
        memcpy(recv_tag, buffer + AES_IV_SIZE, AES_TAG_SIZE);

        // Remaining bytes are ciphertext
        size_t ct_len = received - (AES_IV_SIZE + AES_TAG_SIZE);
        if (ct_len <= 0 || ct_len > sizeof(recv_ciphertext)) {
            ESP_LOGE(TAG, "Invalid ciphertext length: %d", (int)ct_len);
        } else {
            memcpy(recv_ciphertext, buffer + AES_IV_SIZE + AES_TAG_SIZE, ct_len);
            
            //decrypt
            if (aes_gcm_decrypt(aes_key,
                                recv_iv,
                                recv_ciphertext,
                                ct_len,
                                plain_temp,
                                recv_tag) == 0) {
                //information output in hex
                ESP_LOG_BUFFER_HEX("SECONDARY: plaintext", plain_temp, ct_len);
                ESP_LOG_BUFFER_HEX("SECONDARY: ciphertext", recv_ciphertext, ct_len);
                ESP_LOG_BUFFER_HEX("SECONDARY: AES Key", aes_key, AES_KEY_SIZE);
                ESP_LOG_BUFFER_HEX("SECONDARY: IV", recv_iv, AES_IV_SIZE);
                ESP_LOG_BUFFER_HEX("SECONDARY: TAG", recv_tag, AES_TAG_SIZE);
                //output plaintext message
                ESP_LOGI(TAG, "plain: %s", plain_temp);

                //Check request message
                if (strcmp((char *)plain_temp, "REQ:TEMP") == 0) {
                
                // Build temperature response
                float t = read_temperature_c();
                char temp_buf[64] = {0};
                snprintf(temp_buf, sizeof(temp_buf), "%.2f C", t);// max 9 chars -999.99 C
                size_t temp_len = strlen(temp_buf);

                unsigned char send_ciphertext[64] = {0};
                unsigned char send_tag[AES_TAG_SIZE] = {0};
                unsigned char send_iv[AES_IV_SIZE] = {0};
                //choose random IV
                if (generate_random_iv(send_iv, AES_IV_SIZE) != 0) ESP_LOGE(TAG, "Failed to generate IV");

                // encrypt
                if (aes_gcm_encrypt(aes_key, send_iv,
                                    (unsigned char *)temp_buf,
                                    temp_len,
                                    send_ciphertext, send_tag) != 0) {
                    ESP_LOGE(TAG, "Temperature encrypt failed");
                } else {
                    uint8_t buffer[AES_IV_SIZE + AES_KEY_SIZE + 64] = {0};

                    //build packet
                    // [ IV | TAG | CIPHERTEXT ]
                    memcpy(buffer, send_iv, AES_IV_SIZE);
                    memcpy(buffer + AES_IV_SIZE, send_tag, AES_TAG_SIZE);
                    memcpy(buffer + AES_IV_SIZE + AES_TAG_SIZE, send_ciphertext, temp_len);

                    //information output in hex
                    ESP_LOG_BUFFER_HEX("SECONDARY: plaintext", temp_buf, temp_len);
                    ESP_LOG_BUFFER_HEX("SECONDARY: ciphertext", send_ciphertext, temp_len);
                    ESP_LOG_BUFFER_HEX("SECONDARY: AES Key", aes_key, AES_KEY_SIZE);
                    ESP_LOG_BUFFER_HEX("SECONDARY: IV", send_iv, AES_IV_SIZE);
                    ESP_LOG_BUFFER_HEX("SECONDARY: TAG", send_tag, AES_TAG_SIZE);
                    //output plaintext
                    ESP_LOGI(TAG, "plain: %s", temp_buf);

                    size_t sent = send(sock, buffer, AES_IV_SIZE + AES_TAG_SIZE + temp_len, 0);
                    ESP_LOGI(TAG, "Sent temperature: %s", temp_buf);
                }
            }
            else {
                // Either the command was wrong or something failed above
                unsigned char buf[AES_IV_SIZE + AES_KEY_SIZE + 64] = {0};
                send(sock, buf, sizeof(buf), 0);
                ESP_LOGE(TAG, "Command failed.");
            }
            } else {
                ESP_LOGE(TAG, "Decryption failed");
            }
        }
    }

    //free everything
    mbedtls_ecp_point_free(&peer_pub);
    mbedtls_pk_free(&keypair);
    close(sock);
}

void app_main(void)
{
    while (1)
    {
        //loop secondary task
        secondary();
        vTaskDelay(pdMS_TO_TICKS(100000));
    }
}