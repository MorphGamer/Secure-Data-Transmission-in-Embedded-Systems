#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "lwip/sockets.h"
#include "crypto_common.h"

// Wifi information
#define WIFI_SSID      "WiFiSSID"
#define WIFI_PASS      "WiFiPassword"
#define SERVER_IP      "192.168.4.1"   // IP of Secondary ESP (in AP mode)
#define SERVER_PORT    5000

static const char *TAG = "PRIMARY";

// -----------------------------------------------------------------------------
// Wi-Fi Station setup
// -----------------------------------------------------------------------------
static void wifi_init_sta(void)
{
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_STA);

    //config SSID/Password
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };
    esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    esp_wifi_start();
    esp_wifi_connect();
}

// -----------------------------------------------------------------------------
// TCP client connect helper
// -----------------------------------------------------------------------------
static int tcp_client_connect(void)
{
    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(SERVER_PORT);

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    ESP_LOGI(TAG, "Connected to secondary at %s:%d", SERVER_IP, SERVER_PORT);
    return sock;
}

// -----------------------------------------------------------------------------
// Main app
// -----------------------------------------------------------------------------
void primary(void)
{
    ESP_LOGI(TAG, "Starting Primary ESP32-S3...");
    nvs_flash_init();
    wifi_init_sta();
    vTaskDelay(pdMS_TO_TICKS(5000));  // wait for connection

    int sock = tcp_client_connect();

    // Generate ECC keypair
    mbedtls_pk_context keypair;
    generate_ec_keypair(&keypair);

    // Receive secondary public key
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

    // Compute shared secret and derive AES key
    unsigned char shared_secret[64];
    size_t secret_len = 0;
    compute_shared_secret(&keypair, &peer_pub, shared_secret, &secret_len);
    unsigned char aes_key[AES_KEY_SIZE];
    kdf_sha256(shared_secret, secret_len, aes_key, AES_KEY_SIZE);

    ESP_LOGI(TAG, "Shared secret established.");
    // Send request message (AES-GCM encrypted)
    unsigned char iv[AES_IV_SIZE] = {0};
    if (generate_random_iv(iv, AES_IV_SIZE) != 0) ESP_LOGE(TAG, "Failed to generate IV");
    unsigned char tag[AES_TAG_SIZE];
    unsigned char ciphertext[64] = {0};
    const char *msg = "REQ:TEMP";//command to execute

    //encrypt
    aes_gcm_encrypt(aes_key, iv, (unsigned char *)msg, strlen(msg), ciphertext, tag);
    unsigned char buff[AES_IV_SIZE + AES_TAG_SIZE + 64] = {0};
    //build packet
    memcpy(buff, iv, AES_IV_SIZE);
    memcpy( buff + AES_IV_SIZE, tag, AES_TAG_SIZE);
    memcpy( buff + AES_IV_SIZE + AES_TAG_SIZE,ciphertext, strlen(msg));
    send(sock, buff, AES_IV_SIZE + AES_TAG_SIZE + strlen(msg), 0);

    //output values in hex
    ESP_LOG_BUFFER_HEX("PRIMARY: plaintext", msg, strlen(msg));
    ESP_LOG_BUFFER_HEX("PRIMARY: ciphertext", ciphertext, strlen(msg));
    ESP_LOG_BUFFER_HEX("PRIMARY: AES Key", aes_key, AES_KEY_SIZE);
    ESP_LOG_BUFFER_HEX("PRIMARY: IV", iv, AES_IV_SIZE);
    ESP_LOG_BUFFER_HEX("PRIMARY: TAG", tag, AES_TAG_SIZE);

    // Receive encrypted temperature
    uint8_t buffer[AES_IV_SIZE + AES_TAG_SIZE + 64]={0};
    uint8_t recv_iv[12]={0}, recv_tag[16] ={0};
    unsigned char plain_temp[64] = {0};
    unsigned char recv_ciphertext[64] = {0};

    // Compute the actual ciphertext length from how many bytes we got.
    ssize_t received = recv(sock, buffer, sizeof(buffer), 0);
    //ensure got a cipher
    if (received < (AES_IV_SIZE + AES_TAG_SIZE)) {
        ESP_LOGE(TAG,
                 "Failed to receive encrypted temperature header (got %d bytes)",
                 (int)received);
    } else {
        // Parse IV and tag
        memcpy(recv_iv, buffer, AES_IV_SIZE);
        memcpy(recv_tag, buffer + AES_IV_SIZE, AES_TAG_SIZE);

        // Remaining bytes are ciphertext
        ssize_t ct_len = received - (AES_IV_SIZE + AES_TAG_SIZE);
        if (ct_len <= 0 || ct_len > sizeof(recv_ciphertext)) {
            ESP_LOGE(TAG, "Invalid ciphertext length: %d", (int)ct_len);
        } else {
            //grab ciphertext
            memcpy(recv_ciphertext, buffer + AES_IV_SIZE + AES_TAG_SIZE, (size_t)ct_len);

            //decrypt
            if (aes_gcm_decrypt(aes_key,
                                recv_iv,
                                recv_ciphertext,
                                (size_t)ct_len,
                                plain_temp,
                                recv_tag) == 0) {
                //output information in hex         
                ESP_LOG_BUFFER_HEX("PRIMARY: plaintext", plain_temp, ct_len);
                ESP_LOG_BUFFER_HEX("PRIMARY: ciphertext", recv_ciphertext, ct_len);
                ESP_LOG_BUFFER_HEX("PRIMARY: AES Key", aes_key, AES_KEY_SIZE);
                ESP_LOG_BUFFER_HEX("PRIMARY: IV", recv_iv, AES_IV_SIZE);
                ESP_LOG_BUFFER_HEX("PRIMARY: TAG", recv_tag, AES_TAG_SIZE);

                //plaintext result
                ESP_LOGI(TAG, "Received temp: %s", plain_temp);
            } else {
                //output information in hex
                ESP_LOG_BUFFER_HEX("PRIMARY: plaintext", plain_temp, ct_len);
                ESP_LOG_BUFFER_HEX("PRIMARY: ciphertext", recv_ciphertext, ct_len);
                ESP_LOG_BUFFER_HEX("PRIMARY: AES Key", aes_key, AES_KEY_SIZE);
                ESP_LOG_BUFFER_HEX("PRIMARY: IV", recv_iv, AES_IV_SIZE);
                ESP_LOG_BUFFER_HEX("PRIMARY: TAG", recv_tag, AES_TAG_SIZE);
                //fail message
                ESP_LOGE(TAG, "Decryption failed");
            }

        }
    }

    //cleanup
    mbedtls_ecp_point_free(&peer_pub);
    mbedtls_pk_free(&keypair);
    close(sock);
}

void app_main(void)
{
    while (1)
    {
        //loop through primary task
        primary();
        vTaskDelay(pdMS_TO_TICKS(100000));
    }
}