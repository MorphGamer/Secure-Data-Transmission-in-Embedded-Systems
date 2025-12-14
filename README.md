# Secure-Data-Transmission-in-Embedded-Systems
Secure communication framework for embedded devices using a hybrid cryptographic approach that combines Elliptic Curve Integrated Encryption Scheme (ECIES) for secure key exchange, Elliptic Curve Digital Signature Algorithm (ECDSA), and Advanced Encryption Standard in Galois/Counter Mode (AES-GCM)

### ESP-IDF VS Code ECDH Key Exchange • AES-GCM Encryption

This project demonstrates secure communication between two ESP32 devices using:

-   **ECDH** (Elliptic Curve Diffie-Hellman) for shared key agreement\
-   **SHA-256** for key derivation\
-   **AES-GCM** for authenticated encryption\
-   **TCP client/server communication**\
-   **Wi-Fi AP/Station mode**

The **Primary ESP32** requests a temperature reading.\
The **Secondary ESP32** reads the temperature, encrypts it, and sends it back.


# Project Structure

    project-root/
    │
    ├── primary/                 # Primary ESP32 firmware
    │   ├── main/
    │   │   ├── main.c
    │   │   ├── tcp_client.c
    │   │   ├── crypto_common.c
    │   │   ├── crypto_common.h
    │   │   ├── CMakeLists.txt
    │   └── ...
    │
    ├── secondary/               # Secondary ESP32 firmware
    │   ├── main/
    │   │   ├── main.c
    │   │   ├── tcp_server.c
    │   │   ├── crypto_common.c
    │   │   ├── crypto_common.h
    │   │   ├── CMakeLists.txt
    │   └── ...
    │
    └── README.md

Each folder (`primary/` and `secondary/`) is an **independent ESP-IDF
project**.


# Requirements

### Hardware

-   2 × ESP32 boards\
-   2 × USB cables

### Software

-   **Visual Studio Code**
-   **ESP-IDF Extension for VS Code**
-   ESP-IDF installed ( 5.5.1)
-   Python 3.x


# System Overview

### Secondary ESP32

-   Runs as a Wi-Fi Access Point\
-   Hosts a TCP server\
-   Performs ECDH key exchange\
-   Waits for encrypted command `"REQ:TEMP"`\
-   Reads temperature\
-   Encrypts temperature using AES-GCM\
-   Sends packet:    [ IV | TAG | CIPHERTEXT ]

### Primary ESP32

-   Connects to Secondary's Wi-Fi\
-   Opens TCP client connection\
-   Performs ECDH key exchange\
-   Sends encrypted `"REQ:TEMP"`\
-   Receives encrypted temperature\
-   Decrypts and prints it


# Configuration

Both projects contain fields for Wifi:

``` c
#define WIFI_SSID "WiFiSSID"
#define WIFI_PASS "WiFiPassword"

#define SERVER_IP   "192.168.4.1"
#define SERVER_PORT 5000
```

### Secondary ESP32 MUST:

-   Use AP mode\
-   Use static IP `192.168.4.1`\
-   Run TCP server on defined port

### Primary ESP32 MUST:

-   Connect to Secondary's AP\
-   Use same IP + port


# Building in VS Code (ESP-IDF)

You will build each project separately.


## Build & Flash the Secondary

1.  Open **VS Code**
2.  **File → Open Folder** → choose `secondary/`
3.  In the ESP-IDF extension panel:
    -   **Set Target** (`esp32s3`)
    -   **Build Project**
4.  Connect board via USB
5.  
5.  Click **Flash**
6.  Click **Monitor**

You should see:

    WiFi AP started
    TCP Server listening on 5000
    Waiting for client...

Keep this running.


## Build & Flash the Primary (STA + Client)

1.  Open a new VS Code window
2.  Open Folder `primary/`
3.  Set Target, Build, Flash, Monitor

Expected output:

    Connected to AP
    TCP connection established
    ECDH key exchange complete
    Sent encrypted request REQ:TEMP
    Received encrypted temperature
    Decrypted temperature: 23.91 C



# Cryptography Overview

### ECDH Key Exchange

Both devices generate ECC keypairs and exchange public keys:

    shared = ECDH(private_local, public_remote)

### Key Derivation

    aes_key = SHA256(shared)

### AES-GCM Message Format

    0-11   : IV (12 bytes)
    12-27  : TAG (16 bytes)
    28-end : Ciphertext (variable length)

Both devices must agree on exact lengths.

# Running the System

1.  Power both ESP32s\
2.  Start Secondary monitor\
3.  Start Primary monitor\
4.  Primary prints decrypted temperature\
5.  Secondary logs command receipt and encrypted transmission

Example Primary output:

    Decrypted temperature: 23.91 C

Example Secondary output:

    Request decrypted: REQ:TEMP
    Sending encrypted temperature 23.91 C


#  Troubleshooting

###  "Decryption failed"

-   IV mismatch\
-   Ciphertext length mismatch\
-   Tag mismatch\
-   Wrong Wi-Fi SSID/PASS\
-   Server IP/Port mismatch

###  Primary never connects

-   Wrong AP credentials\
-   Wrong AP IP\
-   Server not listening

###  Secondary waiting forever for request

-   Primary not connected\
-   Primary not sending full packet
