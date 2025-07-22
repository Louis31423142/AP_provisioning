/**
 * Copyright (c) 2022 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

#include "lwip/ip4_addr.h"
#include "lwip/init.h"
#include "lwip/apps/httpd.h"

#include "dhcpserver.h"
#include "dnsserver.h"

#include "pico/flash.h"
#include "hardware/flash.h" // for saving succesful credentials

void httpd_init(void);

static absolute_time_t wifi_connected_time;
static bool led_on = false;

// max lengths + 1
char ssid[33] = "";
char password[64] = "";

bool connection_status = false;

// Define flash offset towards end of flash
#ifndef PICO_FLASH_BANK_TOTAL_SIZE
#define PICO_FLASH_BANK_TOTAL_SIZE (FLASH_SECTOR_SIZE * 2u)
#endif

#ifndef PICO_FLASH_BANK_STORAGE_OFFSET
#if PICO_RP2350 && PICO_RP2350_A2_SUPPORTED 
#define FLASH_TARGET_OFFSET (PICO_FLASH_SIZE_BYTES - FLASH_SECTOR_SIZE - PICO_FLASH_BANK_TOTAL_SIZE)
#else
#define FLASH_TARGET_OFFSET (PICO_FLASH_SIZE_BYTES - PICO_FLASH_BANK_TOTAL_SIZE)
#endif
#endif

const uint8_t *flash_target_contents = (const uint8_t *) (XIP_BASE + FLASH_TARGET_OFFSET);

// Function prototypes
static void call_flash_range_erase(void *param);
static void call_flash_range_program(void *param);
void save_credentials(char ssid[], char password[]);
void read_credentials(void);
void attempt_wifi_connection(void);
static const char *credential_cgi_handler(int iIndex, int iNumParams, char *pcParam[], char *pcValue[]);
static const char *connect_cgi_handler(int iIndex, int iNumParams, char *pcParam[], char *pcValue[]);
u16_t ssi_handler(int iIndex, char *pcInsert, int iInsertLen
#if LWIP_HTTPD_SSI_MULTIPART
    , uint16_t current_tag_part, uint16_t *next_tag_part
#endif
);

static tCGI cgi_handlers[] = {
    { "/credentials.cgi", credential_cgi_handler },
    { "/connect.cgi", connect_cgi_handler },
};

// Be aware of LWIP_HTTPD_MAX_TAG_NAME_LEN
static const char *ssi_tags[] = {
    "ssid",
    "password"
};

int main() {
    stdio_init_all();
    if (cyw43_arch_init()) {
        printf("failed to initialise\n");
        return 1;
    }
    printf("intitialised\n");

    // First, try to connect to network using saved credentials
    read_credentials();
    printf("Current saved SSID: %s\n", ssid);
    printf("Current saved password: %s\n", password);

    cyw43_arch_enable_sta_mode();
    if (cyw43_arch_wifi_connect_timeout_ms(ssid, password, CYW43_AUTH_WPA2_AES_PSK, 10000)) { 
        printf("failed to connect with saved credentials \n");
    } else {
        printf("Connected.\n");
        connection_status = true;
    }

    // If this fails, enable access point
    if (connection_status == false) {
        cyw43_arch_disable_sta_mode();
        cyw43_arch_enable_ap_mode("picow_test", "12345678", CYW43_AUTH_WPA2_AES_PSK);
        printf("\nReady, running server at %s\n", ip4addr_ntoa(netif_ip4_addr(netif_list)));

        #if LWIP_IPV6
        #define IP(x) ((x).u_addr.ip4)
        #else
        #define IP(x) (x)
        #endif

        ip4_addr_t mask;
        ip4_addr_t gw;
        IP(gw).addr = PP_HTONL(CYW43_DEFAULT_IP_AP_ADDRESS);
        IP(mask).addr = PP_HTONL(CYW43_DEFAULT_IP_MASK);

        #undef IP
        dhcp_server_t dhcp_server;
        dhcp_server_init(&dhcp_server, &gw, &mask);

        dns_server_t dns_server;
        dns_server_init(&dns_server, &gw);

        char hostname[sizeof(CYW43_HOST_NAME) + 4];
        memcpy(&hostname[0], CYW43_HOST_NAME, sizeof(CYW43_HOST_NAME) - 1);
        hostname[sizeof(hostname) - 1] = '\0';
        netif_set_hostname(&cyw43_state.netif[CYW43_ITF_STA], hostname);

        // start http server
        wifi_connected_time = get_absolute_time();

        // setup http server
        cyw43_arch_lwip_begin();
        httpd_init();
        http_set_cgi_handlers(cgi_handlers, LWIP_ARRAYSIZE(cgi_handlers));
        http_set_ssi_handler(ssi_handler, ssi_tags, LWIP_ARRAYSIZE(ssi_tags));
        cyw43_arch_lwip_end();
    }

    //wait for connection
    while(connection_status == false) {
        cyw43_arch_poll();
        cyw43_arch_wait_for_work_until(make_timeout_time_ms(1000));
    }

    printf("Finished provisioning credentials. \n");
    cyw43_arch_deinit();
    return 0;
}


// This function will be called when it's safe to call flash_range_erase
static void call_flash_range_erase(void *param) {
    uint32_t offset = (uint32_t)param;
    flash_range_erase(offset, FLASH_SECTOR_SIZE);
}

// This function will be called when it's safe to call flash_range_program
static void call_flash_range_program(void *param) {
    uint32_t offset = ((uintptr_t*)param)[0];
    const uint8_t *data = (const uint8_t *)((uintptr_t*)param)[1];
    flash_range_program(offset, data, FLASH_PAGE_SIZE);
}

// Functions for saving and reading credentials from flash
void save_credentials(char ssid[], char password[]) {
    // create empty 256 byte list
    uint8_t flash_data[FLASH_PAGE_SIZE] = {0};

    uint ssid_len = strlen(ssid);
    uint password_len = strlen(password);

    // no character has ascii value 0, so we can seperate our ssid and password with a single 0
    // first add ssid 
    for (uint i = 0; i < ssid_len; i++) {
        int ascii = (int) ssid[i];
        flash_data[i] = ascii;
    }

    //next add password
    for (uint i = 0; i < password_len; i++) {
        int ascii = (int) password[i];
        flash_data[i + ssid_len + 1] = ascii;
    }

    //now erase and then write flash
    int rc = flash_safe_execute(call_flash_range_erase, (void*)FLASH_TARGET_OFFSET, UINT32_MAX);
    hard_assert(rc == PICO_OK);

    uintptr_t params[] = { FLASH_TARGET_OFFSET, (uintptr_t)flash_data};
    rc = flash_safe_execute(call_flash_range_program, params, UINT32_MAX);
    hard_assert(rc == PICO_OK);
}

void read_credentials(void) {
    uint counter = 0;
    uint ssid_len = 0;

    // first check if the flash page begins with FF - this indicates the flash has not yet been written to 
    // so must initialise with empty write (otherwise crashes)
    if (flash_target_contents[0] == 255) {
        save_credentials("", "");
    }

    //initialise temporary ssid and password as 1 bigger than max to ensure null termination
    char t_ssid[33] = {0};
    char t_password[64] = {0};

    // itterate through the flash and seperate ssid and password
    for (uint i = 0; i < FLASH_PAGE_SIZE; i++) {
        // when detect first zero, increment counter and continue. update ssid_len so we can index password
        if (flash_target_contents[i] == 0 && counter == 0) {
            counter++;
            ssid_len = i;
            continue;
        } 
        // when detect second zero, have extracted both ssid and password so stop
        else if (flash_target_contents[i] == 0 && counter == 1)
        {
            break;
        }
        // otherwise just write ssid and password
        else if (counter == 0) {
            t_ssid[i] = (char) flash_target_contents[i];
        }
        else if (counter == 1) {
            t_password[i - ssid_len - 1] = (char) flash_target_contents[i];
        }
    }
    // update global ssid and password
    memset(ssid, 0, sizeof(ssid));
    memcpy(ssid, t_ssid, sizeof(t_ssid));

    memset(password, 0, sizeof(password));
    memcpy(password, t_password, sizeof(t_password));
}

void attempt_wifi_connection(void) {
    cyw43_arch_disable_ap_mode();
    cyw43_arch_enable_sta_mode();

    if (cyw43_arch_wifi_connect_timeout_ms(ssid, password, CYW43_AUTH_WPA2_AES_PSK, 15000)) { 
        panic("Failed to connect!");
    } else {
        printf("Connected.\n");
        connection_status = true;
        // success, so save credentials for future use
        save_credentials(ssid, password);
    }
}

static const char *credential_cgi_handler(int iIndex, int iNumParams, char *pcParam[], char *pcValue[]) {
    printf("credential_cgi_handler called\n");
    if (iNumParams > 0) {
        strncpy(ssid, pcValue[0], sizeof(ssid) - 1);
        strncpy(password, pcValue[1], sizeof(password) - 1);
    }
    printf("SSID AND PASSWORD: %s %s \n", ssid, password);
    return "/index.shtml";
}

static const char *connect_cgi_handler(int iIndex, int iNumParams, char *pcParam[], char *pcValue[]) {
    printf("connect_cgi_handler called\n");
    attempt_wifi_connection();
    return "/index.shtml";
}

// Note that the buffer size is limited by LWIP_HTTPD_MAX_TAG_INSERT_LEN, so use LWIP_HTTPD_SSI_MULTIPART to return larger amounts of data
u16_t ssi_handler(int iIndex, char *pcInsert, int iInsertLen
#if LWIP_HTTPD_SSI_MULTIPART
    , uint16_t current_tag_part, uint16_t *next_tag_part
#endif
) {
    size_t printed;
    switch (iIndex) {
        case 0: { // "ssid"
            printed = snprintf(pcInsert, iInsertLen, ssid);
            break;
        }
        case 1: { // "password"
            printed = snprintf(pcInsert, iInsertLen, password);
            break;
        }
        default: { // unknown tag
            printed = 0;
            break;
        }
    }
  return (u16_t)printed;
}