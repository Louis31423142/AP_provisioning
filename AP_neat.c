/**
 * Copyright (c) 2022 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

#include "lwip/ip4_addr.h"
#include "lwip/apps/mdns.h"
#include "lwip/init.h"
#include "lwip/apps/httpd.h"

#include "dhcpserver.h"
#include "dnsserver.h"


void httpd_init(void);

static absolute_time_t wifi_connected_time;
static bool led_on = false;

char ssid[64] = "";
char password[64] = "";

#if LWIP_MDNS_RESPONDER
static void srv_txt(struct mdns_service *service, void *txt_userdata)
{
  err_t res;
  LWIP_UNUSED_ARG(txt_userdata);

  res = mdns_resp_add_service_txtitem(service, "path=/", 6);
  LWIP_ERROR("mdns add service txt failed\n", (res == ERR_OK), return);
}
#endif

// Return some characters from the ascii representation of the mac address
// e.g. 112233445566
// chr_off is index of character in mac to start
// chr_len is length of result
// chr_off=8 and chr_len=4 would return "5566"
// Return number of characters put into destination
/*
static size_t get_mac_ascii(int idx, size_t chr_off, size_t chr_len, char *dest_in) {
    static const char hexchr[16] = "0123456789ABCDEF";
    uint8_t mac[6];
    char *dest = dest_in;
    assert(chr_off + chr_len <= (2 * sizeof(mac)));
    cyw43_hal_get_mac(idx, mac);
    for (; chr_len && (chr_off >> 1) < sizeof(mac); ++chr_off, --chr_len) {
        *dest++ = hexchr[mac[chr_off >> 1] >> (4 * (1 - (chr_off & 1))) & 0xf];
    }
    return dest - dest_in;
}
*/
static const char *credential_cgi_handler(int iIndex, int iNumParams, char *pcParam[], char *pcValue[]) {
    printf("credential_cgi_handler called\n");
    if (iNumParams > 0) {
        strncpy(ssid, pcValue[0], sizeof(ssid) - 1);
        strncpy(password, pcValue[1], sizeof(password) - 1);
    }
    printf("SSID AND PASSWORD: %s %s \n", ssid, password);
    return "/index.shtml";
}


static tCGI cgi_handlers[] = {
    { "/credentials.cgi", credential_cgi_handler },
};

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

// Be aware of LWIP_HTTPD_MAX_TAG_NAME_LEN
static const char *ssi_tags[] = {
    "ssid",
    "password"
};


#if LWIP_HTTPD_SUPPORT_POST
#define LED_STATE_BUFSIZE 4
static void *current_connection;


err_t httpd_post_begin(void *connection, const char *uri, const char *http_request,
        u16_t http_request_len, int content_len, char *response_uri,
        u16_t response_uri_len, u8_t *post_auto_wnd) {
    printf("post_begin!\n");
    if (memcmp(uri, "/led.cgi", 8) == 0 && current_connection != connection) {
        current_connection = connection;
        snprintf(response_uri, response_uri_len, "/ledfail.shtml");
        *post_auto_wnd = 1;
        return ERR_OK;
    }
    return ERR_VAL;
}

// Return a value for a parameter

char *httpd_param_value(struct pbuf *p, const char *param_name, char *value_buf, size_t value_buf_len) {
    size_t param_len = strlen(param_name);
    u16_t param_pos = pbuf_memfind(p, param_name, param_len, 0);
    if (param_pos != 0xFFFF) {
        u16_t param_value_pos = param_pos + param_len;
        u16_t param_value_len = 0;
        u16_t tmp = pbuf_memfind(p, "&", 1, param_value_pos);
        if (tmp != 0xFFFF) {
            param_value_len = tmp - param_value_pos;
        } else {
            param_value_len = p->tot_len - param_value_pos;
        }
        if (param_value_len > 0 && param_value_len < value_buf_len) {
            char *result = (char *)pbuf_get_contiguous(p, value_buf, value_buf_len, param_value_len, param_value_pos);
            if (result) {
                result[param_value_len] = 0;
                return result;
            }
        }
    }
    return NULL;
}
    

err_t httpd_post_receive_data(void *connection, struct pbuf *p) {
    err_t ret = ERR_VAL;
    LWIP_ASSERT("NULL pbuf", p != NULL);
    if (current_connection == connection) {
        char buf[LED_STATE_BUFSIZE];
        char *val = httpd_param_value(p, "led_state=", buf, sizeof(buf));
        if (val) {
            led_on = (strcmp(val, "ON") == 0) ? true : false;
            cyw43_gpio_set(&cyw43_state, 0, led_on);
            ret = ERR_OK;
        }
    }
    pbuf_free(p);
    return ret;
}

void httpd_post_finished(void *connection, char *response_uri, u16_t response_uri_len) {
    snprintf(response_uri, response_uri_len, "/ledfail.shtml");
    if (current_connection == connection) {
        snprintf(response_uri, response_uri_len, "/ledpass.shtml");
    }
    current_connection = NULL;
}
#endif


int main() {
    stdio_init_all();
    if (cyw43_arch_init()) {
        printf("failed to initialise\n");
        return 1;
    }
    printf("intitialised\n");



    cyw43_arch_enable_ap_mode("picow_test", "12345678", CYW43_AUTH_WPA2_AES_PSK);
    printf("\nReady, running iperf server at %s\n", ip4addr_ntoa(netif_ip4_addr(netif_list)));

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
    //get_mac_ascii(CYW43_HAL_MAC_WLAN0, 8, 4, &hostname[sizeof(CYW43_HOST_NAME) - 1]);
    hostname[sizeof(hostname) - 1] = '\0';
    netif_set_hostname(&cyw43_state.netif[CYW43_ITF_STA], hostname);

    // start http server
    wifi_connected_time = get_absolute_time();

#if LWIP_MDNS_RESPONDER
    // Setup mdns
    cyw43_arch_lwip_begin();
    mdns_resp_init();
    printf("mdns host name %s.local\n", hostname);
#if LWIP_VERSION_MAJOR >= 2 && LWIP_VERSION_MINOR >= 2
    mdns_resp_add_netif(&cyw43_state.netif[CYW43_ITF_STA], hostname);
    mdns_resp_add_service(&cyw43_state.netif[CYW43_ITF_STA], "pico_httpd", "_http", DNSSD_PROTO_TCP, 80, srv_txt, NULL);
#else
    mdns_resp_add_netif(&cyw43_state.netif[CYW43_ITF_STA], hostname, 60);
    mdns_resp_add_service(&cyw43_state.netif[CYW43_ITF_STA], "pico_httpd", "_http", DNSSD_PROTO_TCP, 80, 60, srv_txt, NULL);
#endif
    cyw43_arch_lwip_end();
#endif
    // setup http server
    cyw43_arch_lwip_begin();
    httpd_init();
    http_set_cgi_handlers(cgi_handlers, LWIP_ARRAYSIZE(cgi_handlers));
    http_set_ssi_handler(ssi_handler, ssi_tags, LWIP_ARRAYSIZE(ssi_tags));
    cyw43_arch_lwip_end();

    while(true) {
#if PICO_CYW43_ARCH_POLL
        cyw43_arch_poll();
        cyw43_arch_wait_for_work_until(led_time);
#else
        sleep_ms(1000);
#endif
    }
#if LWIP_MDNS_RESPONDER
    mdns_resp_remove_netif(&cyw43_state.netif[CYW43_ITF_STA]);
#endif
    cyw43_arch_deinit();
}