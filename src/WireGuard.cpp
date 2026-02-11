/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "WireGuard-ESP32.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_netif.h"
#include "esp_system.h"

#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/ip.h"
#include "lwip/netdb.h"

#include "esp32-hal-log.h"

extern "C" {
#include "wireguardif.h"
#include "wireguard-platform.h"
#include "wireguard.h"
}

#define TAG "[WireGuard] "

extern u8_t wg_netif_client_id;

struct begin_parameters {
	const ip4_addr_t ipaddr;
	const ip4_addr_t netmask;
	const ip4_addr_t gw;
	struct netif *wg_netif;
	void *state;
	uint8_t *wireguard_peer_index;
	struct netif **previous_default_netif;
	struct wireguardif_peer *peer;
	bool make_default;
};

static esp_err_t begin_in_lwip_ctx(void *ctx) {
	begin_parameters *param = static_cast<begin_parameters *>(ctx);

	if (wg_netif_client_id == 0xFF) {
		wg_netif_client_id = netif_alloc_client_data_id();
	}

	// - netif->state is still used to pass the wireguardif_init_data to wireguardif_init.
	// - netif_add clears netif->client_data, so we can't use netif_get/set_client_data to pass the init_data to wireguardif_init.
	// - netif_add calls netif_set_addr directly before wireguardif_init
	// - esp-netif is hooked into netif_set_addr and accesses netif->state if LWIP_ESP_NETIF_DATA is not set
	// -> Require that LWIP_ESP_NETIF_DATA is set to make sure we and esp-netif don't use the same pointer.
	#if !LWIP_ESP_NETIF_DATA
	#error "LWIP_ESP_NETIF_DATA has to be set for wireguard to function!"
	#endif

	// Register the new WireGuard network interface with lwIP
	if (netif_add(param->wg_netif, &param->ipaddr, &param->netmask, &param->gw, param->state, &wireguardif_init, &ip_input) == nullptr) {
		return ESP_FAIL;
	}

	// Mark the interface as administratively up, link up flag is set automatically when peer connects
	netif_set_up(param->wg_netif);

	// Initialize the platform
	wireguard_platform_init();
	// Register the new WireGuard peer with the netwok interface
	wireguardif_add_peer(param->wg_netif, param->peer, param->wireguard_peer_index);
	if ((*param->wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&param->peer->endpoint_ip)) {
		// Start outbound connection to peer
		log_i(TAG "connecting wireguard...");
		wireguardif_connect(param->wg_netif, *param->wireguard_peer_index);

		if (param->make_default) {
			// Save the current default interface for restoring when shutting down the WG interface.
			*param->previous_default_netif = netif_default;
			// Set default interface to WG device.
			netif_set_default(param->wg_netif);
		} else {
			// Make sure we don't attempt to restore the previous default interface in ::end()
			*param->previous_default_netif = nullptr;
		}
	}

	return ESP_OK;
}

static esp_err_t netif_set_default_in_lwip_ctx(void *ctx) {
	netif *nif = static_cast<netif *>(ctx);
	netif_set_default(nif);
	return ESP_OK;
}

bool WireGuard::begin(const IPAddress& localIP,
                      const IPAddress& Subnet,
                      const uint16_t localPort,
                      const IPAddress& Gateway,
                      const char* privateKey,
                      const char* remotePeerAddress,
                      const char* remotePeerPublicKey,
                      uint16_t remotePeerPort,
                      const IPAddress &allowedIP,
                      const IPAddress &allowedMask,
                      bool make_default,
                      const char *preshared_key,
					  int (*in_filter_fn)(struct pbuf*),
					  int (*out_filter_fn)(struct pbuf*),
					  void (*update_peer_info_fn)(uint8_t peer_index, bool up, const ip_addr_t *addr, uint16_t port, void *user_data),
					  void *update_peer_info_fn_user_data,
					  uint16_t mtu) {
	assert(privateKey != NULL);
	assert(remotePeerAddress != NULL);
	assert(remotePeerPublicKey != NULL);
	assert(remotePeerPort != 0);

	// If we know the endpoint's address can add here
	const int64_t t_resolve_start_us = esp_timer_get_time();
	bool success_get_endpoint_ip = false;
	ip_addr_t endpoint_ip;
	for(int retry = 0; retry < 5; retry++) {
		struct addrinfo *res = NULL;
		struct addrinfo hint;
		memset(&hint, 0, sizeof(hint));
		memset(&endpoint_ip, 0, sizeof(endpoint_ip));

		const int64_t t_lookup_start_us = esp_timer_get_time();
		if( lwip_getaddrinfo(remotePeerAddress, NULL, &hint, &res) != 0 ) {
			const  int64_t t_now_us       = esp_timer_get_time();
			const uint32_t t_lookup_us    = static_cast<uint32_t>(t_now_us - t_lookup_start_us);
			const uint32_t t_total_us     = static_cast<uint32_t>(t_now_us - t_resolve_start_us);
			const uint32_t t_remaining_us = 15000000ul - t_total_us; // 15s

			if (t_remaining_us < t_lookup_us) {
				break;
			}

			const uint32_t t_lookup_ms = t_lookup_us / 1000;
			if (t_lookup_ms < 2000) {
				vTaskDelay(pdMS_TO_TICKS(2000 - t_lookup_ms));
			}
			continue;
		}
		success_get_endpoint_ip = true;
		struct in_addr addr4 = ((struct sockaddr_in *) (res->ai_addr))->sin_addr;
		inet_addr_to_ip4addr(ip_2_ip4(&endpoint_ip), &addr4);
		lwip_freeaddrinfo(res);

		log_i(TAG "%s is %3d.%3d.%3d.%3d"
			, remotePeerAddress
			, (endpoint_ip.u_addr.ip4.addr >>  0) & 0xff
			, (endpoint_ip.u_addr.ip4.addr >>  8) & 0xff
			, (endpoint_ip.u_addr.ip4.addr >> 16) & 0xff
			, (endpoint_ip.u_addr.ip4.addr >> 24) & 0xff
			);
		break;
	}
	if( !success_get_endpoint_ip  ) {
		log_e(TAG "failed to get endpoint ip.");
		return false;
	}

	// Initialise the first WireGuard peer structure
	struct wireguardif_peer peer;
	wireguardif_peer_init(&peer);
	peer.endpoint_ip = endpoint_ip;
	peer.public_key = remotePeerPublicKey;
	peer.preshared_key = preshared_key;
	peer.allowed_ip = IPADDR4_INIT(static_cast<uint32_t>(allowedIP));
	peer.allowed_mask = IPADDR4_INIT(static_cast<uint32_t>(allowedMask));;
	peer.endport_port = remotePeerPort;

	// Setup the WireGuard device structure
	struct wireguardif_init_data wg;
	wg.private_key = privateKey;
	wg.listen_port = localPort;
	wg.bind_netif = NULL;
	wg.in_filter_fn = in_filter_fn;
	wg.out_filter_fn = out_filter_fn;
	wg.update_peer_info_fn = update_peer_info_fn;
	wg.update_peer_info_fn_user_data = update_peer_info_fn_user_data;
	wg.mtu = mtu;

	begin_parameters params = {
		{static_cast<uint32_t>(localIP)},
		{static_cast<uint32_t>(Subnet)},
		{static_cast<uint32_t>(Gateway)},
		&this->wg_netif,
		&wg,
		&this->wireguard_peer_index,
		&this->previous_default_netif,
		&peer,
		make_default
	};
	esp_err_t err = esp_netif_tcpip_exec(begin_in_lwip_ctx, &params);
	if (err != ESP_OK) {
		log_e(TAG "failed to initialize WG netif.");
		return false;
	}

	this->_is_initialized = true;
	return true;
}


struct end_parameters {
	struct netif **previous_default_netif;
	struct netif *wg_netif;
	uint8_t *wireguard_peer_index;
};

static esp_err_t end_in_lwip_ctx(void *ctx) {
	end_parameters *param = static_cast<end_parameters *>(ctx);

	if (*param->previous_default_netif != nullptr) {
		// Restore the default interface.
		netif_set_default(*param->previous_default_netif);
		*param->previous_default_netif = nullptr;
	}

	// Disconnect the WG interface.
	wireguardif_disconnect(param->wg_netif, *param->wireguard_peer_index);
	// Remove peer from the WG interface
	wireguardif_remove_peer(param->wg_netif, *param->wireguard_peer_index);
	*param->wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;

	// Shutdown the wireguard interface.
	wireguardif_shutdown(param->wg_netif);
	// Remove the WG interface;
	netif_remove(param->wg_netif);

	return ESP_OK;
}

void WireGuard::end() {
	if( !this->_is_initialized ) return;

	end_parameters params = {
		&this->previous_default_netif,
		&this->wg_netif,
		&this->wireguard_peer_index
	};

	esp_netif_tcpip_exec(end_in_lwip_ctx, &params);

	this->_is_initialized = false;
}

WireGuard::WireGuard() {
	bzero(&this->wg_netif, sizeof(this->wg_netif));
}

WireGuard::~WireGuard() {
	this->end();
}

bool WireGuard::derive_public_key(uint8_t *public_key, const uint8_t *private_key) {
	return wireguard_generate_public_key(public_key, private_key);
}
