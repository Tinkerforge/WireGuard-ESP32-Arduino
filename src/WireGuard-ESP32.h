/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once
#include <IPAddress.h>

#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"

extern "C" {
 #include "wireguardif.h"
}

class WireGuard
{
private:
	bool _is_initialized = false;

	// Only access from LWIP TCP/IP thread!
	struct netif wg_netif;
	struct netif *previous_default_netif = NULL;
	uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;

public:
	WireGuard();
	~WireGuard();

	WireGuard(const WireGuard &other) = delete;
	const WireGuard operator=(const WireGuard &other) = delete;

	bool begin(// Private address that this device will have in the WireGuard network
	           const IPAddress& localIP,
	           // Subnet of the WireGuard network
	           const IPAddress& Subnet,
			   // Port that the interface will try to bind to
			   const uint16_t localPort,
	           // Gateway of the WireGuard network
	           const IPAddress& Gateway,
	           // Our private key
	           const char* privateKey,
	           // Public address of the peer to connect to
	           const char* remotePeerAddress,
	           // The peers public key
	           const char* remotePeerPublicKey,
	           // Port of the peer
	           uint16_t remotePeerPort,
	           // IP allowed as source in received packets
	           const IPAddress &allowedIP = IPAddress(0, 0, 0, 0),
	           // Subnet allowed as source in received packets
	           const IPAddress &allowedMask = IPAddress(255, 255, 255, 255),
	           // Make WireGuard the default interface for non-local traffic
	           // (i.e. traffic requiring passing through an interface's gateway)
	           bool make_default = true,
	           // Optional preshared key for this connection.
	           const char *preshared_key = nullptr,
			   int (*in_filter_fn)(struct pbuf*) = nullptr,
			   int (*out_filter_fn)(struct pbuf*) = nullptr,
			   void (*update_peer_info_fn)(uint8_t peer_index, bool up, const ip_addr_t *addr, uint16_t port, void *user_data) = nullptr,
			   void *update_peer_info_fn_user_data = nullptr,
			   uint16_t mtu = WIREGUARDIF_MTU);

	// Call after begin(). Arguments are parsed and copied before returning; no
	// caller-owned address or prefix storage is retained. end() clears settings.
	// IPv6 requires an lwIP IPv6 build and an interface MTU of at least 1280.
	bool setIPv6Address(const char* address);
	bool addAllowedIP(const char* network, uint8_t prefixLength);

#if LWIP_IPV6
	// Call only in lwIP TCP/IP context, e.g. from your existing route hook.
	// Returns this tunnel for allowed destinations while up, otherwise nullptr.
	// Does not install/replace hooks or change the default interface.
	struct netif* routeIPv6(const ip6_addr_t* destination) const;
#endif

	void end();
	bool is_initialized() const { return this->_is_initialized; }

	static bool derive_public_key(uint8_t *public_key, const uint8_t *private_key);
};
