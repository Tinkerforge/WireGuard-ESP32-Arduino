/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once
#include <IPAddress.h>

class WireGuard
{
private:
	bool _is_initialized = false;
public:
	bool begin(// Private address that this device will have in the WireGuard network
	           const IPAddress& localIP,
	           // Subnet of the WireGuard network
	           const IPAddress& Subnet,
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
	           // IP to route over WireGuard
	           const IPAddress &allowedIP = IPAddress(0, 0, 0, 0),
	           // Subnet to route over WireGuard
	           const IPAddress &allowedMask = IPAddress(0, 0, 0, 0),
	           // Make WireGuard the default interface for non-local traffic
	           // (i.e. traffic requiring passing through an interface's gateway)
	           bool make_default = true);

	void end();
	bool is_initialized() const { return this->_is_initialized; }
};
