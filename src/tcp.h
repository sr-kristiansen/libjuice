/**
 * Copyright (c) 2026 myVR Software AS
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef JUICE_TCP_H
#define JUICE_TCP_H

#include "addr.h"
#include "socket.h"
#include "thread.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TCP_RECV_BUFFER_SIZE 65536

typedef enum tcp_conn_state {
	TCP_CONN_STATE_NEW = 0,
	TCP_CONN_STATE_CONNECTING,
	TCP_CONN_STATE_CONNECTED,
#ifdef JUICE_ENABLE_TLS
	TCP_CONN_STATE_TLS_HANDSHAKE,
#endif
	TCP_CONN_STATE_ERROR,
	TCP_CONN_STATE_CLOSED
} tcp_conn_state_t;

typedef struct tcp_turn_conn {
	socket_t sock;
	tcp_conn_state_t state;
	mutex_t send_mutex;
	bool use_tls;

	// Receive buffer for TCP stream reassembly
	char recv_buf[TCP_RECV_BUFFER_SIZE];
	size_t recv_buf_len;

	// Server address (for logging/reconnect)
	addr_record_t server_addr;

#ifdef JUICE_ENABLE_TLS
	void *tls_ctx;   // SSL_CTX*
	void *tls_ssl;   // SSL*
#endif
} tcp_turn_conn_t;

// Create a TCP TURN connection (does not connect yet)
tcp_turn_conn_t *tcp_turn_create(const addr_record_t *server_addr, bool use_tls);

// Destroy and free TCP connection
void tcp_turn_destroy(tcp_turn_conn_t *conn);

// Initiate non-blocking TCP connect
int tcp_turn_connect(tcp_turn_conn_t *conn);

// Check connect completion (call when socket is writable)
// Returns: 0 = still connecting, 1 = connected, -1 = error
int tcp_turn_check_connect(tcp_turn_conn_t *conn);

// Get connection state
tcp_conn_state_t tcp_turn_get_state(tcp_turn_conn_t *conn);

// Send data over TCP (thread-safe, adds no framing - caller must frame STUN/ChannelData)
int tcp_turn_send(tcp_turn_conn_t *conn, const char *data, size_t size);

// Receive one complete STUN message or ChannelData from TCP stream
// Returns: >0 = bytes of complete message written to buffer
//          0 = no complete message available yet (need more data)
//         -1 = error or connection closed
int tcp_turn_recv(tcp_turn_conn_t *conn, char *buffer, size_t size);

// Continue TLS handshake (call when socket is readable/writable during TLS_HANDSHAKE state)
// Returns: 0 = still in progress, 1 = handshake complete (state -> CONNECTED), -1 = error
int tcp_turn_tls_handshake(tcp_turn_conn_t *conn);

// Get the underlying socket for poll() integration
socket_t tcp_turn_get_socket(tcp_turn_conn_t *conn);

#endif // JUICE_TCP_H
