/**
 * Copyright (c) 2026 myVR Software AS
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "tcp.h"
#include "addr.h"
#include "log.h"
#include "stun.h"

#include <string.h>

#ifdef JUICE_ENABLE_TLS
#include <openssl/ssl.h>
#include <openssl/err.h>

static SSL_CTX *tls_create_context(void) {
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx) {
		JLOG_ERROR("Failed to create SSL context");
		return NULL;
	}
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_default_verify_paths(ctx);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	return ctx;
}

static int tls_do_handshake(tcp_turn_conn_t *conn) {
	int ret = SSL_connect((SSL *)conn->tls_ssl);
	if (ret == 1) {
		JLOG_INFO("TLS handshake completed");
		conn->state = TCP_CONN_STATE_CONNECTED;
		return 1;
	}
	int err = SSL_get_error((SSL *)conn->tls_ssl, ret);
	if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
		JLOG_VERBOSE("TLS handshake in progress, want %s",
		             err == SSL_ERROR_WANT_READ ? "read" : "write");
		return 0;
	}
	JLOG_ERROR("TLS handshake failed, SSL error=%d", err);
	conn->state = TCP_CONN_STATE_ERROR;
	return -1;
}
#endif // JUICE_ENABLE_TLS

tcp_turn_conn_t *tcp_turn_create(const addr_record_t *server_addr, bool use_tls) {
	if (use_tls) {
#ifndef JUICE_ENABLE_TLS
		JLOG_ERROR("TLS requested but JUICE_ENABLE_TLS is not enabled");
		return NULL;
#endif
	}

	tcp_turn_conn_t *conn = calloc(1, sizeof(tcp_turn_conn_t));
	if (!conn) {
		JLOG_ERROR("Failed to allocate TCP connection");
		return NULL;
	}

	conn->sock = INVALID_SOCKET;
	conn->state = TCP_CONN_STATE_NEW;
	conn->use_tls = use_tls;
	conn->recv_buf_len = 0;
	conn->server_addr = *server_addr;

	mutex_init(&conn->send_mutex, MUTEX_PLAIN);

	// Create TCP socket
	socket_t sock = socket(server_addr->addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) {
		JLOG_ERROR("TCP socket creation failed, errno=%d", sockerrno);
		goto error;
	}

	conn->sock = sock;

	// Set non-blocking
	ctl_t nbio = 1;
	if (ioctlsocket(sock, FIONBIO, &nbio)) {
		JLOG_ERROR("Setting non-blocking mode on TCP socket failed, errno=%d", sockerrno);
		goto error;
	}

	// Set TCP_NODELAY to disable Nagle's algorithm
	const sockopt_t nodelay = 1;
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay))) {
		JLOG_WARN("Setting TCP_NODELAY failed, errno=%d", sockerrno);
		// Non-fatal, continue
	}

	char addr_str[ADDR_MAX_STRING_LEN];
	addr_to_string((const struct sockaddr *)&server_addr->addr, addr_str, sizeof(addr_str));
	JLOG_DEBUG("Created TCP socket for TURN server %s", addr_str);

	return conn;

error:
	if (conn->sock != INVALID_SOCKET)
		closesocket(conn->sock);
	mutex_destroy(&conn->send_mutex);
	free(conn);
	return NULL;
}

void tcp_turn_destroy(tcp_turn_conn_t *conn) {
	if (!conn)
		return;

#ifdef JUICE_ENABLE_TLS
	if (conn->tls_ssl) {
		SSL_shutdown((SSL *)conn->tls_ssl);
		SSL_free((SSL *)conn->tls_ssl);
		conn->tls_ssl = NULL;
	}
	if (conn->tls_ctx) {
		SSL_CTX_free((SSL_CTX *)conn->tls_ctx);
		conn->tls_ctx = NULL;
	}
#endif

	if (conn->sock != INVALID_SOCKET) {
		closesocket(conn->sock);
		conn->sock = INVALID_SOCKET;
	}

	mutex_destroy(&conn->send_mutex);
	free(conn);
}

int tcp_turn_connect(tcp_turn_conn_t *conn) {
	char addr_str[ADDR_MAX_STRING_LEN];
	addr_to_string((const struct sockaddr *)&conn->server_addr.addr, addr_str, sizeof(addr_str));
	JLOG_INFO("Initiating TCP connection to TURN server %s", addr_str);

	int ret = connect(conn->sock, (const struct sockaddr *)&conn->server_addr.addr,
	                  conn->server_addr.len);
	if (ret == 0) {
		// Connected immediately (unlikely for non-blocking but possible on localhost)
		JLOG_DEBUG("TCP connection established immediately to %s", addr_str);
		conn->state = TCP_CONN_STATE_CONNECTED;
		return 0;
	}

	int err = sockerrno;
#ifdef _WIN32
	if (err == SEWOULDBLOCK) {
#else
	if (err == SEINPROGRESS) {
#endif
		JLOG_DEBUG("TCP connection in progress to %s", addr_str);
		conn->state = TCP_CONN_STATE_CONNECTING;
		return 0;
	}

	JLOG_ERROR("TCP connect to %s failed, errno=%d", addr_str, err);
	conn->state = TCP_CONN_STATE_ERROR;
	return -1;
}

int tcp_turn_check_connect(tcp_turn_conn_t *conn) {
	sockopt_t error = 0;
	socklen_t len = sizeof(error);
	if (getsockopt(conn->sock, SOL_SOCKET, SO_ERROR, (char *)&error, &len) < 0) {
		JLOG_ERROR("getsockopt(SO_ERROR) failed, errno=%d", sockerrno);
		conn->state = TCP_CONN_STATE_ERROR;
		return -1;
	}

	if (error == 0) {
		char addr_str[ADDR_MAX_STRING_LEN];
		addr_to_string((const struct sockaddr *)&conn->server_addr.addr, addr_str,
		               sizeof(addr_str));
		JLOG_INFO("TCP connection established to %s", addr_str);

		if (conn->use_tls) {
#ifdef JUICE_ENABLE_TLS
			conn->tls_ctx = tls_create_context();
			if (!conn->tls_ctx) {
				conn->state = TCP_CONN_STATE_ERROR;
				return -1;
			}
			conn->tls_ssl = SSL_new((SSL_CTX *)conn->tls_ctx);
			if (!conn->tls_ssl) {
				JLOG_ERROR("Failed to create SSL object");
				conn->state = TCP_CONN_STATE_ERROR;
				return -1;
			}
			SSL_set_fd((SSL *)conn->tls_ssl, (int)conn->sock);
			SSL_set_connect_state((SSL *)conn->tls_ssl);
			// Set SNI hostname from server address
			// SNI requires a hostname, not an IP literal — skip for IP addresses
			char sni_host[ADDR_MAX_STRING_LEN];
			sni_host[0] = '\0';
			char addr_str2[ADDR_MAX_STRING_LEN];
			addr_to_string((const struct sockaddr *)&conn->server_addr.addr, addr_str2,
			               sizeof(addr_str2));
			if (addr_str2[0] == '[') {
				// IPv6 bracket notation: [2001:db8::1]:5349
				char *bracket_close = strchr(addr_str2, ']');
				if (bracket_close) {
					size_t len = (size_t)(bracket_close - addr_str2 - 1);
					if (len > 0 && len < sizeof(sni_host)) {
						memcpy(sni_host, addr_str2 + 1, len);
						sni_host[len] = '\0';
					}
				}
			} else {
				// IPv4 or hostname: strip port after last colon
				// But only if there's exactly one colon (avoid bare IPv6 like 2001:db8::1)
				char *first_colon = strchr(addr_str2, ':');
				char *last_colon = strrchr(addr_str2, ':');
				if (first_colon && first_colon == last_colon) {
					// Exactly one colon: host:port
					size_t len = (size_t)(first_colon - addr_str2);
					if (len > 0 && len < sizeof(sni_host)) {
						memcpy(sni_host, addr_str2, len);
						sni_host[len] = '\0';
					}
				} else if (!first_colon) {
					// No colon: bare hostname
					snprintf(sni_host, sizeof(sni_host), "%s", addr_str2);
				}
				// Multiple colons without brackets: bare IPv6, leave sni_host empty
			}
			if (sni_host[0] != '\0') {
				JLOG_DEBUG("Setting TLS SNI hostname: %s", sni_host);
				SSL_set_tlsext_host_name((SSL *)conn->tls_ssl, sni_host);
			} else {
				JLOG_WARN("No valid SNI hostname for TLS (address: %s)", addr_str2);
			}
			conn->state = TCP_CONN_STATE_TLS_HANDSHAKE;
			JLOG_DEBUG("Starting TLS handshake");
			return tls_do_handshake(conn);
#else
			JLOG_ERROR("TLS requested but JUICE_ENABLE_TLS is not enabled");
			conn->state = TCP_CONN_STATE_ERROR;
			return -1;
#endif
		}

		conn->state = TCP_CONN_STATE_CONNECTED;
		return 1;
	}

	if ((int)error == SEINPROGRESS || (int)error == SEWOULDBLOCK) {
		JLOG_VERBOSE("TCP connection still in progress");
		return 0;
	}

	JLOG_ERROR("TCP connection failed, error=%d", (int)error);
	conn->state = TCP_CONN_STATE_ERROR;
	return -1;
}

tcp_conn_state_t tcp_turn_get_state(tcp_turn_conn_t *conn) {
	return conn->state;
}

int tcp_turn_send(tcp_turn_conn_t *conn, const char *data, size_t size) {
	mutex_lock(&conn->send_mutex);

	if (conn->state != TCP_CONN_STATE_CONNECTED
#ifdef JUICE_ENABLE_TLS
	    && conn->state != TCP_CONN_STATE_TLS_HANDSHAKE
#endif
	) {
		JLOG_WARN("Cannot send on TCP connection in state %d", (int)conn->state);
		mutex_unlock(&conn->send_mutex);
		return -1;
	}

#ifdef JUICE_ENABLE_TLS
	if (conn->use_tls && conn->tls_ssl) {
		size_t total_sent = 0;
		while (total_sent < size) {
			int ret = SSL_write((SSL *)conn->tls_ssl, data + total_sent, (int)(size - total_sent));
			if (ret <= 0) {
				int err = SSL_get_error((SSL *)conn->tls_ssl, ret);
				if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
					JLOG_VERBOSE("TLS send would block, sent %zu of %zu bytes so far",
					             total_sent, size);
					if (total_sent > 0) {
						mutex_unlock(&conn->send_mutex);
						return (int)total_sent;
					}
					mutex_unlock(&conn->send_mutex);
					return 0;
				}
				JLOG_ERROR("TLS send failed, SSL error=%d", err);
				conn->state = TCP_CONN_STATE_ERROR;
				mutex_unlock(&conn->send_mutex);
				return -1;
			}
			total_sent += (size_t)ret;
		}
		JLOG_VERBOSE("Sent %zu bytes over TLS", total_sent);
		mutex_unlock(&conn->send_mutex);
		return (int)total_sent;
	}
#endif

	size_t total_sent = 0;
	while (total_sent < size) {
		int ret = send(conn->sock, data + total_sent, (socklen_t)(size - total_sent), 0);
		if (ret <= 0) {
			if (ret == 0) {
				JLOG_WARN("TCP connection closed by peer during send");
				conn->state = TCP_CONN_STATE_CLOSED;
				mutex_unlock(&conn->send_mutex);
				return -1;
			}
			int err = sockerrno;
			if (err == SEAGAIN || err == SEWOULDBLOCK || err == SEINTR) {
				JLOG_VERBOSE("TCP send would block, sent %zu of %zu bytes so far",
				             total_sent, size);
				continue;
			}
			JLOG_ERROR("TCP send failed, errno=%d", err);
			conn->state = TCP_CONN_STATE_ERROR;
			mutex_unlock(&conn->send_mutex);
			return -1;
		}
		total_sent += (size_t)ret;
	}

	JLOG_VERBOSE("Sent %zu bytes over TCP", total_sent);
	mutex_unlock(&conn->send_mutex);
	return (int)total_sent;
}

// Try to extract one complete STUN message or ChannelData from the receive buffer.
// Returns the total message size if a complete message is available, or 0 if not.
// On protocol error returns -1.
static int tcp_try_extract_message(tcp_turn_conn_t *conn, char *buffer, size_t size) {
	if (conn->recv_buf_len < 4)
		return 0; // Need at least 4 bytes to determine message type and length

	uint8_t first_byte = (uint8_t)conn->recv_buf[0];

	if ((first_byte & 0xC0) == 0x00) {
		// STUN message: first two bits are 00
		if (conn->recv_buf_len < sizeof(struct stun_header))
			return 0; // Need full STUN header

		// Read message length from bytes 2-3 (big-endian), after the 2-byte type field
		uint16_t msg_length =
		    (uint16_t)((uint8_t)conn->recv_buf[2] << 8 | (uint8_t)conn->recv_buf[3]);
		size_t total_size = sizeof(struct stun_header) + msg_length;

		if (conn->recv_buf_len < total_size)
			return 0; // Not enough data yet

		if (size < total_size) {
			JLOG_ERROR("Output buffer too small for STUN message, need %zu, have %zu",
			           total_size, size);
			return -1;
		}

		memcpy(buffer, conn->recv_buf, total_size);

		// Compact receive buffer
		conn->recv_buf_len -= total_size;
		if (conn->recv_buf_len > 0)
			memmove(conn->recv_buf, conn->recv_buf + total_size, conn->recv_buf_len);

		JLOG_VERBOSE("Extracted STUN message, size=%zu", total_size);
		return (int)total_size;

	} else if (first_byte >= 0x40 && first_byte <= 0x4F) {
		// ChannelData: first byte in range [0x40, 0x4F]
		// Header: 2-byte channel number + 2-byte length
		uint16_t data_length =
		    (uint16_t)((uint8_t)conn->recv_buf[2] << 8 | (uint8_t)conn->recv_buf[3]);
		size_t unpadded_size = 4 + data_length;
		// Per RFC 8656 Section 12.6, over TCP ChannelData is padded to 4-byte boundary
		size_t padded_size = (unpadded_size + 3) & ~(size_t)3;

		if (conn->recv_buf_len < padded_size)
			return 0; // Not enough data yet

		if (size < unpadded_size) {
			JLOG_ERROR("Output buffer too small for ChannelData, need %zu, have %zu",
			           unpadded_size, size);
			return -1;
		}

		// Copy the unpadded message to output (without padding bytes)
		memcpy(buffer, conn->recv_buf, unpadded_size);

		// Compact receive buffer (consume the padded size)
		conn->recv_buf_len -= padded_size;
		if (conn->recv_buf_len > 0)
			memmove(conn->recv_buf, conn->recv_buf + padded_size, conn->recv_buf_len);

		JLOG_VERBOSE("Extracted ChannelData message, data_length=%hu, padded_size=%zu",
		             data_length, padded_size);
		return (int)unpadded_size;

	} else {
		JLOG_WARN("Unknown message type on TCP stream, first byte=0x%02X", first_byte);
		conn->state = TCP_CONN_STATE_ERROR;
		return -1;
	}
}

int tcp_turn_recv(tcp_turn_conn_t *conn, char *buffer, size_t size) {
	// First check if we already have a complete message buffered
	int extracted = tcp_try_extract_message(conn, buffer, size);
	if (extracted != 0)
		return extracted;

	// Try to read more data from the socket
	size_t remaining = TCP_RECV_BUFFER_SIZE - conn->recv_buf_len;
	if (remaining == 0) {
		JLOG_ERROR("TCP receive buffer full without a complete message");
		conn->state = TCP_CONN_STATE_ERROR;
		return -1;
	}

#ifdef JUICE_ENABLE_TLS
	if (conn->use_tls && conn->tls_ssl) {
		int ret = SSL_read((SSL *)conn->tls_ssl, conn->recv_buf + conn->recv_buf_len,
		                   (int)remaining);
		if (ret <= 0) {
			int err = SSL_get_error((SSL *)conn->tls_ssl, ret);
			if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
				return 0;
			if (err == SSL_ERROR_ZERO_RETURN) {
				JLOG_INFO("TLS connection closed by peer");
				conn->state = TCP_CONN_STATE_CLOSED;
				return -1;
			}
			JLOG_ERROR("TLS recv failed, SSL error=%d", err);
			conn->state = TCP_CONN_STATE_ERROR;
			return -1;
		}
		conn->recv_buf_len += (size_t)ret;
		JLOG_VERBOSE("Received %d bytes over TLS, buffer now has %zu bytes", ret,
		             conn->recv_buf_len);
		return tcp_try_extract_message(conn, buffer, size);
	}
#endif

	int ret = recv(conn->sock, conn->recv_buf + conn->recv_buf_len, (socklen_t)remaining, 0);
	if (ret == 0) {
		JLOG_INFO("TCP connection closed by peer");
		conn->state = TCP_CONN_STATE_CLOSED;
		return -1;
	}
	if (ret < 0) {
		int err = sockerrno;
		if (err == SEAGAIN || err == SEWOULDBLOCK) {
			JLOG_VERBOSE("TCP recv would block, no data available");
			return 0;
		}
		if (err == SEINTR)
			return 0;
		JLOG_ERROR("TCP recv failed, errno=%d", err);
		conn->state = TCP_CONN_STATE_ERROR;
		return -1;
	}

	conn->recv_buf_len += (size_t)ret;
	JLOG_VERBOSE("Received %d bytes on TCP, buffer now has %zu bytes", ret, conn->recv_buf_len);

	// Try to extract a complete message now
	return tcp_try_extract_message(conn, buffer, size);
}

int tcp_turn_tls_handshake(tcp_turn_conn_t *conn) {
#ifdef JUICE_ENABLE_TLS
	if (conn->state != TCP_CONN_STATE_TLS_HANDSHAKE) {
		JLOG_WARN("Not in TLS handshake state");
		return -1;
	}
	return tls_do_handshake(conn);
#else
	(void)conn;
	JLOG_ERROR("TLS support not compiled in");
	return -1;
#endif
}

socket_t tcp_turn_get_socket(tcp_turn_conn_t *conn) {
	return conn->sock;
}
