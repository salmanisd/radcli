/*
 * Copyright (c) 2014, 2015, Nikos Mavrogiannopoulos.  All rights reserved.
 * Copyright (c) 2015, Red Hat, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include "util.h"
#include "tls.h"

/**
 * @defgroup tls-api TLS/DTLS API
 * @brief TLS and DTLS related functions
 *
 * Note that, that API is for improving TLS and DTLS support
 * in an application. Applications are not required to use this
 * API to support them. TLS and DTLS support can be enabled by
 * the administrator transparently from the radiusclient configuration
 * file.
 *
 * @{
 */

#include <pthread.h>
#include <time.h>

#define DEFAULT_DTLS_SECRET "radius/dtls"
#define DEFAULT_TLS_SECRET "radsec"

typedef struct tls_int_st {
	char hostname[256];	/* server's hostname */
	unsigned port;		/* server's port */
	struct sockaddr_storage our_sockaddr;
	SSL *ssl;
	int sockfd;
	unsigned init;
	unsigned need_restart;
	unsigned skip_hostname_check; /* whether to verify hostname */
	pthread_mutex_t lock;
	time_t last_msg;
	time_t last_restart;
} tls_int_st;

typedef struct tls_st {
	struct tls_int_st ctx;	/* one for ACCT and another for AUTH */
	unsigned flags; /* the flags set on init */
	rc_handle *rh; /* a pointer to our owner */
} tls_st;

static void restart_session(rc_handle *rh, tls_st *st);

static int tls_get_fd(void *ptr, struct sockaddr *our_sockaddr)
{
	tls_st *st = ptr;
	return st->ctx.sockfd;
}

static ssize_t tls_sendto(void *ptr, int sockfd,
			   const void *buf, size_t len,
			   int flags, const struct sockaddr *dest_addr,
			   socklen_t addrlen)
{
	tls_st *st = ptr;
	int ret = 0 , bs = 0;
	size_t bytes_sent = 0;

	if (st->ctx.need_restart != 0) {
		restart_session(st->rh, st);
	}

	while (bytes_sent < len) {
		bs = SSL_write(st->ctx.ssl, buf+bytes_sent, len-bytes_sent);
		if (bs < 1) {
			rc_log(LOG_ERR, "%s: SSL write failed with error  %d", __func__, SSL_get_error(st->ctx.ssl, bs));
			errno = EIO;
			st->ctx.need_restart = 1;
			return -1;
		}
		if (bs == 0) {
			return -1;
		}
		bytes_sent += bs;
	}

	st->ctx.last_msg = time(0);
	return ret;
}

static int tls_lock(void *ptr)
{
	tls_st *st = ptr;

	return pthread_mutex_lock(&st->ctx.lock);
}

static int tls_unlock(void *ptr)
{
	tls_st *st = ptr;

	return pthread_mutex_unlock(&st->ctx.lock);
}

static ssize_t tls_recvfrom(void *ptr, int sockfd,
			     void *buf, size_t len,
			     int flags, struct sockaddr *src_addr,
			     socklen_t * addrlen)
{
	tls_st *st = ptr;
	int ret =0, br = 0;

	br = SSL_read(st->ctx.ssl, buf, len);
	if (br <= 0) {
		rc_log(LOG_ERR, "%s: SSL read failed", __func__);
		errno = EIO;
		st->ctx.need_restart = 1;
		return -1;
	}

	st->ctx.last_msg = time(0);
	return br;
}

static void deinit_session(tls_int_st *ses)
{
	if (ses->init != 0) {
		ses->init = 0;
		pthread_mutex_destroy(&ses->lock);
		if (ses->sockfd != -1) {
			close(ses->sockfd);
		}
		SSL_CTX_free((SSL_get_SSL_CTX(ses->ssl)));
		SSL_free(ses->ssl);
		EVP_cleanup();
	}
}

static int init_session(rc_handle *rh, tls_int_st *ses,
			const char *hostname, unsigned port,
			struct sockaddr_storage *our_sockaddr,
			int timeout,
			unsigned secflags)
{
	int sockfd, ret, e;
	struct addrinfo *info;
	char *p;
	unsigned flags = 0;
	unsigned cred_set = 0;
	tls_st *st = rh->so.ptr;

	ses->sockfd = -1;
	ses->init = 1;

	pthread_mutex_init(&ses->lock, NULL);
	sockfd = socket(our_sockaddr->ss_family, (secflags&SEC_FLAG_DTLS)?SOCK_DGRAM:SOCK_STREAM, 0);
	if (sockfd < 0) {
		rc_log(LOG_ERR,
		       "%s: cannot open socket", __func__);
		ret = -1;
		goto cleanup;
	}

	if (our_sockaddr->ss_family == AF_INET)
		((struct sockaddr_in *)our_sockaddr)->sin_port = 0;
	else
		((struct sockaddr_in6 *)our_sockaddr)->sin6_port = 0;

	ses->sockfd = sockfd;
	memcpy(&ses->our_sockaddr, our_sockaddr, sizeof(*our_sockaddr));

	info =
	    rc_getaddrinfo(hostname, PW_AI_AUTH);
	if (info == NULL) {
		ret = -1;
		rc_log(LOG_ERR, "%s: cannot resolve %s", __func__,
		       hostname);
		goto cleanup;
	}

	if (port != 0) {
		if (info->ai_addr->sa_family == AF_INET)
			((struct sockaddr_in *)info->ai_addr)->sin_port =
			    htons(port);
		else
			((struct sockaddr_in6 *)info->ai_addr)->sin6_port =
			    htons(port);
	} else {
		rc_log(LOG_ERR, "%s: no port specified for server %s",
		       __func__, hostname);
		ret = -1;
		goto cleanup;
	}

	strlcpy(ses->hostname, hostname, sizeof(ses->hostname));
	ses->port = port;

	ret = connect(sockfd, info->ai_addr, info->ai_addrlen);
	freeaddrinfo(info);
	if (ret == -1) {
		e = errno;
		ret = -1;
		rc_log(LOG_CRIT, "%s: cannot connect to %s: %s",
		       __func__, hostname, strerror(e));
		goto cleanup;
	}

	if (SSL_set_fd(ses->ssl, sockfd) !=1 ) {
		rc_log(LOG_ERR, "%s:SSL_set_fd failed ", __func__);\
		goto cleanup;
	}

	rc_log(LOG_DEBUG,
	       "%s: performing TLS/DTLS handshake with [%s]:%d",
	       __func__, hostname, port);
	if (ses->ssl) {
		ERR_clear_error();
		ret = SSL_connect(ses->ssl);
	}
	if (ret<1) {
		rc_log(LOG_ERR, "%s: SSL error 0x%lx in connect", __func__, ERR_get_error());
		ret = -1;
		goto cleanup;
	}

	return 0;

 cleanup:
	deinit_session(ses);
	return ret;
}

/* The time after the last message was received, that
 * we will try heartbeats */
#define TIME_ALIVE 120

static void restart_session(rc_handle *rh, tls_st *st)
{
	struct tls_int_st tmps;
	time_t now = time(0);
	int ret;
	int timeout;

	if (now - st->ctx.last_restart < TIME_ALIVE)
		return;

	st->ctx.last_restart = now;

	timeout = rc_conf_int(rh, "radius_timeout");

	if (st->ctx.init != 0) {
		st->ctx.init = 0;
		pthread_mutex_destroy(&st->ctx.lock);
		close(st->ctx.sockfd);
	}
	/* reinitialize this session */
	ret = init_session(rh, &st->ctx , st->ctx.hostname, st->ctx.port, &st->ctx.our_sockaddr, timeout, st->flags);
	if (ret < 0) {
		rc_log(LOG_ERR, "%s: error in re-initializing DTLS", __func__);
		return;
	}

	st->ctx.need_restart = 0;

	return;
}

/** Returns the file descriptor of the TLS/DTLS session
 *
 * This can also be used as a test for the application to see
 * whether TLS or DTLS are in use.
 *
 * @param rh a handle to parsed configuration
 * @return the file descriptor used by the TLS session, or -1 on error
 */
int rc_tls_fd(rc_handle * rh)
{
	tls_st *st;

	if (rh->so_type != RC_SOCKET_TLS && rh->so_type != RC_SOCKET_DTLS)
		return -1;

	st = rh->so.ptr;

	if (st->ctx.init != 0) {
		return st->ctx.sockfd;
	}
	return -1;
}

/** Check established TLS/DTLS channels for operation
 *
 * This function will check whether the channel(s) established
 * for TLS or DTLS are operational, and will re-establish the channel
 * if necessary. If this function fails then  the TLS or DTLS state 
 * should be considered as disconnected.
 * It must be called at a time when the sessions are not in usage
 * (e.g., in a different thread).
 *
 * Note: It is recommended to run this function periodically if you
 * have a DTLS channel since an undetected server reset may
 * result to a black hole behavior of the server.
 *
 * @param rh a handle to parsed configuration
 * @return 0 on success, -1 on error
 */
int rc_check_tls(rc_handle * rh)
{
	tls_st *st;
	time_t now = time(0);
	int ret;

	if (rh->so_type != RC_SOCKET_TLS && rh->so_type != RC_SOCKET_DTLS)
		return 0;

	st = rh->so.ptr;

	if (st->ctx.init != 0) {
		if (st->ctx.need_restart != 0) {
			restart_session(rh, st);
		} else if (now - st->ctx.last_msg > TIME_ALIVE) {
			restart_session(rh, st);
			st->ctx.last_msg = now;
		}
	}
	return 0;
}

/* This function will deinitialize a previously initialed DTLS or TLS session.
 *
 * @param rh the configuration handle.
 */
void rc_deinit_tls(rc_handle * rh)
{
	tls_st *st = rh->so.ptr;
	if (st) {
		if (st->ctx.init != 0)
			deinit_session(&st->ctx);
	}
	free(st);
}

static SSL_CTX *init_ssl(void)
{
	SSL_METHOD *method = NULL;
	SSL_CTX *ctx = NULL;

	method = TLSv1_2_client_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		rc_log(LOG_ERR, "%s: failed to create SSL context", __func__);
		return NULL;
	}
	return ctx;
}

static int set_trust_file(const char *ca_file, SSL_CTX *ctx)
{
	if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) !=1 ) {
		return -1;
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	return 0;
}

/*- Initialize a configuration for TLS or DTLS
 *
 * This function will initialize the handle for TLS or DTLS.
 *
 * @param rh a handle to parsed configuration
 * @param flags must be zero or SEC_FLAG_DTLS
 * @return 0 on success, -1 on failure.
 -*/
int rc_init_tls(rc_handle * rh, unsigned flags)
{
	int ret;
	tls_st *st = NULL;
	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
	struct sockaddr_storage our_sockaddr;
	const char *ca_file = rc_conf_str(rh, "tls-ca-file");
	SERVER *authservers;
	char hostname[256];	/* server's hostname */
	unsigned port;		/* server's port */

	memset(&rh->so, 0, sizeof(rh->so));

	if (flags & SEC_FLAG_DTLS) {
		rh->so_type = RC_SOCKET_DTLS;
		rh->so.static_secret = DEFAULT_DTLS_SECRET;
	} else {
		rh->so_type = RC_SOCKET_TLS;
		rh->so.static_secret = DEFAULT_TLS_SECRET;
	}

	rc_own_bind_addr(rh, &our_sockaddr);
	
	ssl_ctx = init_ssl();

	st = calloc(1, sizeof(tls_st));
	if (st == NULL) {
		ret = -1;
		goto cleanup;
	}

	st->rh = rh;
	st->flags = flags;

	rh->so.ptr = st;

	/* Currently only verify server by using a provided ca file or skip server 
	 * verfication altogether.Also assume server does not require client 
	 * verification. If client verification is required, add support for 
	 * rc_conf_str(rh, "tls-cert-file") and rc_conf_str(rh, "tls-key-file")
	 */
	if (ca_file) {
		if (set_trust_file(ca_file, ssl_ctx) < 0) {
			rc_log(LOG_ERR, "%s: error in ca verify location", __func__);
			ret = -1;
			goto cleanup;
		}
	} else { 
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
	}

	st->ctx.ssl = SSL_new(ssl_ctx);

	authservers = rc_conf_srv(rh, "authserver");
	if (authservers == NULL) {
		rc_log(LOG_ERR,
		       "%s: cannot find authserver", __func__);
		ret = -1;
		goto cleanup;
	}
	if (authservers->max > 1) {
		ret = -1;
		rc_log(LOG_ERR,
		       "%s: too many auth servers for TLS/DTLS; only one is allowed",
		       __func__);
		goto cleanup;
	}
	strlcpy(hostname, authservers->name[0], sizeof(hostname));
	port = authservers->port[0];

	ret = init_session(rh, &st->ctx, hostname, port, &our_sockaddr, 0, flags);
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}

	rh->so.get_fd = tls_get_fd;
	rh->so.sendto = tls_sendto;
	rh->so.recvfrom = tls_recvfrom;
	rh->so.lock = tls_lock;
	rh->so.unlock = tls_unlock;
	return 0;
 
cleanup:
	if (st) {
		if (st->ctx.init != 0)
			deinit_session(&st->ctx);
	}
	free(st);
	return ret;
}

