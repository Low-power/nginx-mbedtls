
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Yawning Angel <yawning at schwanenlied dot me>
 */

#ifndef _NGX_EVENT_POLARSSL_H_INCLUDED_
#define _NGX_EVENT_POLARSSL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include "polarssl/config.h"

#include "polarssl/base64.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/certs.h"
#include "polarssl/x509.h"
#include "polarssl/error.h"


#define NGX_SSL_NAME    "PolarSSL"


#define ngx_ssl_session_t       ssl_session
#define ngx_ssl_conn_t          ssl_context


typedef struct {
    ngx_log_t                  *log;
    void                       *data;

    ssize_t                     builtin_session_cache;
    ngx_shm_zone_t             *cache_shm_zone;
    time_t                      cache_ttl;
<<<<<<< HEAD
=======
    size_t                      buffer_size;
>>>>>>> nginx-1.5

    ngx_uint_t                  minor_min;
    ngx_uint_t                  minor_max;

    int                        *ciphersuites;
    dhm_context                 dhm_ctx;
    x509_crt                   own_cert;
    rsa_context                 own_key;
    x509_crt                    ca_cert;
    x509_crl                    ca_crl;

    int                         (*sni_fn)(void *, ssl_context *,
                                          const unsigned char *, size_t);

    unsigned                    have_own_cert:1;
    unsigned                    have_ca_cert:1;
    unsigned                    have_ca_crl:1;

    void                       *ctx;        /* Fake global state */
} ngx_ssl_t;


typedef struct {
    ngx_ssl_conn_t              *connection;

    ngx_int_t                   last;
    ngx_buf_t                   *buf;

    ngx_connection_handler_pt   handler;

    ngx_event_handler_pt        saved_read_handler;
    ngx_event_handler_pt        saved_write_handler;

    unsigned                    handshaked:1;
    unsigned                    buffer:1;
    unsigned                    no_send_shutdown:1;
    unsigned                    no_wait_shutdown:1;
} ngx_ssl_connection_t;


#define NGX_SSL_NO_SCACHE            -2
#define NGX_SSL_NONE_SCACHE          -3
#define NGX_SSL_NO_BUILTIN_SCACHE    -4
#define NGX_SSL_DFLT_BUILTIN_SCACHE  -5


typedef struct ngx_ssl_sess_id_s ngx_ssl_sess_id_t;

struct ngx_ssl_sess_id_s {
    ngx_rbtree_node_t           node;
    ngx_queue_t                 queue;
    ngx_ssl_session_t          *session;
};


typedef struct {
    ngx_rbtree_t                session_rbtree;
    ngx_rbtree_node_t           sentinel;
    ngx_queue_t                 expire_queue;
    time_t                      ttl;
} ngx_ssl_session_cache_t;


#define NGX_SSL_SSLv2       0x0002
#define NGX_SSL_SSLv3       0x0004
#define NGX_SSL_TLSv1       0x0008
#define NGX_SSL_TLSv1_1     0x0010
#define NGX_SSL_TLSv1_2     0x0020


#define NGX_SSL_BUFFER      1
#define NGX_SSL_CLIENT      2

#define NGX_SSL_BUFSIZE     16384


ngx_int_t ngx_ssl_init(ngx_log_t *log);
ngx_int_t ngx_ssl_create(ngx_ssl_t *ssl, ngx_uint_t protocols, void *data);
ngx_int_t ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_str_t *key);
ngx_int_t ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_int_t depth);
ngx_int_t ngx_ssl_trusted_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_int_t depth);
ngx_int_t ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *crl);
ngx_int_t ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *file, ngx_str_t *responder, ngx_uint_t verify);
ngx_int_t ngx_ssl_stapling_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout);
ngx_int_t ngx_ssl_dhparam(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file);
ngx_int_t ngx_ssl_ecdh_curve(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *name);
ngx_int_t ngx_ssl_cipher_list(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *ciphers);
void ngx_ssl_sni_fn(ngx_ssl_t *ssl, int (*sni_fn)(void *, ssl_context *,
    const unsigned char *, size_t));

ngx_int_t ngx_ssl_session_cache(ngx_ssl_t *ssl, ngx_str_t *sess_ctx,
    ssize_t builtin_session_cache, ngx_shm_zone_t *shm_zone, time_t timeout);
ngx_int_t ngx_ssl_session_cache_init(ngx_shm_zone_t *shm_zone, void *data);
<<<<<<< HEAD
=======
ngx_int_t ngx_ssl_session_ticket_keys(ngx_conf_t *cf, ngx_ssl_t *ssl,
        ngx_array_t *paths);
>>>>>>> nginx-1.5
void ngx_ssl_remove_cached_session(ngx_ssl_t *ssl, ngx_ssl_session_t *sess);
ngx_int_t ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session);
ngx_ssl_session_t *ngx_ssl_get_session(ngx_connection_t *c);
ngx_ssl_session_t *ngx_ssl_peek_session(ngx_connection_t *c);
void ngx_ssl_free_session(ngx_ssl_session_t *session);

ngx_int_t ngx_ssl_have_peer_cert(ngx_connection_t *c);
ngx_int_t ngx_ssl_verify_result(ngx_connection_t *c, long *rc,
    const char **errstr);
#define ngx_ssl_verify_error_optional(n)                                \
    (n & BADCERT_NOT_TRUSTED)


ngx_int_t ngx_ssl_get_protocol(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_cipher_name(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_session_id(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_raw_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_subject_dn(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_issuer_dn(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_serial_number(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_client_verify(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);


ngx_int_t ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c,
    ngx_uint_t flags);
ngx_int_t ngx_ssl_handshake(ngx_connection_t *c);
ssize_t ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size);
ssize_t ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *cl);
ngx_chain_t *ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);
void ngx_ssl_free_buffer(ngx_connection_t *c);
ngx_int_t ngx_ssl_shutdown(ngx_connection_t *c);
void ngx_cdecl ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    char *fmt, ...);
void ngx_ssl_cleanup_ctx(void *data);


#endif /* _NGX_EVENT_POLARSSL_H_INCLUDED_ */
