
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHA1_H_INCLUDED_
#define _NGX_SHA1_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_HAVE_OPENSSL_SHA1_H)
#include <openssl/sha.h>
#elif (NGX_HAVE_POLARSSL_SHA1_H)
#include <polarssl/sha1.h>
#else
#include <sha.h>
#endif

#if (NGX_POLARSSL_SHA1)
typedef sha1_context    ngx_sha1_t;
#else
typedef SHA_CTX         ngx_sha1_t;
#endif

#if (NGX_POLARSSL_SHA1)

#define ngx_sha1_init           sha1_starts
#define ngx_sha1_update         sha1_update
#define ngx_sha1_final(md, c)   sha1_finish((c), (md))

#else

#define ngx_sha1_init    SHA1_Init
#define ngx_sha1_update  SHA1_Update
#define ngx_sha1_final   SHA1_Final

#endif


#endif /* _NGX_SHA1_H_INCLUDED_ */
