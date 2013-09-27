/*
 * liballium_ptcfg.h: Tor Pluggable Transport Configuration
 * Copyright 2013 Yawning Angel <yawning at schwanenlied dot me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _ALLIUM_PTCFG_H_
#define _ALLIUM_PTCFG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

typedef struct allium_ptcfg_s   allium_ptcfg;

#define ALLIUM_ERR_PTCFG			0x00020000
#define ALLIUM_ERR_PTCFG_NOT_CLIENT		(-(ALLIUM_ERR_PTCFG | 1))
#define ALLIUM_ERR_PTCFG_NOT_SERVER		(-(ALLIUM_ERR_PTCFG | 2))
#define ALLIUM_ERR_PTCFG_INVALID_METHOD		(-(ALLIUM_ERR_PTCFG | 3))
#define ALLIUM_ERR_PTCFG_NO_ADDRESS		(-(ALLIUM_ERR_PTCFG | 4))
#define ALLIUM_ERR_PTCFG_NO_AUTH_COOKIE		(-(ALLIUM_ERR_PTCFG | 5))

allium_ptcfg *allium_ptcfg_init(void);
void allium_ptcfg_free(allium_ptcfg *cfg);

int allium_ptcfg_state_dir(const allium_ptcfg *cfg, char *path, size_t
    *path_len);
int allium_ptcfg_is_server(const allium_ptcfg *cfg);
int allium_ptcfg_method_requested(const allium_ptcfg *cfg, const char *method);
int allium_ptcfg_or_port(const allium_ptcfg *cfg, struct sockaddr *addr,
    socklen_t *addr_len);
int allium_ptcfg_ext_port(const allium_ptcfg *cfg, struct sockaddr *addr,
    socklen_t *addr_len);
int allium_ptcfg_bind_addr(const allium_ptcfg *cfg, const char *method, struct
    sockaddr *addr, socklen_t *addr_len);
int allium_ptcfg_auth_cookie_file(const allium_ptcfg *cfg, char *path, size_t
    *path_len);

int allium_ptcfg_cmethod_report(const allium_ptcfg *cfg, const char *method,
    int socks_ver, const struct sockaddr *addr,
    socklen_t addr_len, const char *args, const char *opt_args);
int allium_ptcfg_smethod_report(const allium_ptcfg *cfg, const char *method,
    const struct sockaddr *addr, socklen_t addr_len, const char *args);
int allium_ptcfg_method_error(const allium_ptcfg *cfg, const char *method,
    const char *msg);
int allium_ptcfg_methods_done(const allium_ptcfg *cfg);

#ifdef __cplusplus
}
#endif

#endif
