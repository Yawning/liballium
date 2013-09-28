/*
 * liballium_ptcfg.c: Tor Pluggable Transport Configuration
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "allium.h"
#include "bstrlib.h"


#define PTCFG_STATE_LOCATION		"TOR_PT_STATE_LOCATION"
#define PTCFG_MANAGED_TRANSPORT_VER	"TOR_PT_MANAGED_TRANSPORT_VER"

#define PTCFG_CLIENT_TRANSPORTS		"TOR_PT_CLIENT_TRANSPORTS"

#define PTCFG_EXTENDED_SERVER_PORT	"TOR_PT_EXTENDED_SERVER_PORT"
#define PTCFG_ORPORT			"TOR_PT_ORPORT"
#define PTCFG_SERVER_BIND_ADDR		"TOR_PT_SERVER_BINDADDR"
#define PTCFG_SERVER_TRANSPORTS		"TOR_PT_SERVER_TRANSPORTS"

#define PTCFG_MANAGED_TRANSPORT_V1	"1"
#define PTCFG_ALL_TRANSPORTS		"*"


struct allium_ptcfg_method_s {
	bstring			name;

	int			has_bind_addr;
	struct sockaddr_storage bind_addr;
	socklen_t		bind_addr_len;
};

struct allium_ptcfg_s {
	bstring				version;
	bstring				state_location;

	struct allium_ptcfg_method_s *	methods;
	int				nr_methods;

	/* Server specific information */
	int				is_server;
	int				has_ext_port;
	struct sockaddr_storage		ext_port;
	socklen_t			ext_port_len;
	struct sockaddr_storage		or_port;
	socklen_t			or_port_len;
};


static struct allium_ptcfg_method_s *get_method(const allium_ptcfg *cfg, const
    char *method);
static int parse_addr(const char *addr, struct sockaddr *out, socklen_t
    *out_len);


allium_ptcfg *
allium_ptcfg_init(void)
{
	allium_ptcfg *cfg;
	int transports_valid = 0;
	int orport_valid = 0;
	int extport_valid = 0;
	int bindaddrs_valid = 0;

	cfg = calloc(1, sizeof(*cfg));
	if (NULL == cfg) {
		fprintf(stdout, "ENV-ERROR Failed to allocate cfg\n");
		return (NULL);
	}

	/*
	 * Ensure that we are speaking a compatible version before contiuning
	 * parsing.
	 */
	do {
		const struct tagbstring supported_ver = bsStatic(PTCFG_MANAGED_TRANSPORT_V1);
		struct bstrList *l;
		bstring str;
		int i;

		str = bfromcstr(getenv(PTCFG_MANAGED_TRANSPORT_VER));
		if (NULL == str) {
			fprintf(stdout, "ENV-ERROR No Managed Transport Version\n");
			break;
		}
		if (0 == blength(str)) {
			bdestroy(str);
			fprintf(stdout, "ENV-ERROR Empty Transport Version\n");
			break;
		}
		l = bsplit(str, ',');
		if (NULL == l) {
			bdestroy(str);
			fprintf(stdout, "ENV-ERROR OOM parsing Version\n");
			break;
		}
		for (i = 0; i < l->qty; i++) {
			if (0 == bstrcmp(l->entry[i], &supported_ver)) {
				cfg->version = bstrcpy(l->entry[i]);
				break;
			}
		}
		bstrListDestroy(l);
		bdestroy(str);
		if (NULL == cfg->version)
			fprintf(stdout, "VERSION-ERROR no-version\n");
	} while (0);
	if (NULL == cfg->version) {
		allium_ptcfg_free(cfg);
		return (NULL);
	}

	/* Handle the state directory */
	cfg->state_location = bfromcstr(getenv(PTCFG_STATE_LOCATION));
	if (NULL == cfg->state_location) {
		/* Note: This can also be a case where we are OOM */
		fprintf(stdout, "ENV-ERROR No State Directory\n");
		allium_ptcfg_free(cfg);
		return (NULL);
	}

	/* Handle the transport list */
	do {
		struct bstrList *l;
		bstring str;
		char *transports;
		int i;

		transports = getenv(PTCFG_SERVER_TRANSPORTS);
		cfg->is_server = (NULL != transports);
		if (!cfg->is_server)
			transports = getenv(PTCFG_CLIENT_TRANSPORTS);
		if (NULL == transports) {
			fprintf(stdout, "ENV-ERROR No Transports\n");
			break;
		}
		str = bfromcstr(transports);
		if (NULL == str) {
			fprintf(stdout, "ENV-ERROR OOM parsing Transports\n");
			break;
		}
		if (0 == blength(str)) {
			bdestroy(str);
			fprintf(stdout, "ENV-ERROR Empty Transport List\n");
			break;
		}
		l = bsplit(str, ',');
		if (NULL == l) {
			bdestroy(str);
			fprintf(stdout, "ENV-ERROR OOM parsing Transports\n");
			break;
		}
		cfg->methods = calloc(l->qty, sizeof(*cfg->methods));
		if (NULL == cfg->methods) {
			bstrListDestroy(l);
			bdestroy(str);
			fprintf(stdout, "ENV-ERROR OOM parsing Transports\n");
			break;
		}
		for (i = 0; i < l->qty; i++) {
			if (0 == blength(l->entry[i])) {
				fprintf(stdout, "ENV-ERROR Invalid Transport\n");
				goto done_transport_iter;
			}
			cfg->methods[i].name = bstrcpy(l->entry[i]);
			if (NULL == cfg->methods[i].name) {
				fprintf(stdout, "ENV-ERROR OOM parsing Transports\n");
				goto done_transport_iter;
			}
			cfg->nr_methods++;
		}
		transports_valid = 1;
done_transport_iter:
		bstrListDestroy(l);
		bdestroy(str);
	} while (0);
	if (!transports_valid) {
		allium_ptcfg_free(cfg);
		return (NULL);
	}

	if (!cfg->is_server)
		goto done;


	/*
	 * Handle the server specific options
	 */

	/* ORPort */
	do {
		char *or_port;

		or_port = getenv(PTCFG_ORPORT);
		if (NULL == or_port) {
			fprintf(stdout, "ENV-ERROR No ORPort\n");
			break;
		}
		cfg->or_port_len = sizeof(cfg->or_port);
		if (parse_addr(or_port, (struct sockaddr *)&cfg->or_port,
			    &cfg->or_port_len)) {
			fprintf(stdout, "ENV-ERROR Malformed ORPort\n");
			break;
		}
		orport_valid = 1;
	} while (0);
	if (!orport_valid) {
		allium_ptcfg_free(cfg);
		return (NULL);
	}

	/* Extended Server Port */
	do {
		char *ext_port;

		ext_port = getenv(PTCFG_EXTENDED_SERVER_PORT);
#if 0

		/*
		 * The spec says that this will always exist, but according to
		 * src/or/transports.c, the intention moving forward is for it
		 * to be optional, so be tollerant.
		 */
		if (NULL == ext_port) {
			fprintf(stdout, "ENV-ERROR No Extended Server Port\n");
			break;
		}
#else
		if ((NULL == ext_port) || (0 == strlen(ext_port))) {
			extport_valid = 1;
			break;
		}
#endif
		cfg->ext_port_len = sizeof(cfg->ext_port);
		if (parse_addr(ext_port, (struct sockaddr *)&cfg->ext_port,
			    &cfg->ext_port_len)) {
			fprintf(stdout, "ENV-ERROR Malformed Extended Server Port\n");
			break;
		}
		cfg->has_ext_port = 1;
		extport_valid = 1;
	} while (0);
	if (!extport_valid) {
		allium_ptcfg_free(cfg);
		return (NULL);
	}

	/* Bind addresses */
	do {
		struct bstrList *l;
		bstring str;
		int i, j;

		str = bfromcstr(getenv(PTCFG_SERVER_BIND_ADDR));
		if (NULL == str) {
			/* Note: This can also be a case where we are OOM */
			fprintf(stdout, "ENV-ERROR No Bind Addresses\n");
			break;
		}
		l = bsplit(str, ',');
		if (NULL == l) {
			bdestroy(str);
			fprintf(stdout, "ENV-ERROR OOM parsing Bind Addresses\n");
			break;
		}
		if (l->qty != cfg->nr_methods) {
			fprintf(stdout, "ENV-ERROR Malformed Bind Addresses\n");
			goto done_bindaddrs_iter;
		}
		for (i = 0; i < l->qty; i++) {
			j = bstrrchr(l->entry[i], '-');
			if ((j != blength(cfg->methods[i].name)) ||
			    bstrncmp(l->entry[i],
				    cfg->methods[i].name, j - 1)) {
				fprintf(stdout, "ENV-ERROR Unexpected method in Bind Address\n");
				goto done_bindaddrs_iter;
			}
			cfg->methods[i].bind_addr_len = sizeof(cfg->methods[i].bind_addr);
			if (parse_addr(bdataofs(l->entry[i], j + 1),
				    (struct sockaddr *)&cfg->methods[i].bind_addr,
				    &cfg->methods[i].bind_addr_len)) {
				fprintf(stdout, "ENV-ERROR Invalid address in Bind Address (%s)\n",
				    bdata(l->entry[i]));
				goto done_bindaddrs_iter;
			}
			cfg->methods[i].has_bind_addr = 1;
		}
		bindaddrs_valid = 1;
done_bindaddrs_iter:
		bstrListDestroy(l);
		bdestroy(str);
	} while (0);
	if (!bindaddrs_valid) {
		allium_ptcfg_free(cfg);
		return (NULL);
	}

done:
	/* Report back that a compatible PT version has been found */
	fprintf(stdout, "VERSION %s\n", bdata(cfg->version));

	return (cfg);
}


void
allium_ptcfg_free(allium_ptcfg *cfg)
{
	int i;

	if (NULL == cfg)
		return;

	bdestroy(cfg->version);
	bdestroy(cfg->state_location);
	if (NULL != cfg->methods) {
		for (i = 0; i < cfg->nr_methods; i++) {
			bdestroy(cfg->methods[i].name);
		}
		free(cfg->methods);
	}

	free(cfg);
}


int
allium_ptcfg_state_dir(const allium_ptcfg *cfg, char *path, size_t *path_len)
{
	size_t len;

	if ((NULL == cfg) || (NULL == path_len))
		return (ALLIUM_ERR_INVAL);

	len = blength(cfg->state_location) + 1;
	if ((NULL == path) || (*path_len < len)) {
		*path_len = len;
		return (ALLIUM_ERR_NOBUFS);
	}
	memcpy(path, cfg->state_location->data, len);
	path[len - 1] = '\0';
	*path_len = len;

	return (0);
}


int
allium_ptcfg_is_server(const allium_ptcfg *cfg)
{
	if (NULL == cfg)
		return (ALLIUM_ERR_INVAL);

	return (cfg->is_server);
}


int
allium_ptcfg_or_port(const allium_ptcfg *cfg, struct sockaddr *addr, socklen_t
    *addr_len)
{
	if ((NULL == cfg) || (NULL == addr_len))
		return (ALLIUM_ERR_INVAL);

	if (!cfg->is_server)
		return (ALLIUM_ERR_PTCFG_NOT_SERVER);

	if ((NULL == addr) || (*addr_len < cfg->or_port_len)) {
		*addr_len = cfg->or_port_len;
		return (ALLIUM_ERR_NOBUFS);
	}
	memcpy(addr, &cfg->or_port, cfg->or_port_len);
	*addr_len = cfg->or_port_len;

	return (0);
}


int
allium_ptcfg_ext_port(const allium_ptcfg *cfg, struct sockaddr *addr, socklen_t
    *addr_len)
{
	if ((NULL == cfg) || (NULL == addr_len))
		return (ALLIUM_ERR_INVAL);

	if (!cfg->is_server)
		return (ALLIUM_ERR_PTCFG_NOT_SERVER);

	if ((NULL == addr) || (*addr_len < cfg->ext_port_len)) {
		*addr_len = cfg->ext_port_len;
		return (ALLIUM_ERR_NOBUFS);
	}
	if (!cfg->has_ext_port) {
		*addr_len = 0;
		return (ALLIUM_ERR_PTCFG_NO_ADDRESS);
	}
	memcpy(addr, &cfg->ext_port, cfg->ext_port_len);
	*addr_len = cfg->ext_port_len;

	return (0);
}


int
allium_ptcfg_bind_addr(const allium_ptcfg *cfg, const char *method, struct
    sockaddr *addr, socklen_t *addr_len)
{
	struct allium_ptcfg_method_s *m;

	if ((NULL == cfg) || (NULL == method) || (NULL == addr_len))
		return (ALLIUM_ERR_INVAL);

	if (!cfg->is_server)
		return (ALLIUM_ERR_PTCFG_NOT_SERVER);

	m = get_method(cfg, method);
	if (NULL == m)
		return (ALLIUM_ERR_PTCFG_INVALID_METHOD);

	if ((NULL == addr) || (*addr_len < m->bind_addr_len)) {
		*addr_len = m->bind_addr_len;
		return (ALLIUM_ERR_NOBUFS);
	}
	if (!m->has_bind_addr) {
		*addr_len = 0;
		return (ALLIUM_ERR_PTCFG_NO_ADDRESS);
	}
	memcpy(addr, &m->bind_addr, m->bind_addr_len);
	*addr_len = m->bind_addr_len;

	return (0);
}


int
allium_ptcfg_method_requested(const allium_ptcfg *cfg, const char *method)
{
	if ((NULL == cfg) || (NULL == method))
		return (ALLIUM_ERR_INVAL);

	return (NULL != get_method(cfg, method));
}


int
allium_ptcfg_cmethod_report(const allium_ptcfg *cfg, const char *method,
    int socks_ver, const struct sockaddr *addr,
    socklen_t addr_len, const char *args, const char *opt_args)
{
	char host[INET6_ADDRSTRLEN];
	char service[NI_MAXSERV];

	if ((NULL == cfg) || (NULL == method) || (NULL == addr))
		return (ALLIUM_ERR_INVAL);

	if (cfg->is_server)
		return (ALLIUM_ERR_PTCFG_NOT_CLIENT);

	if (0 == allium_ptcfg_method_requested(cfg, method))
		return (ALLIUM_ERR_PTCFG_INVALID_METHOD);

	if ((AF_INET != addr->sa_family) && (AF_INET6 != addr->sa_family))
		return (ALLIUM_ERR_INVAL);

	if (getnameinfo(addr, addr_len, host, sizeof(host), service,
		    sizeof(service), NI_NUMERICHOST |
		    NI_NUMERICSERV))
		return (ALLIUM_ERR_INVAL);

	fprintf(stdout, "CMETHOD %s socks%d ", method, socks_ver);
	if (AF_INET == addr->sa_family)
		fprintf(stdout, "%s:%s", host, service);
	else if (AF_INET6 == addr->sa_family)
		fprintf(stdout, "[%s]:%s", host, service);
	if (NULL != args)
		fprintf(stdout, " ARGS=%s", args);
	if (NULL != opt_args)
		fprintf(stdout, " OPTARGS=%s", opt_args);
	fprintf(stdout, "\n");

	return (0);
}


int
allium_ptcfg_smethod_report(const allium_ptcfg *cfg, const char *method,
    const struct sockaddr *addr, socklen_t addr_len, const char
    *args, const char *declare, int ext_port)
{
	struct allium_ptcfg_method_s *m;
	char host[INET6_ADDRSTRLEN];
	char service[NI_MAXSERV];

	if ((NULL == cfg) || (NULL == method) || (NULL == addr))
		return (ALLIUM_ERR_INVAL);

	if (!cfg->is_server)
		return (ALLIUM_ERR_PTCFG_NOT_SERVER);

	if ((AF_INET != addr->sa_family) && (AF_INET6 != addr->sa_family))
		return (ALLIUM_ERR_INVAL);

	m = get_method(cfg, method);
	if (NULL == m)
		return (ALLIUM_ERR_PTCFG_INVALID_METHOD);

	if (getnameinfo(addr, addr_len, host, sizeof(host), service,
		    sizeof(service), NI_NUMERICHOST |
		    NI_NUMERICSERV))
		return (ALLIUM_ERR_INVAL);

	fprintf(stdout, "SMETHOD %s ", method);
	if (AF_INET == addr->sa_family)
		fprintf(stdout, "%s:%s", host, service);
	else if (AF_INET6 == addr->sa_family)
		fprintf(stdout, "[%s]:%s", host, service);
	if ((m->bind_addr_len != addr_len) || memcmp(&m->bind_addr, addr,
		    addr_len))
		fprintf(stdout, " FORWARD:1");
	if (NULL != args)
		fprintf(stdout, " ARGS:%s", args);
	if (NULL != declare)
		fprintf(stdout, " DECLARE:%s", declare);
	if (ext_port)
		fprintf(stdout, " USE-EXTENDED-PORT:1");
	fprintf(stdout, "\n");

	return (0);
}


int
allium_ptcfg_method_error(const allium_ptcfg *cfg, const char *method, const
    char *msg)
{
	if ((NULL == cfg) || (NULL == method) || (NULL == msg))
		return (ALLIUM_ERR_INVAL);

	if (0 == allium_ptcfg_method_requested(cfg, method))
		return (ALLIUM_ERR_PTCFG_INVALID_METHOD);

	if (cfg->is_server)
		fprintf(stdout, "SMETHOD-ERROR %s %s\n", method, msg);
	else
		fprintf(stdout, "CMETHOD-ERROR %s %s\n", method, msg);

	return (0);
}


int
allium_ptcfg_methods_done(const allium_ptcfg *cfg)
{
	if (NULL == cfg)
		return (ALLIUM_ERR_INVAL);

	if (cfg->is_server)
		fprintf(stdout, "SMETHODS DONE\n");
	else
		fprintf(stdout, "CMETHODS DONE\n");

	return (0);
}


static struct allium_ptcfg_method_s *
get_method(const allium_ptcfg *cfg, const char *method)
{
	struct tagbstring all_trans = bsStatic(PTCFG_ALL_TRANSPORTS);
	int i;

	if ((NULL == cfg) || (NULL == method))
		return (NULL);

	for (i = 0; i < cfg->nr_methods; i++) {
		if (!cfg->is_server &&
		    (0 == bstrcmp(cfg->methods[i].name, &all_trans)))
			return (&cfg->methods[i]);

		if (1 == biseqcstr(cfg->methods[i].name, method))
			return (&cfg->methods[i]);
	}

	return (NULL);
}


static int
parse_addr(const char *addr, struct sockaddr *out, socklen_t *out_len)
{
	struct addrinfo hints, *info;
	bstring str, host, service;
	int i, ret = -1;

	if ((NULL == addr) || (NULL == out) || (NULL == out_len))
		return (-1);

	str = bfromcstr(addr);
	if (NULL == str)
		return (-1);

	i = bstrrchr(str, ':');
	if ((BSTR_ERR == i) || (i <= 0)) {
		bdestroy(str);
		return (-1);
	}
	if (('[' == bchar(str, 0)) && (']' == bchar(str, i - 1)))
		host = bmidstr(str, 1, i - 2);  /* IPv6 */
	else
		host = bmidstr(str, 0, i);      /* IPv4 */
	if (NULL == host) {
		bdestroy(str);
		return (-1);
	}
	service = bmidstr(str, i + 1, blength(str) - i);
	if (NULL == service) {
		bdestroy(str);
		bdestroy(host);
		return (-1);
	}
	if ((0 != blength(host)) && (0 != blength(service))) {
		/* Use getaddrinfo to parse the strings */
		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		if (0 == getaddrinfo(bdata(host), bdata(service), &hints,
			    &info)) {
			if (*out_len >= info->ai_addrlen) {
				memcpy(out, info->ai_addr, info->ai_addrlen);
				*out_len = info->ai_addrlen;
				ret = 0;
			}
			freeaddrinfo(info);
		}
	}

	bdestroy(str);
	bdestroy(host);
	bdestroy(service);

	return (ret);
}
