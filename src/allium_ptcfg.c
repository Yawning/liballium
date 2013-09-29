/*
 * allium_ptcfg.c: Tor Pluggable Transport Configuration
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

#include <assert.h>

#include "allium.h"
#include "bstrlib.h"


#define PTCFG_STATE_LOCATION		"TOR_PT_STATE_LOCATION"
#define PTCFG_MANAGED_TRANSPORT_VER	"TOR_PT_MANAGED_TRANSPORT_VER"

#define PTCFG_CLIENT_TRANSPORTS		"TOR_PT_CLIENT_TRANSPORTS"

#define PTCFG_EXTENDED_SERVER_PORT	"TOR_PT_EXTENDED_SERVER_PORT"
#define PTCFG_ORPORT			"TOR_PT_ORPORT"
#define PTCFG_SERVER_BIND_ADDR		"TOR_PT_SERVER_BINDADDR"
#define PTCFG_SERVER_TRANSPORTS		"TOR_PT_SERVER_TRANSPORTS"
#define PTCFG_AUTH_COOKIE_FILE		"TOR_PT_AUTH_COOKIE_FILE"
#define PTCFG_SERVER_TRANSPORT_OPTIONS	"TOR_PT_SERVER_TRANSPORT_OPTIONS"

#define PTCFG_MANAGED_TRANSPORT_V1	"1"
#define PTCFG_ALL_TRANSPORTS		"*"


/*
 * blength(s) causes gcc to warn when a tagbstring is passed in, because it
 * checks that s is valid, and it always is.  Since I only use tagbstrings
 * that are on the stack, add a dinky macro for the length.
 */
#define btlength(s)    (s.slen)


struct allium_ptcfg_xport_opt_s {
	bstring					key;
	bstring					value;
	struct allium_ptcfg_xport_opt_s *	next;
};

struct allium_ptcfg_method_s {
	bstring					name;

	int					has_bind_addr;
	struct sockaddr_storage			bind_addr;
	socklen_t				bind_addr_len;
	struct allium_ptcfg_xport_opt_s *	xport_opts;
};

struct allium_ptcfg_s {
	bstring				version;
	bstring				state_location;
	bstring				auth_cookie_file;

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


static int parse_protocol_version(allium_ptcfg *cfg, const char *version);
static int parse_state_directory(allium_ptcfg *cfg, const char *path);
static int parse_transports(allium_ptcfg *cfg, const char *transports);
static int parse_or_port(allium_ptcfg *cfg, const char *or_port);
static int parse_ext_port(allium_ptcfg *cfg, const char *ext_port);
static int parse_bind_address(allium_ptcfg *cfg, const char *addrs);
static int parse_auth_cookie(allium_ptcfg *cfg, const char *path);
static int parse_server_xport_options(allium_ptcfg *cfg, const char *options);
static int parse_server_xport_option(allium_ptcfg *cfg, const bstring arg_str);

static struct allium_ptcfg_method_s *get_method(const allium_ptcfg *cfg, const
    char *method);
static struct allium_ptcfg_xport_opt_s *get_xport_opt(struct
    allium_ptcfg_method_s *method, const bstring key);
static int parse_addr(const char *addr, struct sockaddr *out, socklen_t
    *out_len);
static void unescape_opt_value(bstring str);
static int bdestroy_safe(bstring str);
static int bstrListDestroy_safe(struct bstrList *sl);


allium_ptcfg *
allium_ptcfg_init(void)
{
	allium_ptcfg *cfg;
	int rval;

	cfg = calloc(1, sizeof(*cfg));
	if (NULL == cfg) {
		fprintf(stdout, "ENV-ERROR Failed to allocate cfg\n");
		return (NULL);
	}

	/* Parse the protocol version and validate it */
	rval = parse_protocol_version(cfg, getenv(PTCFG_MANAGED_TRANSPORT_VER));
	if (rval) {
		allium_ptcfg_free(cfg);
		return (NULL);
	}

	/* State directory */
	rval = parse_state_directory(cfg, getenv(PTCFG_STATE_LOCATION));
	if (rval) {
		allium_ptcfg_free(cfg);
		return (NULL);
	}

	/* Transport list */
	rval = parse_transports(cfg, getenv(PTCFG_SERVER_TRANSPORTS));
	if (rval) {
		allium_ptcfg_free(cfg);
		return (NULL);
	}

	if (!cfg->is_server)
		goto done;

	/*
	 * Handle the server specific options
	 */

	/* ORPort */
	rval = parse_or_port(cfg, getenv(PTCFG_ORPORT));
	if (rval) {
		allium_ptcfg_free(cfg);
		return (NULL);
	}

	/* Extended Server Port */
	rval = parse_ext_port(cfg, getenv(PTCFG_EXTENDED_SERVER_PORT));
	if (rval) {
		allium_ptcfg_free(cfg);
		return (NULL);
	}

	/* Bind addresses */
	rval = parse_bind_address(cfg, getenv(PTCFG_SERVER_BIND_ADDR));
	if (rval) {
		allium_ptcfg_free(cfg);
		return (NULL);
	}

	/* Ext port auth cookie */
	rval = parse_auth_cookie(cfg, getenv(PTCFG_AUTH_COOKIE_FILE));
	if (rval) {
		allium_ptcfg_free(cfg);
		return (NULL);
	}

	/* Server transport options */
	rval = parse_server_xport_options(cfg, getenv(PTCFG_SERVER_TRANSPORT_OPTIONS));
	if (rval) {
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
	struct allium_ptcfg_xport_opt_s *opt, *tmp;
	int i;

	if (NULL == cfg)
		return;

	bdestroy(cfg->version);
	bdestroy(cfg->state_location);
	bdestroy(cfg->auth_cookie_file);
	if (NULL != cfg->methods) {
		for (i = 0; i < cfg->nr_methods; i++) {
			bdestroy(cfg->methods[i].name);
			opt = cfg->methods[i].xport_opts;
			while (NULL != opt) {
				tmp = opt->next;
				bdestroy(opt->key);
				bdestroy_safe(opt->value);
				opt = tmp;
			}
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
allium_ptcfg_auth_cookie_file(const allium_ptcfg *cfg, char *path, size_t
    *path_len)
{
	size_t len;

	if ((NULL == cfg) || (NULL == path_len))
		return (ALLIUM_ERR_INVAL);

	if (!cfg->is_server)
		return (ALLIUM_ERR_PTCFG_NOT_SERVER);

	if (NULL == cfg->auth_cookie_file)
		return (ALLIUM_ERR_PTCFG_NO_AUTH_COOKIE);

	len = blength(cfg->auth_cookie_file) + 1;
	if ((NULL == path) || (*path_len < len)) {
		*path_len = len;
		return (ALLIUM_ERR_NOBUFS);
	}
	memcpy(path, cfg->auth_cookie_file->data, len);
	path[len - 1] = '\0';
	*path_len = len;

	return (0);
}


int
allium_ptcfg_server_xport_option(const allium_ptcfg *cfg, const char *method,
    const char *key, char *value, size_t *value_len)
{
	struct allium_ptcfg_method_s *m;
	struct allium_ptcfg_xport_opt_s *opt;
	struct tagbstring key_str;
	size_t len;

	if ((NULL == cfg) || (NULL == method) || (NULL == key) || (NULL ==
		    value_len))
		return (ALLIUM_ERR_INVAL);

	if (!cfg->is_server)
		return (ALLIUM_ERR_PTCFG_NOT_SERVER);

	m = get_method(cfg, method);
	if (NULL == m)
		return (ALLIUM_ERR_PTCFG_INVALID_METHOD);

	btfromcstr(key_str, key);
	opt = get_xport_opt(m, &key_str);
	if ((NULL == opt) || (0 == blength(opt->value)))
		return (ALLIUM_ERR_PTCFG_NO_XPORT_OPTION);

	len = blength(opt->value) + 1;
	if ((NULL == value) || (*value_len < len)) {
		*value_len = len;
		return (ALLIUM_ERR_NOBUFS);
	}
	memcpy(value, opt->value->data, len);
	value[len - 1] = '\0';
	*value_len = len;

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
    const struct sockaddr *addr, socklen_t addr_len, const char *args)
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
	if (NULL != args)
		fprintf(stdout, " ARGS:%s", args);
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


static int
parse_protocol_version(allium_ptcfg *cfg, const char *version)
{
	const struct tagbstring supported_ver = bsStatic(PTCFG_MANAGED_TRANSPORT_V1);
	struct tagbstring str;
	struct bstrList *l;
	int i;

	assert(NULL != cfg);

	if (NULL == version) {
		fprintf(stdout, "ENV-ERROR No Managed Transport Version\n");
		return (-1);
	}
	btfromcstr(str, version);
	if (0 == btlength(str)) {
		fprintf(stdout, "ENV-ERROR Empty Transport Version\n");
		return (-1);
	}
	l = bsplit(&str, ',');
	if (NULL == l) {
		fprintf(stdout, "ENV-ERROR OOM parsing Version\n");
		return (-1);
	}
	for (i = 0; i < l->qty; i++) {
		if (0 == bstrcmp(l->entry[i], &supported_ver)) {
			cfg->version = bstrcpy(l->entry[i]);
			break;
		}
	}
	bstrListDestroy(l);
	if (NULL == cfg->version) {
		fprintf(stdout, "VERSION-ERROR no-version\n");
		return (-1);
	}

	return (0);
}


static int
parse_state_directory(allium_ptcfg *cfg, const char *path)
{
	assert(NULL != cfg);

	if (NULL == path) {
		fprintf(stdout, "ENV-ERROR No State Directory\n");
		return (-1);
	}

	cfg->state_location = bfromcstr(path);
	if (NULL == cfg->state_location) {
		fprintf(stdout, "ENV-ERROR OOM parsing State Location\n");
		return (-1);
	}

	return (0);
}


static int
parse_transports(allium_ptcfg *cfg, const char *transports)
{
	struct bstrList *l;
	struct tagbstring str;
	int i;

	assert(NULL != cfg);

	cfg->is_server = (NULL != transports);
	if (!cfg->is_server)
		transports = getenv(PTCFG_CLIENT_TRANSPORTS);
	if (NULL == transports) {
		fprintf(stdout, "ENV-ERROR No Transports\n");
		return (-1);
	}
	btfromcstr(str, transports);
	if (0 == btlength(str)) {
		fprintf(stdout, "ENV-ERROR Empty Transport List\n");
		return (-1);
	}
	l = bsplit(&str, ',');
	if (NULL == l) {
		fprintf(stdout, "ENV-ERROR OOM parsing Transports\n");
		return (-1);
	}
	cfg->methods = calloc(l->qty, sizeof(*cfg->methods));
	if (NULL == cfg->methods) {
		bstrListDestroy(l);
		fprintf(stdout, "ENV-ERROR OOM parsing Transports\n");
		return (-1);
	}
	for (i = 0; i < l->qty; i++) {
		if (0 == blength(l->entry[i])) {
			fprintf(stdout, "ENV-ERROR Invalid Transport\n");
			bstrListDestroy(l);
			return (-1);
		}
		cfg->methods[i].name = bstrcpy(l->entry[i]);
		if (NULL == cfg->methods[i].name) {
			fprintf(stdout, "ENV-ERROR OOM parsing Transports\n");
			bstrListDestroy(l);
			return (-1);
		}
		cfg->nr_methods++;
	}

	return (0);
}


static int
parse_or_port(allium_ptcfg *cfg, const char *or_port)
{
	assert(NULL != cfg);

	if (NULL == or_port) {
		fprintf(stdout, "ENV-ERROR No ORPort\n");
		return (-1);
	}
	cfg->or_port_len = sizeof(cfg->or_port);
	if (parse_addr(or_port, (struct sockaddr *)&cfg->or_port,
		    &cfg->or_port_len)) {
		fprintf(stdout, "ENV-ERROR Malformed ORPort\n");
		return (-1);
	}

	return (0);
}


static int
parse_ext_port(allium_ptcfg *cfg, const char *ext_port)
{
	assert(NULL != cfg);

#if 0

	/*
	 * The spec says that this will always exist, but according to
	 * src/or/transports.c, the intention moving forward is for it to be
	 * optional, so be tollerant.
	 */
	if (NULL == ext_port) {
		fprintf(stdout, "ENV-ERROR No Extended Server Port\n");
		return (-1);
	}
#else
	if ((NULL == ext_port) || (0 == strlen(ext_port))) {
		return (0);
	}
#endif
	cfg->ext_port_len = sizeof(cfg->ext_port);
	if (parse_addr(ext_port, (struct sockaddr *)&cfg->ext_port,
		    &cfg->ext_port_len)) {
		fprintf(stdout, "ENV-ERROR Malformed Extended Server Port\n");
		return (-1);
	}
	cfg->has_ext_port = 1;

	return (0);
}


static int
parse_bind_address(allium_ptcfg *cfg, const char *addrs)
{
	struct bstrList *l;
	struct tagbstring str;
	int i, j;

	assert(NULL != cfg);

	if (NULL == addrs) {
		fprintf(stdout, "ENV-ERROR No Bind Addresses\n");
		return (-1);
	}
	btfromcstr(str, addrs);
	if (0 == btlength(str)) {
		fprintf(stdout, "ENV-ERROR Empty Bind Address\n");
		return (-1);
	}
	l = bsplit(&str, ',');
	if (NULL == l) {
		fprintf(stdout, "ENV-ERROR OOM parsing Bind Addresses\n");
		return (-1);
	}
	if (l->qty != cfg->nr_methods) {
		fprintf(stdout, "ENV-ERROR Malformed Bind Addresses\n");
		bstrListDestroy(l);
		return (-1);
	}
	for (i = 0; i < l->qty; i++) {
		/*
		 * Per pt-spec.txt, the order is identical to the transport
		 * list.  I have no idea what is supposed to happen when
		 * the transport list is wildcarded, so this routine will
		 * currently fail gracefully.
		 */
		j = bstrrchr(l->entry[i], '-');
		if ((j != blength(cfg->methods[i].name)) || bstrncmp(l->entry[i],
			    cfg->methods[i].name, j - 1)) {
			fprintf(stdout, "ENV-ERROR Unexpected method in Bind Address\n");
			bstrListDestroy(l);
			return (-1);
		}
		cfg->methods[i].bind_addr_len = sizeof(cfg->methods[i].bind_addr);
		if (parse_addr(bdataofs(l->entry[i], j + 1),
			    (struct sockaddr *)&cfg->methods[i].bind_addr,
			    &cfg->methods[i].bind_addr_len)) {
			fprintf(stdout, "ENV-ERROR Invalid address in Bind Address (%s)\n",
			    bdata(l->entry[i]));
			bstrListDestroy(l);
			return (-1);
		}
		cfg->methods[i].has_bind_addr = 1;
	}
	bstrListDestroy(l);

	return (0);
}


static int
parse_auth_cookie(allium_ptcfg *cfg, const char *path)
{
	assert(NULL != cfg);

	if (NULL == path)
		return (0);

	cfg->auth_cookie_file = bfromcstr(path);
	if (NULL == cfg->auth_cookie_file) {
		fprintf(stdout, "ENV-ERROR OOM parsing Auth Cookie File\n");
		return (-1);
	}

	return (0);
}


static int
parse_server_xport_options(allium_ptcfg *cfg, const char *options)
{
	struct bstrList *l;
	struct tagbstring str;
	int i;

	assert(NULL != cfg);

	if ((NULL == options) || (0 == strlen(options)))
		return (0);

	btfromcstr(str, options);
	l = bsplit(&str, ';');
	if (NULL == l) {
		fprintf(stdout, "ENV-ERROR OOM parsing Transport Options\n");
		return (-1);
	}
	for (i = 0; i < l->qty; /* See next_i */) {
		bstring arg_str;
		int next_i = i + 1;

		if (0 == blength(l->entry[i])) {
out_malformed:
			fprintf(stdout, "ENV-ERROR Malformed Transport Option\n");
			bstrListDestroy_safe(l);
			return (-1);
		}

		/*
		 * Allocate arg_str such that realloc will never be called by
		 * bconcat
		 */
		arg_str = bfromcstralloc(btlength(str), bdata(l->entry[i]));
		if (NULL == arg_str) {
out_oom:
			bstrListDestroy_safe(l);
			fprintf(stdout, "ENV-ERROR OOM parsing Transport Options\n");
			return (-1);
		}
		while ('\\' == bchar(arg_str, blength(arg_str) - 1) && next_i < l->qty) {
			*bdataofs(arg_str, blength(arg_str) - 1) = ';';
			if (NULL == l->entry[next_i]) {
				next_i++;
				break;
			}
			if (BSTR_ERR == bconcat(arg_str, l->entry[next_i])) {
				bdestroy_safe(arg_str);
				goto out_oom;
			}
			next_i++;
		}
		if (parse_server_xport_option(cfg, arg_str)) {
			/*
			 * XXX: This also will claim that the option is
			 * malformed if a malloc fails in the subroutine.
			 * However if that happens, you have bigger problems.
			 */
			bdestroy_safe(arg_str);
			goto out_malformed;
		}
		i = next_i;
		bdestroy_safe(arg_str);
	}
	bstrListDestroy_safe(l);

	return (0);
}


static int
parse_server_xport_option(allium_ptcfg *cfg, const bstring arg_str)
{
	struct allium_ptcfg_method_s *m;
	struct allium_ptcfg_xport_opt_s *opt;
	bstring transport;
	bstring key;
	bstring value;
	int i, j;

	assert(cfg);
	assert(arg_str);

	if (0 == blength(arg_str))
		return (-1);

	/*
	 * Figure out what transport this argument is for.  We don't need to
	 * unescape method names as they conform to "[a-zA-Z_][a-zA-Z0-9_]*"
	 */
	i = bstrchr(arg_str, ':');
	if (BSTR_ERR == i)
		return (-1);

	transport = bmidstr(arg_str, 0, i);
	if (NULL == transport)
		return (-1);

	m = get_method(cfg, bdata(transport));
	bdestroy(transport);    /* Done with the transport at this point */
	if (NULL == m)
		return (-1);

	/*
	 * Figure out what key the transport is expecting the value for.
	 *
	 * XXX: If people want to use the escaped characters in their keys they
	 * get what they deserve (Note this as a gotcha and fix it when people
	 * cry about it).
	 */
	j = bstrchrp(arg_str, '=', i);
	if (BSTR_ERR == j)
		return (-1);

	key = bmidstr(arg_str, i + 1, j - i - 1);
	if (NULL == key)
		return (-1);

	opt = get_xport_opt(m, key);
	if ((NULL != opt) || (0 == blength(key))) {
		/* We don't support redefining existing key/value pairs */
		bdestroy(key);
		return (-1);
	}

	/* Parse the value, unescaping as needed */
	value = bmidstr(arg_str, j + 1, blength(arg_str) - j - 1);
	if (NULL == value) {
		bdestroy(key);
		return (-1);
	}
	unescape_opt_value(value);

	/* Stash it away so people can get to it */
	opt = calloc(1, sizeof(*opt));
	if (NULL == opt) {
		bdestroy(key);
		bdestroy_safe(value);
		return (-1);
	}
	opt->key = key;
	opt->value = value;
	opt->next = m->xport_opts;
	m->xport_opts = opt;

	return (0);
}


static struct allium_ptcfg_method_s *
get_method(const allium_ptcfg *cfg, const char *method)
{
	struct tagbstring all_trans = bsStatic(PTCFG_ALL_TRANSPORTS);
	int i;

	/* All the routines that call this check these */
	assert(NULL != cfg);
	assert(NULL != method);

	for (i = 0; i < cfg->nr_methods; i++) {
		if (!cfg->is_server &&
		    (0 == bstrcmp(cfg->methods[i].name, &all_trans)))
			return (&cfg->methods[i]);

		if (1 == biseqcstr(cfg->methods[i].name, method))
			return (&cfg->methods[i]);
	}

	return (NULL);
}


static struct allium_ptcfg_xport_opt_s *get_xport_opt(struct
    allium_ptcfg_method_s *method, const bstring key)
{
	struct allium_ptcfg_xport_opt_s *opt;

	assert(NULL != method);
	assert(NULL != key);

	opt = method->xport_opts;
	while (NULL != opt) {
		if (1 == biseq(key, opt->key))
			return (opt);

		opt = opt->next;
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


static void
unescape_opt_value(bstring str)
{
	const struct tagbstring esc_comma = bsStatic("\\,");
	const struct tagbstring comma = bsStatic(",");
	const struct tagbstring esc_slash = bsStatic("\\\\");
	const struct tagbstring slash = bsStatic("\\");
	const struct tagbstring esc_colon = bsStatic("\\:");
	const struct tagbstring colon = bsStatic(":");
	const struct tagbstring esc_equals = bsStatic("\\=");
	const struct tagbstring equals = bsStatic("=");

	assert(str);

	/* Unescape: \, \\ \: \; \= */
	bfindreplace(str, &esc_comma, &comma, 0);
	bfindreplace(str, &esc_slash, &slash, 0);
	bfindreplace(str, &esc_colon, &colon, 0);
	bfindreplace(str, &esc_equals, &equals, 0);
}


static int
bdestroy_safe(bstring str)
{
	if ((NULL != str) && (0 < str->mlen) && (NULL != str->data))
		allium_scrub(str->data, str->mlen);

	return (bdestroy(str));
}


static int
bstrListDestroy_safe(struct bstrList *sl)
{
	int i;

	if (NULL != sl)
		for (i = 0; i < sl->qty; i++) {
			if (NULL == sl->entry[i]->data)
				continue;
			allium_scrub(sl->entry[i]->data, sl->entry[i]->mlen);
		}


	return (bstrListDestroy(sl));
}
