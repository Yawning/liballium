/*
 * ptcfg_test.c: Tor Pluggable Transport Configuration tests
 * Copyright (c) 2013 Yawning Angel <yawning at schwanenlied dot me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
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

#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

#include <assert.h>

#include "allium.h"
#include "sput.h"

static void ptcfg_test_client(void);
static void ptcfg_test_server(void);

static void ptcfg_init_noargs_test(void);
static void ptcfg_init_client_test(void);
static void ptcfg_init_server_test(void);

static void ptcfg_state_dir_test(void);
static void ptcfg_is_server_test(void);
static void ptcfg_method_requested_test(void);
static void ptcfg_or_port_test(void);
static void ptcfg_ext_port_test(void);
static void ptcfg_bind_addr_test(void);
static void ptcfg_auth_cookie_file_test(void);
static void ptcfg_server_xport_option_test(void);

static void ptcfg_cmethod_report_test(void);
static void ptcfg_smethod_report_test(void);
static void ptcfg_method_error_test(void);
static void ptcfg_methods_done_test(void);

int
main(int argc, char *argv[])
{
	sput_start_testing();

	sput_enter_suite("allium_ptcfg_init(): No basic arguments");
	sput_run_test(ptcfg_init_noargs_test);

	sput_enter_suite("allium_ptcfg_init(): Client transports");
	sput_run_test(ptcfg_init_client_test);

	sput_enter_suite("allium_ptcfg_init(): Server transports");
	sput_run_test(ptcfg_init_server_test);

	sput_enter_suite("allium_ptcfg_state_dir(): State directory");
	sput_run_test(ptcfg_state_dir_test);

	sput_enter_suite("allium_ptcfg_is_server(): Is server");
	sput_run_test(ptcfg_is_server_test);

	sput_enter_suite("allium_ptcfg_method_requested(): Method requested");
	sput_run_test(ptcfg_method_requested_test);

	sput_enter_suite("allium_ptcfg_or_port(): OR Port");
	sput_run_test(ptcfg_or_port_test);

	sput_enter_suite("allium_ptcfg_ext_port(): Ext Port");
	sput_run_test(ptcfg_ext_port_test);

	sput_enter_suite("allium_ptcfg_bind_addr(): Bind Addr");
	sput_run_test(ptcfg_bind_addr_test);

	sput_enter_suite("allium_ptcfg_auth_cookie_file(): Auth Cookie");
	sput_run_test(ptcfg_auth_cookie_file_test);

	sput_enter_suite("allium_ptcfg_server_xport_option(): Server Transport Options");
	sput_run_test(ptcfg_server_xport_option_test);

	sput_enter_suite("allium_ptcfg_cmethod_report(): Cmethod");
	sput_run_test(ptcfg_cmethod_report_test);

	sput_enter_suite("allium_ptcfg_smethod_report(): Smethod");
	sput_run_test(ptcfg_smethod_report_test);

	sput_enter_suite("allium_ptcfg_method_error(): Method Error");
	sput_run_test(ptcfg_method_error_test);

	sput_enter_suite("allium_ptcfg_methods_done(): Methods Done");
	sput_run_test(ptcfg_methods_done_test);

	sput_finish_testing();

	return (sput_get_return_value());
}


static void
ptcfg_test_client(void)
{
	clearenv();
	putenv("TOR_PT_MANAGED_TRANSPORT_VER=1");
	putenv("TOR_PT_STATE_LOCATION=/tmp/my_sexy_pt");
	putenv("TOR_PT_CLIENT_TRANSPORTS=foo,bar,baz");
}


static void
ptcfg_test_server(void)
{
	clearenv();
	putenv("TOR_PT_MANAGED_TRANSPORT_VER=1");
	putenv("TOR_PT_STATE_LOCATION=/tmp/my_sexy_pt");
	putenv("TOR_PT_SERVER_TRANSPORTS=foo,bar,baz");
	putenv("TOR_PT_ORPORT=127.0.0.1:9001");
	putenv("TOR_PT_EXTENDED_SERVER_PORT=127.0.0.1:9002");
	putenv("TOR_PT_SERVER_BINDADDR=foo-127.0.0.1:69,bar-[::1]:23,baz-127.0.0.1:22");
	putenv("TOR_PT_AUTH_COOKIE_FILE=/tmp/chcolate-chip");
}


static void
ptcfg_init_noargs_test(void)
{
	allium_ptcfg *cfg;

	clearenv();

	/* No env vars at all */
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL == cfg, "cfg == NULL, No args");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Empty managed transport version */
	putenv("TOR_PT_MANAGED_TRANSPORT_VER=");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL == cfg, "cfg == NULL, Empty version");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Invalid managed transport version */
	putenv("TOR_PT_MANAGED_TRANSPORT_VER=666");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL == cfg, "cfg == NULL, Invalid version");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Just have a managed transport version */
	putenv("TOR_PT_MANAGED_TRANSPORT_VER=1");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL == cfg, "cfg == NULL, Only version");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Empty PT state variable */
	putenv("TOR_PT_STATE_LOCATION=");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL == cfg, "cfg == NULL, State set but empty");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Neither client nor server */
	putenv("TOR_PT_STATE_LOCATION=/tmp/my_sexy_pt");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL == cfg, "cfg == NULL, Not client/server");
	if (cfg)
		allium_ptcfg_free(cfg);
}


static void
ptcfg_init_client_test(void)
{
	allium_ptcfg *cfg;

	clearenv();

	/* Setup basic valid enviornment variables */
	putenv("TOR_PT_MANAGED_TRANSPORT_VER=1");
	putenv("TOR_PT_STATE_LOCATION=/tmp/my_sexy_pt");

	/* Empty client transport */
	putenv("TOR_PT_CLIENT_TRANSPORTS=");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL == cfg, "cfg == NULL, Empty client transports");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* One empty client transport, mixed */
	putenv("TOR_PT_CLIENT_TRANSPORTS=foo,,baz");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL == cfg, "cfg == NULL, 0 length transport");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* One client transport */
	putenv("TOR_PT_CLIENT_TRANSPORTS=foo");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL != cfg, "cfg != NULL, 1 valid transport");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Multiple client transports */
	putenv("TOR_PT_CLIENT_TRANSPORTS=foo,bar,baz");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL != cfg, "cfg != NULL, 3 valid transports");
	if (cfg)
		allium_ptcfg_free(cfg);
}


static void
ptcfg_init_server_test(void)
{
	allium_ptcfg *cfg;

	clearenv();

	/* Setup basic valid enviornment variables */
	ptcfg_test_server();

	/* Empty server transport */
	putenv("TOR_PT_SERVER_TRANSPORTS=");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL == cfg, "cfg == NULL, Empty server transports");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* One empty server transport, mixed */
	putenv("TOR_PT_SERVER_TRANSPORTS=foo,,baz");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL == cfg, "cfg == NULL, 0 length transport");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Valid server transport */
	putenv("TOR_PT_SERVER_TRANSPORTS=foo");
	putenv("TOR_PT_SERVER_BINDADDR=foo-127.0.0.1:69");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL != cfg, "cfg != NULL, Valid server transport");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Multiple server transports */
	putenv("TOR_PT_SERVER_TRANSPORTS=foo,bar,baz");
	putenv("TOR_PT_SERVER_BINDADDR=foo-127.0.0.1:69,bar-[::1]:23,baz-127.0.0.1:22");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL != cfg, "cfg != NULL, 3 valid transports");
	if (cfg)
		allium_ptcfg_free(cfg);

	/*
	 * OR Port tests
	 */

	/* Set but empty orport */
	putenv("TOR_PT_ORPORT=");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL == cfg, "cfg == NULL, Empty OR Port");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Blatantly invalid orport */
	putenv("TOR_PT_ORPORT=All the cool kids set addresses here");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL == cfg, "cfg == NULL, Invalid OR Port");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* IPv4 address, without a port */
	putenv("TOR_PT_ORPORT=127.0.0.1");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL == cfg,
	    "cfg == NULL, IPv4 addr, no port OR Port");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Valid IPv4 address */
	putenv("TOR_PT_ORPORT=127.0.0.1:9001");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL != cfg, "cfg != NULL, Valid IPv4 OR Port");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Invalid IPv6 address */
	putenv("TOR_PT_ORPORT=[This isn't an address]:9001");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL == cfg, "cfg == NULL, Invalid IPv6 OR Port");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Valid IPv6 address */
	putenv("TOR_PT_ORPORT=[::1]:9001");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL != cfg, "cfg != NULL, Valid IPv6 OR Port");
	if (cfg)
		allium_ptcfg_free(cfg);

	/*
	 * Ext Port tests - Since the orport code exercises the address parser
	 * the lazy test writer can just make sure that valid strings are
	 * parsed.
	 */

	/* Empty Ext Port (We are more forgiving than pt-spec.txt) */
	putenv("TOR_PT_EXTENDED_SERVER PORT=");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL != cfg, "cfg != NULL, Empty Ext Port");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Valid IPv4 address */
	putenv("TOR_PT_EXTENDED_SERVER_PORT=127.0.0.1:9002");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL != cfg, "cfg != NULL, Valid IPv4 Ext Port");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Valid IPv6 address */
	putenv("TOR_PT_EXTENDED_SERVER_PORT=[::1]:9002");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL != cfg, "cfg != NULL, Valid IPv6 Ext Port");
	if (cfg)
		allium_ptcfg_free(cfg);

	/*
	 * Bind Addr tests
	 */

	/* Empty Bind Addr */
	putenv("TOR_PT_SERVER_BINDADDR=");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL == cfg, "cfg == NULL, Empty bind addr");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Malformed Bind Addr */
	putenv("TOR_PT_SERVER_BINDADDR=I'll be a real address one day");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL == cfg, "cfg == NULL, Invalid bind addr");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Missing address */
	putenv("TOR_PT_SERVER_BINDADDR=foo-");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL == cfg, "cfg == NULL, Missing address");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Valid address */
	putenv("TOR_PT_SERVER_TRANSPORTS=foo");
	putenv("TOR_PT_SERVER_BINDADDR=foo-127.0.0.1:69");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL != cfg, "cfg != NULL, 1 Valid IPv4 address");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* 3 Valid addresses */
	putenv("TOR_PT_SERVER_TRANSPORTS=foo,bar,baz");
	putenv("TOR_PT_SERVER_BINDADDR=foo-127.0.0.1:69,bar-[::1]:23,baz-127.0.0.1:22");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL != cfg, "cfg != NULL, 3 Valid address");
	if (cfg)
		allium_ptcfg_free(cfg);

	/*
	 * Auth cookie tests
	 */

	/* Empty auth cookie */
	putenv("TOR_PT_AUTH_COOKIE_FILE=");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL != cfg, "cfg != NULL, Empty cookie");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Valid auth cookie */
	putenv("TOR_PT_AUTH_COOKIE_FILE=/tmp/chcolate-chip");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL != cfg, "cfg != NULL, Valid cookie");
	if (cfg)
		allium_ptcfg_free(cfg);

	/*
	 * Server transport options tests
	 */

	/* Empty server transport options */
	putenv("TOR_PT_SERVER_TRANSPORT_OPTIONS=");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL != cfg, "cfg != NULL, Empty transport options");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Blatantly broken server transport options */
	putenv("TOR_PT_SERVER_TRANSPORT_OPTIONS=blorch");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL == cfg, "cfg == NULL, Invalid transport options");
	if (cfg)
		allium_ptcfg_free(cfg);

	/* Valid server transport option */
	putenv("TOR_PT_SERVER_TRANSPORT_OPTIONS=foo:arg=123;bar:zzz=abc\\;;baz:bbb=231231");
	cfg = allium_ptcfg_init();
	sput_fail_unless(NULL != cfg, "cfg != NULL, Valid transport options");
	if (cfg)
		allium_ptcfg_free(cfg);
}


static void
ptcfg_state_dir_test(void)
{
	static const char dir[] = "/tmp/my_sexy_pt";
	char buf[1024];
	size_t len;
	allium_ptcfg *cfg;
	int rval;

	ptcfg_test_client();
	setenv("TOR_PT_STATE_LOCATION", dir, 1);
	cfg = allium_ptcfg_init();
	assert(cfg);

	/* Invalid arguments */
	len = sizeof(buf);
	rval = allium_ptcfg_state_dir(NULL, buf, &len);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, Invalid config");
	rval = allium_ptcfg_state_dir(cfg, buf, NULL);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, Invalid length");

	/* Buffer NULL/Too small */
	len = sizeof(buf);
	rval = allium_ptcfg_state_dir(cfg, NULL, &len);
	sput_fail_unless(ALLIUM_ERR_NOBUFS == rval,
	    "rval == ALLIUM_ERR_NOBUFS, NULL buffer");
	sput_fail_unless(strlen(dir) + 1 == len,
	    "len == strlen(dir) + 1, NULL buffer");
	len = 3; /* Something too short */
	rval = allium_ptcfg_state_dir(cfg, buf, &len);
	sput_fail_unless(ALLIUM_ERR_NOBUFS == rval,
	    "rval == ALLIUM_ERR_NOBUFS, Length too small");
	sput_fail_unless(len == strlen(dir) + 1,
	    "len == strlen(dir) + 1, Length too small");

	/* Valid arguments */
	buf[0] = '\0';
	len = sizeof(buf);
	rval = allium_ptcfg_state_dir(cfg, buf, &len);
	sput_fail_unless(0 == rval, "rval == 0, Valid args");
	sput_fail_unless(0 == strcmp(buf, dir), "Correct state dir");
	sput_fail_unless(len == strlen(dir) + 1, "Correct length");

	allium_ptcfg_free(cfg);
}


static void
ptcfg_is_server_test(void)
{
	allium_ptcfg *cfg;
	int rval;

	clearenv();

	/* Invalid arguments */
	rval = allium_ptcfg_is_server(NULL);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL config");

	/* Client */
	ptcfg_test_client();
	cfg = allium_ptcfg_init();
	assert(cfg);

	rval = allium_ptcfg_is_server(cfg);
	sput_fail_unless(0 == rval, "rval == 0, Client");
	allium_ptcfg_free(cfg);

	/* Server */
	ptcfg_test_server();
	cfg = allium_ptcfg_init();
	assert(cfg);
	rval = allium_ptcfg_is_server(cfg);
	sput_fail_unless(1 == rval, "rval == 1, Server");
	allium_ptcfg_free(cfg);
}


static void
ptcfg_method_requested_test(void)
{
	allium_ptcfg *cfg;
	int rval;

	ptcfg_test_client();
	cfg = allium_ptcfg_init();
	assert(cfg);

	/* Invalid arguments */
	rval = allium_ptcfg_method_requested(NULL, "foo");
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL config");
	rval = allium_ptcfg_method_requested(cfg, NULL);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL method");

	/* Missing method */
	rval = allium_ptcfg_method_requested(cfg, "missing");
	sput_fail_unless(0 == rval, "rval == 0, Unrequested method");

	/* Specific method */
	rval = allium_ptcfg_method_requested(cfg, "bar");
	sput_fail_unless(1 == rval, "rval == 1, Specific method");

	allium_ptcfg_free(cfg);

	/* All methods */
	putenv("TOR_PT_CLIENT_TRANSPORTS=*");
	cfg = allium_ptcfg_init();
	assert(cfg);

	rval = allium_ptcfg_method_requested(cfg, "qux");
	sput_fail_unless(1 == rval, "rval == 1, All methods");
	allium_ptcfg_free(cfg);
}


static void
ptcfg_or_port_test(void)
{
	allium_ptcfg *cfg;
	int rval;
	struct sockaddr_in v4addr, cmp_v4addr;
	struct sockaddr_in6 v6addr, cmp_v6addr;
	socklen_t len;

	ptcfg_test_server();
	cfg = allium_ptcfg_init();
	assert(cfg);

	memset(&cmp_v4addr, 0, sizeof(cmp_v4addr));
	cmp_v4addr.sin_family = AF_INET;
	cmp_v4addr.sin_port = htons(9001);
	inet_pton(AF_INET, "127.0.0.1", &cmp_v4addr.sin_addr);

	memset(&cmp_v6addr, 0, sizeof(cmp_v6addr));
	cmp_v6addr.sin6_family = AF_INET6;
	cmp_v6addr.sin6_port = htons(9001);
	inet_pton(AF_INET6, "::1", &cmp_v6addr.sin6_addr);

	/* Invalid arguments */
	len = sizeof(v4addr);
	rval = allium_ptcfg_or_port(NULL, (struct sockaddr *)&v4addr, &len);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL config");
	rval = allium_ptcfg_or_port(cfg, (struct sockaddr *)&v4addr, NULL);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL addr_len");

	/* Addr NULL/Too small */
	rval = allium_ptcfg_or_port(cfg, NULL, &len);
	sput_fail_unless(ALLIUM_ERR_NOBUFS == rval,
	    "rval == ALLIUM_ERR_NOBUFS, NULL addr");
	sput_fail_unless(sizeof(v4addr) == len,
	    "len == sizeof(v4addr), NULL buffer");
	len = 3; /* Something too short */
	rval = allium_ptcfg_or_port(cfg, (struct sockaddr *)&v4addr, &len);
	sput_fail_unless(ALLIUM_ERR_NOBUFS == rval,
	    "rval == ALLIUM_ERR_NOBUFS, Length too small");
	sput_fail_unless(sizeof(v4addr) == len,
	    "len == sizeof(v4addr), NULL buffer");

	/* Validate IPv4 address */
	len = sizeof(v4addr);
	rval = allium_ptcfg_or_port(cfg, (struct sockaddr *)&v4addr, &len);
	sput_fail_unless(0 == rval, "rval == 0, Valid IPv4 address");
	sput_fail_unless(0 == memcmp(&v4addr, &cmp_v4addr, len),
	    "v4addr matches");

	allium_ptcfg_free(cfg);

	/* Validate IPv6 address */
	putenv("TOR_PT_ORPORT=[::1]:9001");
	cfg = allium_ptcfg_init();
	assert(cfg);

	len = sizeof(v6addr);
	rval = allium_ptcfg_or_port(cfg, (struct sockaddr *)&v6addr, &len);
	sput_fail_unless(0 == rval, "rval == 0, Valid IPv6 address");
	sput_fail_unless(0 == memcmp(&v6addr, &cmp_v6addr, len),
	    "v6addr matches");

	allium_ptcfg_free(cfg);
}


static void
ptcfg_ext_port_test(void)
{
	allium_ptcfg *cfg;
	int rval;
	struct sockaddr_in v4addr, cmp_v4addr;
	struct sockaddr_in6 v6addr, cmp_v6addr;
	socklen_t len;

	ptcfg_test_server();
	cfg = allium_ptcfg_init();
	assert(cfg);

	memset(&cmp_v4addr, 0, sizeof(cmp_v4addr));
	cmp_v4addr.sin_family = AF_INET;
	cmp_v4addr.sin_port = htons(9002);
	inet_pton(AF_INET, "127.0.0.1", &cmp_v4addr.sin_addr);

	memset(&cmp_v6addr, 0, sizeof(cmp_v6addr));
	cmp_v6addr.sin6_family = AF_INET6;
	cmp_v6addr.sin6_port = htons(9002);
	inet_pton(AF_INET6, "::1", &cmp_v6addr.sin6_addr);

	/* Invalid arguments */
	len = sizeof(v4addr);
	rval = allium_ptcfg_ext_port(NULL, (struct sockaddr *)&v4addr, &len);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL config");
	rval = allium_ptcfg_ext_port(cfg, (struct sockaddr *)&v4addr, NULL);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL addr_len");

	/* Addr NULL/Too small */
	rval = allium_ptcfg_ext_port(cfg, NULL, &len);
	sput_fail_unless(ALLIUM_ERR_NOBUFS == rval,
	    "rval == ALLIUM_ERR_NOBUFS, NULL addr");
	sput_fail_unless(sizeof(v4addr) == len,
	    "len == sizeof(v4addr), NULL buffer");
	len = 3; /* Something too short */
	rval = allium_ptcfg_ext_port(cfg, (struct sockaddr *)&v4addr, &len);
	sput_fail_unless(ALLIUM_ERR_NOBUFS == rval,
	    "rval == ALLIUM_ERR_NOBUFS, Length too small");
	sput_fail_unless(sizeof(v4addr) == len,
	    "len == sizeof(v4addr), NULL buffer");

	/* Validate IPv4 address */
	len = sizeof(v4addr);
	rval = allium_ptcfg_ext_port(cfg, (struct sockaddr *)&v4addr, &len);
	sput_fail_unless(0 == rval, "rval == 0, Valid IPv4 address");
	sput_fail_unless(0 == memcmp(&v4addr, &cmp_v4addr, len),
	    "v4addr matches");

	allium_ptcfg_free(cfg);

	/* Validate IPv6 address */
	putenv("TOR_PT_EXTENDED_SERVER_PORT=[::1]:9002");
	cfg = allium_ptcfg_init();
	assert(cfg);

	len = sizeof(v6addr);
	rval = allium_ptcfg_ext_port(cfg, (struct sockaddr *)&v6addr, &len);
	sput_fail_unless(0 == rval, "rval == 0, Valid IPv6 address");
	sput_fail_unless(0 == memcmp(&v6addr, &cmp_v6addr, len),
	    "v6addr matches");

	allium_ptcfg_free(cfg);

	/* No Ext Port */
	unsetenv("TOR_PT_EXTENDED_SERVER_PORT");
	cfg = allium_ptcfg_init();
	assert(cfg);

	rval = allium_ptcfg_ext_port(cfg, (struct sockaddr *)&v6addr, &len);
	sput_fail_unless(ALLIUM_ERR_PTCFG_NO_ADDRESS == rval,
	    "rval == ALLIUM_ERR_PTCFG_NO_ADDRESS, No Ext Port");
	sput_fail_unless(0 == len, "len == 0");

	allium_ptcfg_free(cfg);
}


static void
ptcfg_bind_addr_test(void)
{
	allium_ptcfg *cfg;
	int rval;
	struct sockaddr_in v4addr, cmp_v4addr;
	struct sockaddr_in6 v6addr, cmp_v6addr;
	socklen_t len;

	ptcfg_test_server();

	memset(&cmp_v4addr, 0, sizeof(cmp_v4addr));
	cmp_v4addr.sin_family = AF_INET;
	cmp_v4addr.sin_port = htons(69);
	inet_pton(AF_INET, "127.0.0.1", &cmp_v4addr.sin_addr);

	memset(&cmp_v6addr, 0, sizeof(cmp_v6addr));
	cmp_v6addr.sin6_family = AF_INET6;
	cmp_v6addr.sin6_port = htons(23);
	inet_pton(AF_INET6, "::1", &cmp_v6addr.sin6_addr);
	cfg = allium_ptcfg_init();
	assert(cfg);

	/* Invalid arguments */
	len = sizeof(v4addr);
	rval = allium_ptcfg_bind_addr(NULL, "foo", (struct sockaddr *)&v4addr, &len);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL config");
	rval = allium_ptcfg_bind_addr(cfg, NULL, (struct sockaddr *)&v4addr, &len);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL addr");
	rval = allium_ptcfg_bind_addr(cfg, "foo", (struct sockaddr *)&v4addr, NULL);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL addr_len");
	rval = allium_ptcfg_bind_addr(cfg, "qux", (struct sockaddr *)&v4addr, &len);
	sput_fail_unless(ALLIUM_ERR_PTCFG_INVALID_METHOD == rval,
	    "rval == ALLIUM_ERR_PTCFG_INVALID_METHOD, Invalid method");

	/* Addr NULL/Too small */
	rval = allium_ptcfg_bind_addr(cfg, "foo", NULL, &len);
	sput_fail_unless(ALLIUM_ERR_NOBUFS == rval,
	    "rval == ALLIUM_ERR_NOBUFS, NULL addr");
	sput_fail_unless(sizeof(v4addr) == len,
	    "len == sizeof(v4addr), NULL buffer");
	len = 3; /* Something too short */
	rval = allium_ptcfg_bind_addr(cfg, "foo", (struct sockaddr *)&v4addr, &len);
	sput_fail_unless(ALLIUM_ERR_NOBUFS == rval,
	    "rval == ALLIUM_ERR_NOBUFS, Length too small");
	sput_fail_unless(sizeof(v4addr) == len,
	    "len == sizeof(v4addr), NULL buffer");

	/* Validate IPv4 address */
	len = sizeof(v4addr);
	rval = allium_ptcfg_bind_addr(cfg, "foo", (struct sockaddr *)&v4addr, &len);
	sput_fail_unless(0 == rval, "rval == 0, Valid IPv4 address");
	sput_fail_unless(0 == memcmp(&v4addr, &cmp_v4addr, len),
	    "v4addr matches");

	/* Validate IPv6 address */
	len = sizeof(v6addr);
	rval = allium_ptcfg_bind_addr(cfg, "bar", (struct sockaddr *)&v6addr, &len);
	sput_fail_unless(0 == rval, "rval == 0, Valid IPv6 address");
	sput_fail_unless(0 == memcmp(&v6addr, &cmp_v6addr, len),
	    "v6addr matches");

	allium_ptcfg_free(cfg);
}


static void
ptcfg_auth_cookie_file_test(void)
{
	static const char cookie[] = "/tmp/chocolate-chip";
	char buf[1024];
	size_t len;
	allium_ptcfg *cfg;
	int rval;

	ptcfg_test_server();
	setenv("TOR_PT_AUTH_COOKIE_FILE", cookie, 1);
	cfg = allium_ptcfg_init();
	assert(cfg);

	/* Invalid arguments */
	len = sizeof(buf);
	rval = allium_ptcfg_auth_cookie_file(NULL, buf, &len);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, Invalid config");
	rval = allium_ptcfg_auth_cookie_file(cfg, buf, NULL);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, Invalid length");

	/* Buffer NULL/Too small */
	len = sizeof(buf);
	rval = allium_ptcfg_auth_cookie_file(cfg, NULL, &len);
	sput_fail_unless(ALLIUM_ERR_NOBUFS == rval,
	    "rval == ALLIUM_ERR_NOBUFS, NULL buffer");
	sput_fail_unless(strlen(cookie) + 1 == len,
	    "len == strlen(cookie) + 1, NULL buffer");
	len = 3; /* Something too short */
	rval = allium_ptcfg_auth_cookie_file(cfg, buf, &len);
	sput_fail_unless(ALLIUM_ERR_NOBUFS == rval,
	    "rval == ALLIUM_ERR_NOBUFS, Length too small");
	sput_fail_unless(len == strlen(cookie) + 1,
	    "len == strlen(cookie) + 1, Length too small");

	/* Valid arguments */
	buf[0] = '\0';
	len = sizeof(buf);
	rval = allium_ptcfg_auth_cookie_file(cfg, buf, &len);
	sput_fail_unless(0 == rval, "rval == 0, Valid args");
	sput_fail_unless(0 == strcmp(buf, cookie), "Correct cookie");
	sput_fail_unless(len == strlen(cookie) + 1, "Correct length");

	allium_ptcfg_free(cfg);

	/* No auth cookie */
	unsetenv("TOR_PT_AUTH_COOKIE_FILE");
	cfg = allium_ptcfg_init();
	assert(cfg);

	rval = allium_ptcfg_auth_cookie_file(cfg, buf, &len);
	sput_fail_unless(ALLIUM_ERR_PTCFG_NO_AUTH_COOKIE == rval,
	    "rval == ALLIUM_ERR_PTCFG_NO_AUTH_COOKIE, No cookie");

	allium_ptcfg_free(cfg);
}


static void
ptcfg_server_xport_option_test(void)
{
	allium_ptcfg *cfg;
	char buf[1024];
	size_t len;
	int rval;

	ptcfg_test_server();
	putenv("TOR_PT_SERVER_TRANSPORT_OPTIONS=foo:arg=123;bar:zzz=abc\\;;foo:bbb=zzz\\,\\\\\\;\\:\\=");
	cfg = allium_ptcfg_init();

	/* Invalid arguments */
	len = sizeof(buf);
	rval = allium_ptcfg_server_xport_option(NULL, "foo", "arg", buf, &len);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, Invalid config");
	rval = allium_ptcfg_server_xport_option(cfg, NULL, "arg", buf, &len);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, Invalid method");
	rval = allium_ptcfg_server_xport_option(cfg, "foo", NULL, buf, &len);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, Invalid arg");
	rval = allium_ptcfg_server_xport_option(cfg, "foo", "arg", buf, NULL);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, Invalid length");
	assert(cfg);

	/* Buffer NULL/Too small */
	len = sizeof(buf);
	rval = allium_ptcfg_server_xport_option(cfg, "foo", "arg", NULL, &len);
	sput_fail_unless(ALLIUM_ERR_NOBUFS == rval,
	    "rval == ALLIUM_ERR_NOBUFS, NULL buffer");
	sput_fail_unless(3 + 1 == len, "len == 3 + 1, NULL buffer");
	len = 1; /* Something too short */
	rval = allium_ptcfg_server_xport_option(cfg, "foo", "arg", buf, &len);
	sput_fail_unless(ALLIUM_ERR_NOBUFS == rval,
	    "rval == ALLIUM_ERR_NOBUFS, Length too small");
	sput_fail_unless(3+ 1 == len, "len == 3 + 1, Length too small");

	/* Valid arguments */
	len = sizeof(buf);
	rval = allium_ptcfg_server_xport_option(cfg, "foo", "arg", buf, &len);
	sput_fail_unless(0 == rval, "rval == 0, Valid args");
	sput_fail_unless(0 == strcmp(buf, "123"), "Correct value");
	sput_fail_unless(len == strlen("123") + 1, "Correct length");
	len = sizeof(buf);
	rval = allium_ptcfg_server_xport_option(cfg, "foo", "bbb", buf, &len);
	sput_fail_unless(0 == rval, "rval == 0, Valid args 2");
	sput_fail_unless(0 == strcmp(buf, "zzz,\\;:="), "Correct value");
	sput_fail_unless(len == strlen("zzz,\\;:=") + 1, "Correct length");

	/* Missing argument */
	len = sizeof(buf);
	rval = allium_ptcfg_server_xport_option(cfg, "foo", "no_such_arg", buf, &len);
	sput_fail_unless(ALLIUM_ERR_PTCFG_NO_XPORT_OPTION == rval, "Missing arg");

	allium_ptcfg_free(cfg);
}


static void
ptcfg_cmethod_report_test(void)
{
	allium_ptcfg *cfg;
	struct sockaddr_in v4addr;
	struct sockaddr_in6 v6addr;
	int rval;

	ptcfg_test_client();
	cfg = allium_ptcfg_init();
	assert(cfg);

	memset(&v4addr, 0, sizeof(v4addr));
	v4addr.sin_family = AF_INET;
	v4addr.sin_port = htons(69);
	inet_pton(AF_INET, "127.0.0.1", &v4addr.sin_addr);

	memset(&v6addr, 0, sizeof(v6addr));
	v6addr.sin6_family = AF_INET6;
	v6addr.sin6_port = htons(23);
	inet_pton(AF_INET6, "::1", &v6addr.sin6_addr);

	/* Invalid arguments */
	rval = allium_ptcfg_cmethod_report(NULL, "foo", 5,
	    (struct sockaddr *)&v4addr, sizeof(v4addr), NULL,
	    NULL);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL config");
	rval = allium_ptcfg_cmethod_report(cfg, NULL, 5,
	    (struct sockaddr *)&v4addr, sizeof(v4addr), NULL,
	    NULL);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL method");
	rval = allium_ptcfg_cmethod_report(cfg, "foo", 5, NULL,
	    sizeof(v4addr), NULL, NULL);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL addr");
	v4addr.sin_family = AF_APPLETALK; /* Temporarily change this */
	rval = allium_ptcfg_cmethod_report(cfg, "foo", 5,
	    (struct sockaddr *)&v4addr, sizeof(v4addr), "myargs",
	    "myoptargs");
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, Invalid addr");
	v4addr.sin_family = AF_INET;

	/* Unspecified method */
	rval = allium_ptcfg_cmethod_report(cfg, "qux", 5,
	    (struct sockaddr *)&v4addr, sizeof(v4addr), "myargs",
	    "myoptargs");
	sput_fail_unless(ALLIUM_ERR_PTCFG_INVALID_METHOD == rval,
	    "rval == ALLIUM_ERR_PTCFG_INVALID_METHOD, Invalid method");

	/* Valid args */
	rval = allium_ptcfg_cmethod_report(cfg, "foo", 5,
	    (struct sockaddr *)&v4addr, sizeof(v4addr), "myargs",
	    "myoptargs");
	sput_fail_unless(0 == rval, "rval == 0, Valid IPv4 address");
	rval = allium_ptcfg_cmethod_report(cfg, "foo", 5,
	    (struct sockaddr *)&v6addr, sizeof(v6addr), "myargs",
	    "myoptargs");
	sput_fail_unless(0 == rval, "rval == 0, Valid IPv6 address");

	allium_ptcfg_free(cfg);

	ptcfg_test_server();
	cfg = allium_ptcfg_init();
	assert(cfg);

	/* Server config */
	rval = allium_ptcfg_cmethod_report(cfg, "foo", 5,
	    (struct sockaddr *)&v4addr, sizeof(v4addr), "myargs",
	    "myoptargs");
	sput_fail_unless(ALLIUM_ERR_PTCFG_NOT_CLIENT == rval,
	    "rval == ALLIUM_ERR_PTCFG_NOT_CLIENT, Server config");

	allium_ptcfg_free(cfg);
}


static void
ptcfg_smethod_report_test(void)
{
	allium_ptcfg *cfg;
	struct sockaddr_in v4addr;
	struct sockaddr_in6 v6addr;
	int rval;

	ptcfg_test_server();
	cfg = allium_ptcfg_init();
	assert(cfg);

	memset(&v4addr, 0, sizeof(v4addr));
	v4addr.sin_family = AF_INET;
	v4addr.sin_port = htons(69);
	inet_pton(AF_INET, "127.0.0.1", &v4addr.sin_addr);

	memset(&v6addr, 0, sizeof(v6addr));
	v6addr.sin6_family = AF_INET6;
	v6addr.sin6_port = htons(23);
	inet_pton(AF_INET6, "::1", &v6addr.sin6_addr);

	/* Invalid arguments */
	rval = allium_ptcfg_smethod_report(NULL, "foo",
	    (struct sockaddr *)&v4addr, sizeof(v4addr), NULL);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL config");
	rval = allium_ptcfg_smethod_report(cfg, NULL, (struct sockaddr *)
	    &v4addr, sizeof(v4addr), NULL);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL method");
	rval = allium_ptcfg_smethod_report(cfg, "foo", NULL, sizeof(v4addr),
	    NULL);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL addr");
	v4addr.sin_family = AF_APPLETALK; /* Temporarily change this */
	rval = allium_ptcfg_smethod_report(cfg, "foo", (struct sockaddr *)
	    &v4addr, sizeof(v4addr), NULL);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, Invalid addr");
	v4addr.sin_family = AF_INET;

	/* Unspecified method */
	rval = allium_ptcfg_smethod_report(cfg, "qux", (struct sockaddr *)
	    &v4addr, sizeof(v4addr), NULL);
	sput_fail_unless(ALLIUM_ERR_PTCFG_INVALID_METHOD == rval,
	    "rval == ALLIUM_ERR_PTCFG_INVALID_METHOD, Invalid method");

	/* Valid args */
	rval = allium_ptcfg_smethod_report(cfg, "foo", (struct sockaddr *)
	    &v4addr, sizeof(v4addr), "myargs");
	sput_fail_unless(0 == rval, "rval == 0, Valid IPv4 address");
	rval = allium_ptcfg_smethod_report(cfg, "bar", (struct sockaddr *)
	    &v6addr, sizeof(v6addr), "myargs");
	sput_fail_unless(0 == rval, "rval == 0, Valid IPv6 address");
	rval = allium_ptcfg_smethod_report(cfg, "baz", (struct sockaddr *)
	    &v6addr, sizeof(v6addr), "myargs");
	sput_fail_unless(0 == rval, "rval == 0, Different address");

	allium_ptcfg_free(cfg);

	ptcfg_test_client();
	cfg = allium_ptcfg_init();
	assert(cfg);

	/* Client config */
	rval = allium_ptcfg_smethod_report(cfg, "foo", (struct sockaddr *)
	    &v4addr, sizeof(v4addr), "myargs");
	sput_fail_unless(ALLIUM_ERR_PTCFG_NOT_SERVER == rval,
	    "rval == ALLIUM_ERR_PTCFG_NOT_SERVER, Client config");

	allium_ptcfg_free(cfg);
}


static void
ptcfg_method_error_test(void)
{
	allium_ptcfg *cfg;
	int rval;

	ptcfg_test_client();
	cfg = allium_ptcfg_init();
	assert(cfg);

	/* Invalid arguments */
	rval = allium_ptcfg_method_error(NULL, "foo", "Something went wrong");
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL config");
	rval = allium_ptcfg_method_error(cfg, NULL, "Something went wrong");
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL method");
	rval = allium_ptcfg_method_error(cfg, "foo", NULL);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL msg");

	/* Unspecified method */
	rval = allium_ptcfg_method_error(cfg, "qux", "Something went wrong");
	sput_fail_unless(ALLIUM_ERR_PTCFG_INVALID_METHOD == rval,
	    "rval == ALLIUM_ERR_PTCFG_INVALID_METHOD, Invalid method");

	/* Valid input */
	rval = allium_ptcfg_method_error(cfg, "foo", "Something went wrong");
	sput_fail_unless(0 == rval, "rval == 0, Client");

	allium_ptcfg_free(cfg);

	ptcfg_test_server();
	cfg = allium_ptcfg_init();
	assert(cfg);

	rval = allium_ptcfg_method_error(cfg, "foo", "Something went wrong");
	sput_fail_unless(0 == rval, "rval == 0, Server");

	allium_ptcfg_free(cfg);
}


static void
ptcfg_methods_done_test(void)
{
	allium_ptcfg *cfg;
	int rval;

	ptcfg_test_client();
	cfg = allium_ptcfg_init();
	assert(cfg);

	/* Invalid arguments */
	rval = allium_ptcfg_methods_done(NULL);
	sput_fail_unless(ALLIUM_ERR_INVAL == rval,
	    "rval == ALLIUM_ERR_INVAL, NULL config");

	/* Client done */
	rval = allium_ptcfg_methods_done(cfg);
	sput_fail_unless(0 == rval, "rval == 0, Client config");

	allium_ptcfg_free(cfg);

	ptcfg_test_server();
	cfg = allium_ptcfg_init();
	assert(cfg);

	/* Server done */
	rval = allium_ptcfg_methods_done(cfg);
	sput_fail_unless(0 == rval, "rval == 0, Server config");

	allium_ptcfg_free(cfg);
}
