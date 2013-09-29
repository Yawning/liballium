/*
 * ptcfg_example.c: liballium Pluggable Transport Configuration example
 * Written by Yawning Angel <yawning at schwanenlied dot me>
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>             /* For memset () */

#include "allium.h"


#define METHOD_NAME		"trebuchet"
#define METHOD_ARGS		"rocks,height"
#define METHOD_OPT_ARGS		"tensile-strength"
#define METHOD_SERVER_OPT	"rocks"


static int ptserver_init(allium_ptcfg *cfg);
static int ptclient_init(allium_ptcfg *cfg);


static char *pt_state_dir;


int
main(int argc, char *argv[])
{
	allium_ptcfg *cfg;
	size_t len;
	int rval;

	/* Initialize the Pluggable Transport config */
	cfg = allium_ptcfg_init();
	if (!cfg)
		exit(-1);

	/* Ensure that Tor wants us to provide a supported method */
	rval = allium_ptcfg_method_requested(cfg, METHOD_NAME);
	if (1 != rval) {
out_error:
		allium_ptcfg_methods_done(cfg);
		allium_ptcfg_free(cfg);
		exit(-1);
	}

	/*
	 * Find out where Tor wants us to store temporary files
	 *
	 * Note:
	 *  * You can also just pass in a static buffer, if you wish to do so,
	 *    instead of querying the length, but you need to check the return
	 *    value.
	 */
	allium_ptcfg_state_dir(cfg, NULL, &len);
	pt_state_dir = malloc(len);
	if (!pt_state_dir) {
		allium_ptcfg_method_error(cfg, METHOD_NAME, "OOM");
		goto out_error;
	}
	allium_ptcfg_state_dir(cfg, pt_state_dir, &len);

	/*
	 * Until you invoke allium_ptcfg_methods_done(), you MUST not
	 * use stdout, because that will confuse Tor, which is still
	 * expecting pluggable transport config protocol chatter.
	 */
	/* fprintf(stderr, "State Directory: [%s]\n", pt_state_dir); */

	if (allium_ptcfg_is_server(cfg)) {
		/* Tor expects us to be a server (Running on the bridge) */
		rval = ptserver_init(cfg);
		allium_ptcfg_methods_done(cfg); /* Done with the config! */
		if (!rval) {
			/* Enter the server main loop here! */
		}
	} else {
		/* Client related config options */
		rval = ptclient_init(cfg);
		allium_ptcfg_methods_done(cfg); /* Done with the config! */
		if (!rval) {
			/* Enter the client main loop here! */
		}
	}

	free(pt_state_dir);

	/* Free the memory allocated to the config */
	allium_ptcfg_free(cfg);

	return (0);
}


static int
ptserver_init(allium_ptcfg *cfg)
{
	/* Server related config options */
	char auth_cookie[1024];
	char rocks[16];
	size_t cookie_len;
	size_t rocks_len;
	struct sockaddr_in orport;
	struct sockaddr_in extport;
	struct sockaddr_storage bindaddr;
	socklen_t addr_len;
	int has_extport = 1;
	int has_auth_cookie = 1;
	int has_bindaddr = 1;
	int rval;

	/* Tor's ORPort */
	addr_len = sizeof(orport);
	rval = allium_ptcfg_or_port(cfg, (struct sockaddr *)&orport, &addr_len);
	if (rval) {
		allium_ptcfg_method_error(cfg, METHOD_NAME, "Failed to query ORPort");
		return (-1);
	}

	/* Tor's Extended Server Port */
	addr_len = sizeof(extport);
	rval = allium_ptcfg_ext_port(cfg, (struct sockaddr *)&extport, &addr_len);
	if (ALLIUM_ERR_PTCFG_NO_ADDRESS == rval) {
		/* The Extended Server Port is optional */
		has_extport = 0;
	} else if (rval) {
		allium_ptcfg_method_error(cfg, METHOD_NAME, "Failed to query ExtPort");
		return (-1);
	}

	/*
	 * Tor's Extended Server Port Auth Cookie
	 *
	 * Note:
	 *  * Only need to check this if there is a Ext. Port
	 */
	if (has_extport) {
		/*
		 * Might as well show off the other way to get strings out of
		 * the ptcfg module (You can use the same pattern with the
		 * state_dir.)
		 */
		cookie_len = sizeof(auth_cookie);
		rval = allium_ptcfg_auth_cookie_file(cfg, auth_cookie,
		    &cookie_len);
		if (ALLIUM_ERR_PTCFG_NO_AUTH_COOKIE == rval)
			has_auth_cookie = 0;
		else if (rval) {
			/* rval is 99% ALLIUM_ERR_NOBUFS, but too lazy */
			allium_ptcfg_method_error(cfg, METHOD_NAME, "Failed to query cookie");
			return (-1);
		}
	}

	/* The address that Tor expects us to listen on */
	addr_len = sizeof(bindaddr);
	rval = allium_ptcfg_bind_addr(cfg, METHOD_NAME,
	    (struct sockaddr *)&bindaddr, &addr_len);
	if (ALLIUM_ERR_PTCFG_NO_ADDRESS == rval) {
		/*
		 * Tor does not care what address we listen on.
		 *
		 * XXX: Not sure if this ever happens.
		 */
		has_bindaddr = 0;
	} else if (rval) {
		/* Something went horribly wrong */
		allium_ptcfg_method_error(cfg, METHOD_NAME, "Failed to query BindAddr");
		return (-1);
	}

	/* Query the Server Transport Options if you have any */
	rocks_len = sizeof(rocks);
	rval = allium_ptcfg_server_xport_option(cfg, METHOD_NAME,
			METHOD_SERVER_OPT, rocks, &rocks_len);
	if (ALLIUM_ERR_PTCFG_NO_XPORT_OPTION == rval) {
		/* Option not set */
	} else if (rval) {
		/* rval is 99% ALLIUM_ERR_NOBUFS, but too lazy */
		allium_ptcfg_method_error(cfg, METHOD_NAME, "Failed to query transport option");
		return (-1);
	} else {
		/* Parse the option */
	}

	/*
	 * Do your setup here!
	 */

	(void)has_extport;      /* Shut GCC up, you should use these though! */
	(void)has_auth_cookie;
	(void)has_bindaddr;

#if 0
	if (/* Something goes horribly wrong */) {
		allium_ptcfg_method_error(cfg, METHOD_NAME, "Trebuchet on fire");
		return (-1);
	}
#endif

	/*
	 * Inform Tor about the address we are accepting connections on,
	 * and whatever arguments that should be listed in the extra-info
	 * document.
	 */

	allium_ptcfg_smethod_report(cfg, METHOD_NAME, (struct sockaddr *)
	    &bindaddr, addr_len, "rocks=5,height=100m");

	return (0);
}


static int
ptclient_init(allium_ptcfg *cfg)
{
	struct sockaddr_in socks_addr;

	/*
	 * Do your setup here!
	 */

	/* Just provide a fake address for the sake of example */
	memset(&socks_addr, 0, sizeof(socks_addr));
	socks_addr.sin_family = AF_INET;
	socks_addr.sin_port = htons(1234);
	inet_aton("127.0.0.1", &socks_addr.sin_addr);

#if 0
	if (/* Something goes horribly wrong */) {
		allium_ptcfg_method_error(cfg, METHOD_NAME, "Trebuchet on fire");
		return (-1);
	}
#endif

	/*
	 * Inform Tor about the SOCKS version we support, the address that we
	 * are accepting SOCKS connections on, and what arguments mandetory
	 * or optional that should be passed via the SOCKS auth sidechannel
	 * on a per-connection basis.
	 */

	allium_ptcfg_cmethod_report(cfg, METHOD_NAME, 5, (struct sockaddr *)&socks_addr,
	    sizeof(socks_addr), METHOD_ARGS, METHOD_OPT_ARGS);

	return (0);
}
