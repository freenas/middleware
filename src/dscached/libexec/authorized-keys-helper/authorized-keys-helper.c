/*
 * Copyright 2017 iXsystems, Inc.
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <errno.h>
#include <jansson.h>
#include <dispatcher.h>

static int
call_dispatcher(const char *method, json_t *args, json_t **result)
{
	connection_t *conn;
	int err, rpc_err;

	conn = dispatcher_open("unix:///var/run/dscached.sock");
	if (conn == NULL)
		return (-1);

	err = dispatcher_call_sync(conn, method, args, result);

	if (err == RPC_CALL_ERROR) {
		/* Handle the ENOENT case gracefully */
		rpc_err = json_integer_value(json_object_get(*result, "code"));
		if (rpc_err == ENOENT) {
			*result = json_null();
			dispatcher_close(conn);
			return (0);
		}

		fprintf(stderr, "RPC %s error: <%d> %s\n", method, rpc_err,
			json_string_value(json_object_get(*result, "message")));
	}

	if (err != RPC_CALL_DONE) {
		dispatcher_close(conn);
		return (-1);
	}

	json_incref(*result);
	dispatcher_close(conn);
	return (0);
}

int
main(int argc, char *argv[])
{
	json_t *args, *result;
	const char *str;
	int err;

	if (argc < 2) {
		fprintf(stderr, "Not enough arguments provided\n");
		return (1);
	}

	args = json_pack("[s]", argv[1]);
	err = call_dispatcher("dscached.account.get_ssh_keys", args, &result);
	if (err != 0) {
		fprintf(stderr, "Failed to call dscached\n");
		return (1);
	}

	str = json_string_value(result);
	json_decref(result);
	if (str != NULL)
		printf("%s\n", str);

	return (0);
}
