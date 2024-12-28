/* Inadyn dnsExit plugin
 *
 * Copyright (C) 2003-2004  Narcis Ilisei <inarcis2002@hotpop.com>
 * Copyright (C) 2006       Steve Horbachuk
 * Copyright (C) 2010-2021  Joachim Wiberg <troglobit@gmail.com>
 * Copyright (C) 2024       Chris Fraire <cfraire@me.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, visit the Free Software Foundation
 * website at http://www.gnu.org/licenses/gpl-2.0.html or write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */

#include "plugin.h"
#include "json.h"

/*
 * For API information, see
 * https://dnsexit.com/apps/dynamic-dns-update-clients/
 */
#define DNSEXIT_UPDATE_IP_HTTP_REQUEST					\
	"GET %s?"							\
	"apikey=%s&"							\
	"host=%s "							\
	"HTTP/1.0\r\n"							\
	"Host: %s\r\n"							\
	"User-Agent: %s\r\n\r\n"

static int request  (ddns_t       *ctx,   ddns_info_t *info, ddns_alias_t *alias);
static int response (http_trans_t *trans, ddns_info_t *info, ddns_alias_t *alias);

static ddns_system_t plugin = {
	.name         = "default@dnsexit.com",

	.request      = (req_fn_t)request,
	.response     = (rsp_fn_t)response,

	.nousername   = 1,	/* Provider does not require username */

	.checkip_name = "ip3.dnsexit.com",
	.checkip_url  = "/",
	.checkip_ssl  = DDNS_CHECKIP_SSL_UNSUPPORTED,

	.server_name  = "api.dnsexit.com",
	.server_url   = "/dns/ud/"
};

static int get_code_value(const char *json)
{
	const char * const KCODE = "code";
	int rc = -1;
	int i, num_tokens;
	jsmntok_t *tokens, *token;

	num_tokens = parse_json(json, &tokens);
	if (num_tokens < 0)
		return -1;

	if (tokens[0].type != JSMN_OBJECT) {
		logit(LOG_ERR, "JSON response contained no objects.");
		goto cleanup;
	}

	for (i = 1; i < num_tokens; i++) {
		if (jsoneq(json, tokens + i, KCODE) == 0 &&
		    i + 1 < num_tokens &&
		    (token = tokens + i + 1) != NULL &&
		    token->type == JSMN_PRIMITIVE) {
			switch (*(json + token->start))
			{
				case 't': /* true */
				case 'f': /* false */
				case 'n': /* null */
					continue;
				default:
					rc = atoi(json + token->start);
					break;
			}
			goto cleanup;
		}
	}

	logit(LOG_INFO, "Could not find number primitive '%s'.", KCODE);
cleanup:
	free(tokens);
	return rc;
}

static int request(ddns_t *ctx, ddns_info_t *info, ddns_alias_t *alias)
{
	return snprintf(ctx->request_buf, ctx->request_buflen,
			info->system->server_req,
			info->server_url,
			info->creds.password,
			alias->name,
			info->server_name.name,
			info->user_agent);
}

static int response(http_trans_t *trans, ddns_info_t *info, ddns_alias_t *alias)
{
	int   code = -1;
	char *tmp;

	(void)info;
	(void)alias;

	DO(http_status_valid(trans->status));

	tmp = strchr(trans->rsp_body, '\n');
	if (tmp != NULL) {
		code = get_code_value(tmp);
	}

	/*
	 * "code:0 indicates successful updates while code:1 indicates IP
	 * address not changed. Other returning codes indicate errors."
	 */
	logit(LOG_DEBUG, "DNSExit result code: %d\n", code);

	switch (code) {
	case 0:
	case 1:
		return 0;
	default:
		return RC_DDNS_RSP_RETRY_LATER;
	}
}

PLUGIN_INIT(plugin_init)
{
	plugin_register(&plugin, DNSEXIT_UPDATE_IP_HTTP_REQUEST);
	plugin_register_v6(&plugin, DNSEXIT_UPDATE_IP_HTTP_REQUEST);
}

PLUGIN_EXIT(plugin_exit)
{
	plugin_unregister(&plugin);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
