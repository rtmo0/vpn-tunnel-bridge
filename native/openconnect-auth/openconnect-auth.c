/*
 * bridge-openconnect-auth: logs in to an OpenConnect server (AnyConnect, Fortinet,
 * GlobalProtect, Pulse, F5, Array) with libopenconnect and prints the session
 * cookie. Runs as the user, inside Bridge.app; only the cookie reaches the
 * privileged helper, which then starts `openconnect --cookie-on-stdin`.
 *
 * Talks to Bridge over stdin/stdout, one message per line:
 *
 *   out (JSON)                                   in (space-separated, base64 values)
 *   {"type":"log","level":1,"text":…}
 *   {"type":"cert","fingerprint":…,"reason":…}   accept | reject
 *   {"type":"form","fields":[…],…}               set <name> <value> … then submit | cancel
 *   {"type":"webview","url":…}                   load <uri> <n> <k> <v>… <m> <k> <v>… (per page) | cancel
 *   {"type":"browser","url":…}                   (none: the server redirects to localhost)
 *   {"type":"done","cookie":…,"connect_url":…,"fingerprint":…,"resolve":…}
 *   {"type":"error","message":…} | {"type":"cancelled"}
 *
 * Usage: bridge-openconnect-auth --protocol P --url URL [--group G] [--servercert PIN]
 *        [--useragent UA] [--os OS] [--cert FILE [--key FILE]]
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openconnect.h>

static struct openconnect_info *vpninfo;
static const char *opt_group, *opt_pin;
static int group_applied;

/* ---- output ---- */

static void json_str(const char *s)
{
	putchar('"');
	for (; s && *s; s++) {
		unsigned char c = (unsigned char)*s;
		switch (c) {
		case '"': fputs("\\\"", stdout); break;
		case '\\': fputs("\\\\", stdout); break;
		case '\n': fputs("\\n", stdout); break;
		case '\r': fputs("\\r", stdout); break;
		case '\t': fputs("\\t", stdout); break;
		default:
			if (c < 0x20) printf("\\u%04x", c);
			else putchar(c);
		}
	}
	putchar('"');
}

static void field(const char *key, const char *value, int comma)
{
	if (comma) putchar(',');
	json_str(key);
	putchar(':');
	if (value) json_str(value); else fputs("null", stdout);
}

static void end_line(void)
{
	puts("}");
	fflush(stdout);
}

/* ---- input ---- */

static char line[1 << 20];

static int read_line(void)
{
	if (!fgets(line, sizeof(line), stdin)) return -1;
	line[strcspn(line, "\r\n")] = 0;
	return 0;
}

static int b64val(int c)
{
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+' || c == '-') return 62;
	if (c == '/' || c == '_') return 63;
	return -1;
}

/* Decodes base64 into a new NUL-terminated string. */
static char *b64dup(const char *in)
{
	size_t n = strlen(in);
	char *out = malloc(n * 3 / 4 + 4), *p = out;
	unsigned int acc = 0;
	int bits = 0;
	if (!out) return NULL;
	for (; *in; in++) {
		int v = b64val((unsigned char)*in);
		if (v < 0) continue;
		acc = (acc << 6) | (unsigned int)v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			*p++ = (char)((acc >> bits) & 0xff);
		}
	}
	*p = 0;
	return out;
}

/* ---- callbacks ---- */

static void progress(void *priv, int level, const char *fmt, ...)
{
	char buf[2048];
	va_list ap;
	(void)priv;
	if (level > PRG_INFO) return;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	buf[strcspn(buf, "\n")] = 0;
	printf("{\"type\":\"log\",\"level\":%d", level);
	field("text", buf, 1);
	end_line();
}

static int validate_cert(void *priv, const char *reason)
{
	const char *hash = openconnect_get_peer_cert_hash(vpninfo);
	char *details = openconnect_get_peer_cert_details(vpninfo);
	(void)priv;
	if (opt_pin && openconnect_check_peer_cert_hash(vpninfo, opt_pin) == 0) {
		openconnect_free_cert_info(vpninfo, details);
		return 0;
	}
	printf("{");
	field("type", "cert", 0);
	field("fingerprint", hash, 1);
	field("reason", reason, 1);
	field("details", details, 1);
	end_line();
	openconnect_free_cert_info(vpninfo, details);
	if (read_line() < 0) return -1;
	return strcmp(line, "accept") == 0 ? 0 : -1;
}

static const char *type_name(int type)
{
	switch (type) {
	case OC_FORM_OPT_TEXT: return "text";
	case OC_FORM_OPT_PASSWORD: return "password";
	case OC_FORM_OPT_SELECT: return "select";
	case OC_FORM_OPT_TOKEN: return "token";
	default: return "hidden";
	}
}

/* The current value of an option; for the group list, the selected choice. */
static const char *current_value(struct oc_auth_form *form, struct oc_form_opt *opt)
{
	if (opt->_value) return opt->_value;
	if (form->authgroup_opt && opt == &form->authgroup_opt->form) {
		struct oc_form_opt_select *sel = form->authgroup_opt;
		if (form->authgroup_selection >= 0 && form->authgroup_selection < sel->nr_choices)
			return sel->choices[form->authgroup_selection]->name;
	}
	return NULL;
}

static int process_form(void *priv, struct oc_auth_form *form)
{
	struct oc_form_opt *opt;
	int first = 1;
	(void)priv;

	/* Pick the configured group, like the openconnect command does. The value is
	   always set explicitly: a selection without a value is not posted. */
	if (opt_group && form->authgroup_opt) {
		struct oc_form_opt_select *sel = form->authgroup_opt;
		int i;
		for (i = 0; i < sel->nr_choices; i++) {
			struct oc_choice *c = sel->choices[i];
			if (!strcmp(c->name, opt_group) || (c->label && !strcmp(c->label, opt_group))) {
				openconnect_set_option_value(&sel->form, c->name);
				if (i != form->authgroup_selection && !group_applied) {
					group_applied = 1;
					return OC_FORM_RESULT_NEWGROUP;
				}
				break;
			}
		}
	}

	printf("{");
	field("type", "form", 0);
	field("banner", form->banner, 1);
	field("message", form->message, 1);
	field("error", form->error, 1);
	field("auth_id", form->auth_id, 1);
	field("authgroup", form->authgroup_opt ? form->authgroup_opt->form.name : NULL, 1);
	fputs(",\"fields\":[", stdout);
	for (opt = form->opts; opt; opt = opt->next) {
		if (opt->flags & OC_FORM_OPT_IGNORE) continue;
		if (!first) putchar(',');
		first = 0;
		printf("{");
		field("name", opt->name, 0);
		field("label", opt->label, 1);
		field("type", type_name(opt->type), 1);
		field("value", current_value(form, opt), 1);
		printf(",\"numeric\":%s", (opt->flags & OC_FORM_OPT_NUMERIC) ? "true" : "false");
		if (opt->type == OC_FORM_OPT_SELECT) {
			struct oc_form_opt_select *sel = (struct oc_form_opt_select *)opt;
			int i;
			fputs(",\"options\":[", stdout);
			for (i = 0; i < sel->nr_choices; i++) {
				printf("%s{", i ? "," : "");
				field("name", sel->choices[i]->name, 0);
				field("label", sel->choices[i]->label, 1);
				putchar('}');
			}
			putchar(']');
		}
		putchar('}');
	}
	putchar(']');
	end_line();

	for (;;) {
		char *cmd, *name, *value;
		if (read_line() < 0) return OC_FORM_RESULT_CANCELLED;
		if (!strcmp(line, "submit")) break;
		if (!strcmp(line, "cancel")) return OC_FORM_RESULT_CANCELLED;
		cmd = strtok(line, " ");
		name = strtok(NULL, " ");
		value = strtok(NULL, " ");
		if (!cmd || strcmp(cmd, "set") || !name) continue;
		{
			char *n = b64dup(name), *v = b64dup(value ? value : "");
			int newgroup = 0;
			for (opt = form->opts; opt; opt = opt->next) {
				if (!opt->name || strcmp(opt->name, n)) continue;
				if (form->authgroup_opt && opt == &form->authgroup_opt->form) {
					const char *cur = current_value(form, opt);
					if (!cur || strcmp(cur, v)) newgroup = 1;
				}
				openconnect_set_option_value(opt, v);
			}
			free(n);
			if (v) {
				memset(v, 0, strlen(v));
				free(v);
			}
			if (newgroup) {
				/* A different group can mean a different form; ask the server. */
				while (read_line() == 0 && strcmp(line, "submit") && strcmp(line, "cancel")) { }
				return OC_FORM_RESULT_NEWGROUP;
			}
		}
	}
	return OC_FORM_RESULT_OK;
}

/* Embedded login page (SAML / OIDC): Bridge shows a web view and reports every page load. */
static int open_webview(struct openconnect_info *vi, const char *uri, void *priv)
{
	(void)priv;
	printf("{");
	field("type", "webview", 0);
	field("url", uri, 1);
	end_line();

	for (;;) {
		char *tok, *save = NULL;
		const char **cookies = NULL, **headers = NULL;
		char *page = NULL;
		int n, i, ret;
		if (read_line() < 0 || !strcmp(line, "cancel")) return -ECANCELED;
		tok = strtok_r(line, " ", &save);
		if (!tok || strcmp(tok, "load")) continue;
		tok = strtok_r(NULL, " ", &save);
		page = b64dup(tok ? tok : "");
		for (int list = 0; list < 2; list++) {
			const char **arr;
			tok = strtok_r(NULL, " ", &save);
			n = tok ? atoi(tok) : 0;
			if (n < 0 || n > 4096) n = 0;
			arr = calloc((size_t)n * 2 + 1, sizeof(char *));
			for (i = 0; i < n * 2; i++) {
				tok = strtok_r(NULL, " ", &save);
				arr[i] = b64dup(tok ? tok : "");
			}
			if (list == 0) cookies = arr; else headers = arr;
		}
		{
			struct oc_webview_result result = { page, cookies, headers };
			ret = openconnect_webview_load_changed(vi, &result);
		}
		free(page);
		for (const char **a = cookies; a && *a; a++) free((void *)*a);
		for (const char **a = headers; a && *a; a++) free((void *)*a);
		free(cookies);
		free(headers);
		if (ret == 0) {
			printf("{");
			field("type", "webview-done", 0);
			end_line();
			return 0;
		}
		if (ret != -EAGAIN) return ret;
	}
}

/* Cisco "external browser" SAML: the server sends the browser back to localhost:29786. */
static int open_external_browser(struct openconnect_info *vi, const char *uri, void *priv)
{
	(void)vi;
	(void)priv;
	printf("{");
	field("type", "browser", 0);
	field("url", uri, 1);
	end_line();
	return 0;
}

int main(int argc, char **argv)
{
	const char *protocol = "anyconnect", *url = NULL, *ua = NULL, *os = NULL, *cert = NULL, *key = NULL;
	int i, ret;

	for (i = 1; i + 1 < argc; i += 2) {
		const char *k = argv[i], *v = argv[i + 1];
		if (!strcmp(k, "--protocol")) protocol = v;
		else if (!strcmp(k, "--url")) url = v;
		else if (!strcmp(k, "--group")) opt_group = v;
		else if (!strcmp(k, "--servercert")) opt_pin = v;
		else if (!strcmp(k, "--useragent")) ua = v;
		else if (!strcmp(k, "--os")) os = v;
		else if (!strcmp(k, "--cert")) cert = v;
		else if (!strcmp(k, "--key")) key = v;
		else {
			fprintf(stderr, "unknown option %s\n", k);
			return 2;
		}
	}
	if (!url) {
		fprintf(stderr, "--url is required\n");
		return 2;
	}

	openconnect_init_ssl();
	/* Same default as the openconnect command, which carries the session on. */
	vpninfo = openconnect_vpninfo_new("Open AnyConnect VPN Agent", validate_cert, NULL, process_form, progress, NULL);
	if (!vpninfo) return 1;
	if (ua) openconnect_set_useragent(vpninfo, ua);
	openconnect_set_loglevel(vpninfo, PRG_INFO);
	if (openconnect_set_protocol(vpninfo, protocol)) {
		printf("{");
		field("type", "error", 0);
		field("message", "Unknown protocol", 1);
		end_line();
		return 1;
	}
	if (os) openconnect_set_reported_os(vpninfo, os);
	if (cert) openconnect_set_client_cert(vpninfo, cert, key);
	openconnect_set_webview_callback(vpninfo, open_webview);
	openconnect_set_external_browser_callback(vpninfo, open_external_browser);
	if (openconnect_parse_url(vpninfo, url)) {
		printf("{");
		field("type", "error", 0);
		field("message", "The server address is not valid", 1);
		end_line();
		return 1;
	}

	ret = openconnect_obtain_cookie(vpninfo);
	if (ret == 1) {
		printf("{");
		field("type", "cancelled", 0);
		end_line();
		return 1;
	}
	if (ret != 0 || !openconnect_get_cookie(vpninfo)) {
		printf("{");
		field("type", "error", 0);
		field("message", "Authentication failed", 1);
		end_line();
		return 1;
	}

	{
		const char *host = openconnect_get_hostname(vpninfo), *dns = openconnect_get_dnsname(vpninfo);
		char resolve[512] = "";
		/* The server's IP as authentication saw it, so the tunnel reaches the same node. */
		if (host && dns && strcmp(host, dns))
			snprintf(resolve, sizeof(resolve), "%s:%s", dns, host);
		printf("{");
		field("type", "done", 0);
		field("cookie", openconnect_get_cookie(vpninfo), 1);
		field("connect_url", openconnect_get_connect_url(vpninfo), 1);
		field("host", host, 1);
		field("fingerprint", openconnect_get_peer_cert_hash(vpninfo), 1);
		field("resolve", resolve[0] ? resolve : NULL, 1);
		end_line();
	}
	openconnect_vpninfo_free(vpninfo);
	return 0;
}
