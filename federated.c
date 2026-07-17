/*
 * federated (SSO) login support
 *
 * Copyright (C) 2014-2026 LastPass.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 * See LICENSE.OpenSSL for more details regarding this exception.
 */
#include "federated.h"
#include "http.h"
#include "util.h"
#include "cipher.h"
#include "config.h"
#include "blob.h"
#include "cJSON.h"
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/wait.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <curl/curl.h>

#define FEDERATED_REDIRECT_URI "https://accounts.lastpass.com/federated/oidcredirect.html"
#define FEDERATED_ALP_SERVER "https://accounts.lastpass.com"
/* the official LastPass browser extension's origin; identity providers with
 * SPA-type app registrations require a matching Origin on token requests */
#define FEDERATED_EXTENSION_ORIGIN "chrome-extension://hdokiejnpimakedhajhdlcegeplioahd"
#define OIDC_WELL_KNOWN "/.well-known/openid-configuration"

static char *json_dup_string(cJSON *json, const char *name)
{
	cJSON *item = cJSON_GetObjectItem(json, name);

	if (!cJSON_IsString(item) || !item->valuestring[0])
		return NULL;
	return xstrdup(item->valuestring);
}

static int json_get_int(cJSON *json, const char *name, int def)
{
	cJSON *item = cJSON_GetObjectItem(json, name);

	if (!cJSON_IsNumber(item))
		return def;
	return item->valueint;
}

static char *url_encode(const char *str)
{
	CURL *curl;
	char *encoded, *result;

	curl = curl_easy_init();
	if (!curl)
		die("Could not init curl");
	encoded = curl_easy_escape(curl, str, 0);
	if (!encoded)
		die("Could not escape %s with curl", str);
	result = xstrdup(encoded);
	curl_free(encoded);
	curl_easy_cleanup(curl);
	return result;
}

static char *url_decode(const char *str, size_t len)
{
	CURL *curl;
	char *decoded, *result;

	curl = curl_easy_init();
	if (!curl)
		die("Could not init curl");
	decoded = curl_easy_unescape(curl, str, len, NULL);
	if (!decoded)
		die("Could not unescape %s with curl", str);
	result = xstrdup(decoded);
	curl_free(decoded);
	curl_easy_cleanup(curl);
	return result;
}

static char *b64url_encode(const unsigned char *bytes, size_t len)
{
	char *b64 = xcalloc(((len + 2) / 3) * 4 + 1, 1);
	char *p;

	EVP_EncodeBlock((unsigned char *)b64, bytes, len);
	for (p = b64; *p; p++) {
		if (*p == '+')
			*p = '-';
		else if (*p == '/')
			*p = '_';
		else if (*p == '=') {
			*p = '\0';
			break;
		}
	}
	return b64;
}

static char *random_b64url(void)
{
	unsigned char bytes[32];

	if (RAND_bytes(bytes, sizeof(bytes)) != 1)
		die("Could not generate random bytes.");
	return b64url_encode(bytes, sizeof(bytes));
}

static char *pkce_challenge(const char *verifier)
{
	unsigned char digest[SHA256_DIGEST_LENGTH];

	SHA256((const unsigned char *)verifier, strlen(verifier), digest);
	return b64url_encode(digest, sizeof(digest));
}

bool federated_parse_login_type(const char *json, struct federated_config *cfg)
{
	cJSON *root;
	char *query;

	root = cJSON_Parse(json);
	if (!root)
		return false;

	cfg->type = json_get_int(root, "type", 0);
	cfg->provider = json_get_int(root, "Provider", -1);
	cfg->company_id = json_get_int(root, "CompanyId", 0);
	cfg->authority = json_dup_string(root, "OpenIDConnectAuthority");
	cfg->client_id = json_dup_string(root, "OpenIDConnectClientId");
	cfg->idp_url = json_dup_string(root, "IdentityProviderURL");
	cfg->pkce_enabled = cJSON_IsTrue(cJSON_GetObjectItem(root, "PkceEnabled"));
	cJSON_Delete(root);

	/* Azure appends "?appid=..." to the authority; strip any query */
	if (cfg->authority) {
		query = strchr(cfg->authority, '?');
		if (query)
			*query = '\0';
	}

	return cfg->type == 3 && cfg->authority && cfg->client_id;
}

bool federated_check(const char *username, struct federated_config *cfg)
{
	_cleanup_free_ char *user_lower = NULL;
	_cleanup_free_ char *user_encoded = NULL;
	_cleanup_free_ char *url = NULL;
	_cleanup_free_ char *reply = NULL;
	long http_code = 0;

	user_lower = xstrlower(username);
	user_encoded = url_encode(user_lower);
	xasprintf(&url, "https://" LASTPASS_SERVER "/lmiapi/login/type?username=%s",
		  user_encoded);

	reply = http_get_url(url, NULL, NULL, &http_code);
	if (!reply || http_code != 200)
		return false;

	return federated_parse_login_type(reply, cfg);
}

void federated_config_free_contents(struct federated_config *cfg)
{
	free(cfg->authority);
	free(cfg->client_id);
	free(cfg->idp_url);
	cfg->authority = cfg->client_id = cfg->idp_url = NULL;
}

static void oidc_discover(const struct federated_config *cfg,
			  char **authorize_ep, char **token_ep)
{
	_cleanup_free_ char *url = NULL;
	_cleanup_free_ char *reply = NULL;
	long http_code = 0;
	cJSON *root;

	if (strstr(cfg->authority, OIDC_WELL_KNOWN))
		url = xstrdup(cfg->authority);
	else
		xasprintf(&url, "%s%s%s", cfg->authority,
			  cfg->authority[strlen(cfg->authority) - 1] == '/' ? "" : "/",
			  &OIDC_WELL_KNOWN[1]);

	reply = http_get_url(url, NULL, NULL, &http_code);
	if (!reply || http_code != 200)
		die("Unable to fetch OpenID Connect configuration from your identity provider (%s).", url);

	root = cJSON_Parse(reply);
	if (!root)
		die("Invalid OpenID Connect configuration document.");
	*authorize_ep = json_dup_string(root, "authorization_endpoint");
	*token_ep = json_dup_string(root, "token_endpoint");
	cJSON_Delete(root);

	if (!*authorize_ep || !*token_ep)
		die("OpenID Connect configuration is missing authorization or token endpoint.");
}

static const char *provider_scope(const struct federated_config *cfg)
{
	switch (cfg->provider) {
	case FEDERATED_PROVIDER_AZURE:
		return "openid email profile user.readwrite";
	default:
		return "openid email profile";
	}
}

static char *build_authorize_url(const struct federated_config *cfg,
				 const char *authorize_ep, const char *username,
				 bool use_pkce, const char *state,
				 const char *nonce, const char *code_challenge)
{
	struct buffer buf;
	unsigned int i;

	const char *params[][2] = {
		{ "client_id", cfg->client_id },
		{ "redirect_uri", FEDERATED_REDIRECT_URI },
		{ "response_type", use_pkce ? "code" : "id_token token" },
		{ "response_mode", use_pkce ? "query" : "fragment" },
		{ "scope", provider_scope(cfg) },
		{ "state", state },
		{ "nonce", nonce },
		{ "login_hint", username },
		{ "code_challenge", use_pkce ? code_challenge : NULL },
		{ "code_challenge_method", use_pkce ? "S256" : NULL },
	};

	buffer_init(&buf);
	buffer_append_str(&buf, (char *)authorize_ep);
	for (i = 0; i < ARRAY_SIZE(params); i++) {
		_cleanup_free_ char *encoded = NULL;

		if (!params[i][1])
			continue;
		encoded = url_encode(params[i][1]);
		buffer_append_char(&buf, i == 0 ? '?' : '&');
		buffer_append_str(&buf, (char *)params[i][0]);
		buffer_append_char(&buf, '=');
		buffer_append_str(&buf, encoded);
	}
	buffer_append_char(&buf, '\0');
	return buf.bytes;
}

/*
 * Parse code / tokens out of the redirect URL the user pasted back.
 * Handles parameters in either the query string (PKCE, response_mode=query)
 * or the fragment (implicit flow). Dies with the IdP's message if the
 * response carries an OAuth error.
 */
static void parse_redirect_url(const char *url, const char *expected_state,
			       char **code, char **access_token, char **id_token)
{
	_cleanup_free_ char *state = NULL;
	_cleanup_free_ char *error = NULL;
	_cleanup_free_ char *error_desc = NULL;
	const char *start, *p, *eq, *end;

	*code = *access_token = *id_token = NULL;

	start = strchr(url, '?');
	if (!start)
		start = strchr(url, '#');
	if (!start)
		die("No parameters found in the pasted URL. Paste the full URL from the browser's address bar.");

	for (p = start + 1; *p; p = *end ? end + 1 : end) {
		if (*p == '#') {
			p++;
			if (!*p)
				break;
		}
		end = p + strcspn(p, "&#");
		eq = memchr(p, '=', end - p);
		if (!eq)
			continue;

		_cleanup_free_ char *name = xstrndup(p, eq - p);
		_cleanup_free_ char *value = url_decode(eq + 1, end - (eq + 1));

		if (!strcmp(name, "code")) {
			free(*code);
			*code = xstrdup(value);
		} else if (!strcmp(name, "access_token")) {
			free(*access_token);
			*access_token = xstrdup(value);
		} else if (!strcmp(name, "id_token")) {
			free(*id_token);
			*id_token = xstrdup(value);
		} else if (!strcmp(name, "state")) {
			free(state);
			state = xstrdup(value);
		} else if (!strcmp(name, "error")) {
			free(error);
			error = xstrdup(value);
		} else if (!strcmp(name, "error_description")) {
			free(error_desc);
			error_desc = xstrdup(value);
		}
	}

	if (error)
		die("Your identity provider returned an error: %s%s%s",
		    error, error_desc ? ": " : "", error_desc ? error_desc : "");

	if (!state || strcmp(state, expected_state))
		die("The pasted URL does not match this login attempt (state mismatch). Please try again.");
}

static void open_browser(const char *url)
{
	pid_t pid;

	if (getenv("LPASS_NO_BROWSER"))
		return;

	pid = fork();
	if (pid < 0)
		return;
	if (!pid) {
		int null = open("/dev/null", O_WRONLY);
		if (null >= 0) {
			dup2(null, STDOUT_FILENO);
			dup2(null, STDERR_FILENO);
			close(null);
		}
#if defined(__APPLE__)
		execlp("open", "open", url, NULL);
#else
		execlp("xdg-open", "xdg-open", url, NULL);
#endif
		_exit(127);
	}
	waitpid(pid, NULL, 0);
}

/*
 * Read a line of arbitrary length from stdin. When stdin is a terminal,
 * canonical mode must be disabled first: its line buffer is limited (1024
 * bytes on macOS), which silently swallows pasted OAuth redirect URLs that
 * routinely exceed 3KB.
 */
static ssize_t read_pasted_line(char **line, size_t *len)
{
	struct termios old_termios, raw;
	bool restore = false;
	ssize_t read_len;

	if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &old_termios) == 0) {
		raw = old_termios;
		raw.c_lflag &= ~ICANON;
		raw.c_cc[VMIN] = 1;
		raw.c_cc[VTIME] = 0;
		if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0)
			restore = true;
	}

	read_len = getline(line, len, stdin);

	if (restore && tcsetattr(STDIN_FILENO, TCSANOW, &old_termios) < 0)
		die_errno("tcsetattr");

	return read_len;
}

static void browser_authorize(const char *url, const char *expected_state,
			      char **code, char **access_token, char **id_token)
{
	_cleanup_free_ char *line = NULL;
	size_t len = 0;
	ssize_t read_len;

	printf("Open the following URL in your browser and sign in to your identity provider:\n\n%s\n\n", url);
	open_browser(url);
	printf("After signing in, you will land on an %s page.\n"
	       "Copy the full URL from the browser's address bar and paste it here.\n\n",
	       "accounts.lastpass.com");
	printf("Paste redirect URL: ");
	fflush(stdout);

	read_len = read_pasted_line(&line, &len);
	if (read_len < 0)
		die("Failed to read the redirect URL.");
	while (read_len > 0 && (line[read_len - 1] == '\n' || line[read_len - 1] == '\r' ||
				line[read_len - 1] == ' '))
		line[--read_len] = '\0';

	parse_redirect_url(line, expected_state, code, access_token, id_token);
	secure_clear(line, len);
}

/*
 * Redeem the authorization code. Returns false if the identity provider
 * refuses public-client code redemption entirely (confidential Web app
 * registration, AADSTS7000218) so the caller can retry with the legacy
 * implicit flow; dies on any other failure.
 */
static bool token_exchange(const char *token_ep, const struct federated_config *cfg,
			   const char *code, const char *verifier,
			   char **access_token, char **id_token)
{
	_cleanup_free_ char *reply = NULL;
	long http_code = 0;
	cJSON *root;

	char *params[] = {
		"grant_type", "authorization_code",
		"client_id", cfg->client_id,
		"code", (char *)code,
		"redirect_uri", FEDERATED_REDIRECT_URI,
		"code_verifier", (char *)verifier,
		NULL
	};

	reply = http_post_url_form(token_ep, params, NULL, &http_code);

	/*
	 * Azure rejects same-origin redemption for SPA-type app
	 * registrations (AADSTS9002327); those require an Origin header
	 * matching the official extension. Web-type registrations reject
	 * the reverse (AADSTS9002326), so only add Origin on demand.
	 */
	if (reply && http_code != 200 && strstr(reply, "AADSTS9002327")) {
		secure_clear(reply, strlen(reply));
		free(reply);
		reply = http_post_url_form(token_ep, params,
					   FEDERATED_EXTENSION_ORIGIN, &http_code);
	}

	if (!reply)
		die("Unable to contact your identity provider's token endpoint.");

	if (http_code != 200 && strstr(reply, "AADSTS7000218"))
		return false;

	root = cJSON_Parse(reply);
	secure_clear(reply, strlen(reply));
	if (!root)
		die("Invalid response from your identity provider's token endpoint.");

	*access_token = json_dup_string(root, "access_token");
	*id_token = json_dup_string(root, "id_token");
	if (http_code != 200 || !*access_token || !*id_token) {
		_cleanup_free_ char *desc = json_dup_string(root, "error_description");
		cJSON_Delete(root);
		die("Token exchange with your identity provider failed%s%s.",
		    desc ? ": " : "", desc ? desc : "");
	}
	cJSON_Delete(root);
	return true;
}

static char *fetch_k1_azure(const char *access_token)
{
	_cleanup_free_ char *reply = NULL;
	long http_code = 0;
	cJSON *root, *extensions, *extension, *k1_item;
	char *k1 = NULL;

	reply = http_get_url("https://graph.microsoft.com/v1.0/me?$select=id,displayName,mail&$expand=extensions",
			     access_token, NULL, &http_code);
	if (!reply || http_code != 200)
		die("Unable to read your user profile from Microsoft Graph (HTTP %ld).", http_code);

	root = cJSON_Parse(reply);
	if (!root)
		die("Invalid response from Microsoft Graph.");

	extensions = cJSON_GetObjectItem(root, "extensions");
	cJSON_ArrayForEach(extension, extensions) {
		_cleanup_free_ char *id = json_dup_string(extension, "id");

		if (id && strcmp(id, "com.lastpass.keys"))
			continue;
		k1_item = cJSON_GetObjectItem(extension, "LastPassK1");
		if (cJSON_IsString(k1_item)) {
			k1 = xstrdup(k1_item->valuestring);
			break;
		}
	}
	cJSON_Delete(root);

	if (!k1)
		die("Your account does not have LastPass federated key material provisioned.\n"
		    "Log in once with the LastPass browser extension or web vault, then try again.");
	return k1;
}

static void fetch_k2(const struct federated_config *cfg, const char *id_token,
		     char **k2, char **fragment_id)
{
	_cleanup_free_ char *url = NULL;
	_cleanup_free_ char *body = NULL;
	_cleanup_free_ char *reply = NULL;
	long http_code = 0;
	cJSON *root;

	root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "company_id", cfg->company_id);
	cJSON_AddStringToObject(root, "id_token", id_token);
	body = cJSON_PrintUnformatted(root);
	cJSON_Delete(root);

	xasprintf(&url, "%s/federatedlogin/api/v1/getkey",
		  cfg->idp_url ? cfg->idp_url : FEDERATED_ALP_SERVER);

	reply = http_post_url_json(url, body, &http_code);
	secure_clear(body, strlen(body));
	if (!reply || http_code != 200)
		die("Unable to fetch your key material from LastPass (HTTP %ld).", http_code);

	root = cJSON_Parse(reply);
	secure_clear(reply, strlen(reply));
	if (!root)
		die("Invalid response from the LastPass federated login service.");
	*k2 = json_dup_string(root, "k2");
	*fragment_id = json_dup_string(root, "fragment_id");
	cJSON_Delete(root);

	if (!*k2 || !*fragment_id)
		die("The LastPass federated login service did not return key material.");
}

static void derive_hidden_password(const char *k1_b64, const char *k2_b64,
				   char **hidden_password,
				   char **calculated_fragment_id)
{
	_cleanup_free_ unsigned char *k1 = NULL;
	_cleanup_free_ unsigned char *k2 = NULL;
	_cleanup_free_ unsigned char *xored = NULL;
	size_t k1_len, k2_len, i;

	k1_len = unbase64(k1_b64, &k1);
	k2_len = unbase64(k2_b64, &k2);
	if (!k1_len || k1_len != k2_len)
		die("Federated key material is malformed (K1/K2 length mismatch).");

	xored = xcalloc(k1_len, 1);
	for (i = 0; i < k1_len; i++)
		xored[i] = k1[i] ^ k2[i];

	*hidden_password = cipher_sha256_b64(xored, k1_len);
	*calculated_fragment_id = cipher_sha256_b64(k1, k1_len);

	secure_clear(k1, k1_len);
	secure_clear(k2, k2_len);
	secure_clear(xored, k1_len);
}

/*
 * One authorize round trip through the browser. With use_pkce, redeems the
 * pasted authorization code at the token endpoint; returns false if the
 * identity provider only allows the implicit flow. Without use_pkce
 * (implicit flow), the tokens arrive directly in the pasted URL fragment.
 */
static bool oidc_authorize_round(const struct federated_config *cfg,
				 const char *authorize_ep, const char *token_ep,
				 const char *user_lower, bool use_pkce,
				 char **access_token, char **id_token)
{
	_cleanup_free_ char *state = NULL;
	_cleanup_free_ char *nonce = NULL;
	_cleanup_free_ char *verifier = NULL;
	_cleanup_free_ char *challenge = NULL;
	_cleanup_free_ char *authorize_url = NULL;
	_cleanup_free_ char *code = NULL;

	state = random_b64url();
	nonce = random_b64url();
	if (use_pkce) {
		verifier = random_b64url();
		challenge = pkce_challenge(verifier);
	}

	authorize_url = build_authorize_url(cfg, authorize_ep, user_lower,
					    use_pkce, state, nonce, challenge);
	browser_authorize(authorize_url, state, &code, access_token, id_token);

	if (use_pkce) {
		if (!code)
			die("The pasted URL does not contain an authorization code.");
		if (!token_exchange(token_ep, cfg, code, verifier,
				    access_token, id_token))
			return false;
		secure_clear_str(verifier);
	}
	if (!*access_token || !*id_token)
		die("The pasted URL does not contain the expected tokens. Paste the full URL, including everything after '#'.");
	return true;
}

void federated_login(const char *username, const struct federated_config *cfg,
		     char **hidden_password, char **fragment_id,
		     char **calculated_fragment_id)
{
	_cleanup_free_ char *authorize_ep = NULL;
	_cleanup_free_ char *token_ep = NULL;
	_cleanup_free_ char *user_lower = NULL;
	_cleanup_free_ char *access_token = NULL;
	_cleanup_free_ char *id_token = NULL;
	_cleanup_free_ char *k1 = NULL;
	_cleanup_free_ char *k2 = NULL;

	switch (cfg->provider) {
	case FEDERATED_PROVIDER_AZURE:
		break;
	default:
		die("Your account is federated through an identity provider (%d) that lpass does not support yet.\n"
		    "Currently supported: Microsoft Entra ID (Azure AD).", cfg->provider);
	}

	oidc_discover(cfg, &authorize_ep, &token_ep);
	user_lower = xstrlower(username);

	/*
	 * The PkceEnabled flag from login/type is unreliable: some tenants'
	 * app registrations only permit the implicit flow even when the API
	 * claims PKCE. Remember which flow last worked so re-logins don't
	 * need two browser rounds; `lpass logout` clears the hint.
	 */
	bool use_pkce = cfg->pkce_enabled;
	_cleanup_free_ char *flow_hint = config_read_string("federated_flow");
	if (flow_hint && !strcmp(flow_hint, "implicit"))
		use_pkce = false;

	if (!oidc_authorize_round(cfg, authorize_ep, token_ep, user_lower,
				  use_pkce, &access_token, &id_token)) {
		printf("\nYour identity provider does not allow the authorization code flow;\n"
		       "retrying with the legacy flow. Please sign in once more.\n\n");
		use_pkce = false;
		if (!oidc_authorize_round(cfg, authorize_ep, token_ep, user_lower,
					  false, &access_token, &id_token))
			die("Login with your identity provider failed.");
	}
	config_write_string("federated_flow", use_pkce ? "pkce" : "implicit");

	k1 = fetch_k1_azure(access_token);
	fetch_k2(cfg, id_token, &k2, fragment_id);

	derive_hidden_password(k1, k2, hidden_password, calculated_fragment_id);

	secure_clear_str(k1);
	secure_clear_str(k2);
	secure_clear_str(access_token);
	secure_clear_str(id_token);
}
