#ifndef FEDERATED_H
#define FEDERATED_H

#include <stdbool.h>
#include <stddef.h>

enum federated_provider {
	FEDERATED_PROVIDER_AZURE = 0,
	FEDERATED_PROVIDER_OKTA = 1,
	FEDERATED_PROVIDER_OKTA_AUTHSERVER = 2,
	FEDERATED_PROVIDER_GOOGLE = 3,
	FEDERATED_PROVIDER_PINGONE = 4,
	FEDERATED_PROVIDER_ONELOGIN = 5,
};

struct federated_config {
	int type;		/* login type; 3 = federated OIDC */
	int provider;		/* enum federated_provider */
	char *authority;	/* OpenIDConnectAuthority, query string stripped */
	char *client_id;	/* OpenIDConnectClientId */
	int company_id;		/* CompanyId */
	bool pkce_enabled;	/* PkceEnabled */
	char *idp_url;		/* IdentityProviderURL, or NULL */
};

bool federated_check(const char *username, struct federated_config *cfg);
void federated_config_free_contents(struct federated_config *cfg);

/*
 * Run the full interactive federated (SSO) login flow. Dies on
 * unrecoverable errors. All three outputs are heap strings the caller
 * must secure_clear_str() and free.
 */
void federated_login(const char *username, const struct federated_config *cfg,
		     char **hidden_password, char **fragment_id,
		     char **calculated_fragment_id);

/* exposed for testing */
bool federated_parse_login_type(const char *json, struct federated_config *cfg);

#endif
