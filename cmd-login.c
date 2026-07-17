/*
 * command for logging into the service
 *
 * Copyright (C) 2014-2018 LastPass.
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

#include "cmd.h"
#include "kdf.h"
#include "password.h"
#include "session.h"
#include "util.h"
#include "process.h"
#include "endpoints.h"
#include "config.h"
#include "agent.h"
#include "terminal.h"
#include "federated.h"
#include <getopt.h>

int cmd_login(int argc, char **argv)
{
	static struct option long_options[] = {
		{"trust", no_argument, NULL, 't'},
		{"plaintext-key", no_argument, NULL, 'P'},
		{"force", no_argument, NULL, 'f'},
		{"color", required_argument, NULL, 'C'},
		{"no-sso", no_argument, NULL, 'S'},
		{0, 0, 0, 0}
	};
	int option;
	int option_index;
	bool trust = false;
	bool plaintext_key = false;
	bool force = false;
	bool no_sso = false;
	bool is_federated = false;
	struct federated_config fed = { 0 };
	char *username;
	_cleanup_free_ char *error = NULL;
	_cleanup_free_ char *password = NULL;
	int iterations;
	struct session *session;
	unsigned char key[KDF_HASH_LEN];
	char hex[KDF_HEX_LEN];

	while ((option = getopt_long(argc, argv, "f", long_options, &option_index)) != -1) {
	switch (option) {
		case 't':
			trust = true;
			break;
		case 'P':
			plaintext_key = true;
			break;
		case 'f':
			force = true;
			break;
		case 'C':
			terminal_set_color_mode(
				parse_color_mode_string(optarg));
			break;
		case 'S':
			no_sso = true;
			break;
		case '?':
		default:
			die_usage(cmd_login_usage);
		}
	}
	if (argc - optind != 1)
		die_usage(cmd_login_usage);

	if (!force && plaintext_key && !ask_yes_no(false, "You have used the --plaintext-key option. This option will greatly reduce the security of your passwords. You are advised, instead, to use the agent, whose timeout can be disabled by setting LPASS_AGENT_TIMEOUT=0. Are you sure you would like to do this?"))
		die("Login aborted. Try again without --plaintext-key.");

	username = argv[optind];
	is_federated = !no_sso && federated_check(username, &fed);
	iterations = lastpass_iterations(username);
	if (!iterations)
		die("Unable to fetch iteration count. Check your internet connection and be sure your username is valid.");

	if (is_federated) {
		_cleanup_free_ char *fragment_id = NULL;
		_cleanup_free_ char *calc_fragment_id = NULL;

		federated_login(username, &fed, &password, &fragment_id, &calc_fragment_id);

		/*
		 * Official clients disagree on calculatedfragmentid: the
		 * browser extension sends base64(SHA256(k1)), while Bitwarden's
		 * importer reuses the ALP fragment_id for both fields. Try the
		 * extension's behavior first, then fall back.
		 */
		const char *calc_attempts[] = { calc_fragment_id, fragment_id };

		for (size_t i = 0; i < ARRAY_SIZE(calc_attempts); i++) {
			struct lastpass_login_extra extra = {
				.alpfragmentid = fragment_id,
				.calculatedfragmentid = calc_attempts[i],
			};

			free(error);
			error = NULL;
			kdf_login_key(username, password, iterations, hex);
			kdf_decryption_key(username, password, iterations, key);
			session = lastpass_login_ex(username, hex, key, iterations, &error, trust, &extra);

			/* retry once with the server-corrected iteration count */
			if (!session_is_valid(session) && extra.ret_iterations > 0 &&
			    extra.ret_iterations != iterations) {
				iterations = extra.ret_iterations;
				kdf_login_key(username, password, iterations, hex);
				kdf_decryption_key(username, password, iterations, key);
				free(error);
				error = NULL;
				session = lastpass_login_ex(username, hex, key, iterations, &error, trust, &extra);
			}

			if (session_is_valid(session))
				break;
		}

		if (!session_is_valid(session))
			die("Federated login failed: %s", error ? error : "unknown error");
	} else do {
		free(password);
		password = password_prompt("Master Password", error, "Please enter the LastPass master password for <%s>.", username);
		if (!password)
			die("Failed to enter correct password.");

		kdf_login_key(username, password, iterations, hex);
		kdf_decryption_key(username, password, iterations, key);

		free(error);
		error = NULL;
		session = lastpass_login(username, hex, key, iterations, &error, trust);
	} while (!session_is_valid(session));

	federated_config_free_contents(&fed);
	secure_clear_str(password);

	if (is_federated)
		config_write_string("federated", "1");
	else
		config_unlink("federated");

	config_unlink("plaintext_key");
	if (plaintext_key)
		config_write_buffer("plaintext_key", (char *)key, KDF_HASH_LEN);

	agent_save(username, iterations, key);

	session_save(session, key);
	session_free(session);
	session = NULL;

	terminal_printf(TERMINAL_FG_GREEN TERMINAL_BOLD "Success" TERMINAL_RESET ": Logged in as " TERMINAL_UNDERLINE "%s" TERMINAL_RESET ".\n", username);

	return 0;
}
