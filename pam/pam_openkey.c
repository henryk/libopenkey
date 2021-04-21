#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "helpers.h"
#include "openkey.h"

// Boilerplate code copied from pam_yubico.c

#ifndef PIC
#define PAM_STATIC
#endif

#define PAM_SM_AUTH

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#ifndef PAM_EXTERN
#ifdef PAM_STATIC
#define PAM_EXTERN static
#else
#define PAM_EXTERN extern
#endif
#endif

#define D_ERR(msg, ...) do{fprintf(stderr, "ERROR: %s:%i: " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); syslog(LOG_ERR, "pam_openkey: %s:%i: " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__);}while(0)
#define D_ERR_MEM D_ERR("Couldn't allocate memory")
#define D_WARN(msg, ...) do{fprintf(stderr, "Warning: %s:%i: " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); syslog(LOG_WARNING, "pam_openkey: %s:%i: " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__);}while(0)
#define D_DBG(msg, ...) do{if(s->debug) {fprintf(stderr, "DEBUG: %s:%i: " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); syslog(LOG_DEBUG, "pam_openkey: %s:%i: " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__);}}while(0)

struct status {
	openkey_context_t ctx;
	bool alwaysok, try_first_pass, use_first_pass, no_pin, allow_empty_pin, any_token, debug;
	char *map_file;
	char *secrets_directory;

	const char *username;
	const char *password;
	bool password_needs_free;
	char *token_id;
};

static int parse_arguments(struct status *s, int argc, const char **argv)
{
	if(argc < 1) {
		D_ERR("No secrets directory specified");
		return -1;
	}

	s->secrets_directory = strdup(argv[0]);
	if(s->secrets_directory == NULL) {
		D_ERR_MEM;
		return -1;
	}

	argv++;
	argc--;

	for(int i=0; i<argc; i++) {
		if(strncasecmp(argv[i], "alwaysok", 8) == 0) {
			s->alwaysok = 1;
		} else if(strncasecmp(argv[i], "try_first_pass", 14) == 0) {
			s->try_first_pass = 1;
		} else if(strncasecmp(argv[i], "use_first_pass", 14) == 0) {
			s->use_first_pass = 1;
		} else if(strncasecmp(argv[i], "no_pin", 6) == 0) {
			s->no_pin = 1;
		} else if(strncasecmp(argv[i], "allow_empty_pin", 15) == 0) {
			s->allow_empty_pin = 1;
		} else if(strncasecmp(argv[i], "any_token", 9) == 0) {
			s->any_token = 1;
		} else if(strncasecmp(argv[i], "debug", 5) == 0) {
			s->debug = 1;
		} else if(strncasecmp(argv[i], "map_file=", 9) == 0) {
			if(s->map_file != NULL) {
				free(s->map_file);
			}
			s->map_file = strdup(argv[i] + 9);
			if(s->map_file == NULL) {
				D_ERR_MEM;
				return -1;
			}
		} else {
			D_WARN("Unknown argument received: '%s', ignored", argv[i]);
		}
	}

	if(s->map_file == NULL && !s->any_token) {
		D_ERR("Either 'any_token' must be specified or a token map file with 'map_file=...'");
		return -1;
	}

	return 0;
}

static int check_token_id(struct status *s)
{
	int retval = PAM_AUTH_ERR;
	FILE *fh = NULL;
	char *line = NULL;
	size_t line_length = 0;

	fh = fopen(s->map_file, "r");
	if(fh == NULL) {
		D_ERR("Couldn't open token map file");
		goto abort;
	}

	while(getline(&line, &line_length, fh) >= 0) {
		if(line_length == 0) {
			D_DBG("Empty line, ignored");
			continue;
		}
		if(line[0] == '#') {
			D_DBG("Comment line, ignored");
			continue;
		}

		char *colonpos = strchr(line, ':');
		if(colonpos == NULL) {
			D_DBG("Malformed line, missing colon, ignored");
			continue;
		}

		if(strncasecmp(s->username, line, colonpos-line) != 0 || strlen(s->username) != colonpos-line) {
			D_DBG("Username '%s' doesn't match line '%s', ignored", s->username, line);
			continue;
		}

		if(strlen(colonpos) < strlen(s->token_id) + 1 + 1) { // Account for colon and newline character
			D_DBG("Token in line '%s' is shorter than presented token, ignored", line);
			continue;
		}

		if(strncasecmp(s->token_id, colonpos+1, strlen(s->token_id)) == 0) { // Ignore trailing garbage, f.e. white space
			D_DBG("Token '%s' matched line '%s', succeeded", s->token_id, line);
			retval = PAM_SUCCESS;
			break;
		}
	}

abort:
	if(fh != NULL) {
		fclose(fh);
	}
	if(line != NULL) {
		memset(line, 0, line_length);
		free(line);
	}

	return retval;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval = PAM_AUTHINFO_UNAVAIL;
	struct status status;
	struct status *s = &status;
	struct pam_conv *conv;

	memset(&status, 0, sizeof(status));

	if(parse_arguments(s, argc, argv) < 0) {
		// No output, parse_arguments() does all the error reporting itself
		goto abort;
	}

	s->ctx = openkey_init();
	if(s->ctx == NULL) {
		D_ERR("Couldn't allocate a libopenkey context");
		goto abort;
	}

	if( openkey_role_add(s->ctx, OPENKEY_ROLE_CARD_AUTHENTICATOR, s->secrets_directory) < 0 ) {
		D_ERR("Couldn't add card authenticator role, secrets directory wrong?");
		goto abort;
	}

	if( openkey_authenticator_prepare(s->ctx) < 0 ) {
		D_ERR("Couldn't prepare libopenkey for card authenticator role");
		goto abort;
	}

	retval = pam_get_user(pamh, &s->username, NULL);
	if(retval != PAM_SUCCESS) {
		D_ERR("Couldn't get the authenticating user");
		goto abort;
	}

retry:
	if(!s->no_pin) {
		if(s->try_first_pass || s->use_first_pass) {
			retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&s->password);
			if(retval != PAM_SUCCESS) {
				D_ERR("Couldn't retrieve the old authentication token");
				goto abort;
			}
		}

		if(s->use_first_pass && s->password == NULL) {
			retval = PAM_AUTH_ERR;
			D_ERR("'use_first_pass' set but the previous authentication token was empty");
			goto abort;
		}

		if(s->password == NULL) {
			retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
			if(retval != PAM_SUCCESS) {
				D_ERR("Couldn't retrieve conversation function callback");
				goto abort;
			}

			const struct pam_message query[] = {
					{ PAM_PROMPT_ECHO_OFF, "Token PIN: ",},
			};
			const struct pam_message *query_pointer = query;
			struct pam_response *resp = NULL;

			retval = conv->conv(1, &query_pointer, &resp, conv->appdata_ptr);
			if(retval != PAM_SUCCESS) {
				D_ERR("Conversation function returned an error: %s", pam_strerror(pamh, retval));
				goto abort;
			}

			if(resp[0].resp == NULL) {
				D_ERR("Conversation function returned NULL response");
				goto abort;
			}

			s->password = resp[0].resp;
			s->password_needs_free = 1;
			free(resp);

		}
	}

	FreefareTag tag = NULL;
	if(helpers_first_tag(NULL, &tag) > 0) {
		do {
			if(freefare_get_tag_type(tag) != MIFARE_DESFIRE) {
				D_DBG("Token is not a DESfire card");
				continue;
			} else {
				D_DBG("Got a DESfire card");
			}

			int r;
			if(s->password == NULL || (strlen(s->password) == 0 && !s->allow_empty_pin) ) {
				r = openkey_authenticator_card_authenticate(s->ctx, tag, &s->token_id);
			} else {
				r = openkey_authenticator_card_authenticate_pw(s->ctx, tag, &s->token_id, s->password, strlen(s->password));
			}

			if(r>=0) {
				break;
			}

		} while(helpers_next_tag(NULL, &tag) > 0);
	}

	if(s->token_id != NULL) {
		if(s->any_token) {
			retval = PAM_SUCCESS;
		} else {
			retval = check_token_id(s);
		}
	} else {
		if(s->try_first_pass && !s->use_first_pass && !s->no_pin) {
			// Clear try_first_pass and go again, will trigger conversation
			D_DBG("'try_first_pass' did not work out, retrying with conversation");
			s->try_first_pass = 0;
			s->password = NULL;
			goto retry;
		} else {
			D_DBG("Authentication failed or no token presented");
			retval = PAM_AUTH_ERR;
		}
	}

abort:
	if(s->ctx != NULL) {
		openkey_fini(s->ctx);
	}
	if(s->map_file != NULL) {
		free(s->map_file);
	}
	if(s->secrets_directory != NULL) {
		free(s->secrets_directory);
	}
	if(s->token_id != NULL) {
		free(s->token_id);
	}
	if(s->password_needs_free) {
		memset((char*)s->password, 0, strlen(s->password));
		free((char*)s->password);
	}

	helpers_cleanup();

	if(s->alwaysok && retval != PAM_SUCCESS) {
		D_ERR("alwaysok needed, original return code was %i", retval);
		retval = PAM_SUCCESS;
	}

	return retval;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}


#ifdef PAM_STATIC
struct pam_module _pam_openkey_modstruct = {
  "pam_openkey",
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  NULL,
  NULL,
  NULL
};
#endif
