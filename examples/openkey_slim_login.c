/*-
 * Copyright (C) 2017, Jonathan Sieber
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#include "openkey.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <xdo.h>

#include <nfc/nfc.h>

#define D_ERR(msg, ...) do{fprintf(stderr, "ERROR: %s:%i: " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); syslog(LOG_ERR, "pam_openkey: %s:%i: " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__);}while(0)
#define D_ERR_MEM D_ERR("Couldn't allocate memory")
#define D_WARN(msg, ...) do{fprintf(stderr, "Warning: %s:%i: " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); syslog(LOG_WARNING, "pam_openkey: %s:%i: " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__);}while(0)
#define D_DBG(msg, ...) do{{fprintf(stderr, "DEBUG: %s:%i: " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); syslog(LOG_DEBUG, "pam_openkey: %s:%i: " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__);}}while(0)

const char* SECRETS_PATH = "/etc/openkey_secrets";
const char* MAP_FILE = "/etc/openkey-users";

const char* XDISPLAY = ":0";
const char* XAUTHORITY = "/var/run/slim.auth";

int find_user(const char* card_id, char** username)
{
	int retval = -1;
	FILE *fh = NULL;
	char *line = NULL;
	size_t line_length = 0;

	fh = fopen(MAP_FILE, "r");
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

		/*
		if((strncasecmp(s->username, line, colonpos-line) != 0 || strlen(s->username) != colonpos-line) ) {
			D_DBG("Username '%s' doesn't match line '%s', ignored", s->username, line);
			continue;
		}
		* */

		if(strlen(colonpos) < strlen(card_id) + 1 + 1) { // Account for colon and newline character
			D_DBG("Token in line '%s' is shorter than presented token, ignored", line);
			continue;
		}

		if(strncasecmp(card_id, colonpos+1, strlen(card_id)) == 0) { // Ignore trailing garbage, f.e. white space
			D_DBG("Token '%s' matched line '%s', succeeded", card_id, line);
			*username = strdup(line);
			*strchr(*username, ':') = 0;
			//strncpy(username, line, colonpos-line);
			//username[colonpos-line] = 0;
			//pam_set_item(pamh, PAM_USER, username);
			// retval = PAM_SUCCESS;
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
/*
	FILE* file = fopen(, "rb");
			size_t read;
			char* line = 0;
			size_t len = 0;
			while ((read = getline(&line, &len, file)) >= 0) {
				char *colonpos = strchr(line, ':');
				if (strncasecmp(card_id, colonpos+1, strlen(card_id)) == 0) { // Ignore trailing garbage, f.e. white space
					char username[256];
					strncpy(username, line, colonpos-line);
					username[colonpos-line] = 0;
					printf("Identified user %s\n", username);
					break;
				}
			}
			fclose(file);

}*/

static void login_username(char* username)
{
	setenv("XAUTHORITY", XAUTHORITY, 1);
	xdo_t* xdo = xdo_new(XDISPLAY);
	if (!xdo) {
		D_ERR("Could not connect to X11 Display. Is %s readable?", XAUTHORITY);
		return;
	}
	xdo_enter_text_window(xdo, CURRENTWINDOW, username, 12000);
	//sleep(1);
	xdo_send_keysequence_window(xdo, CURRENTWINDOW, "Return", 12000000);

	xdo_free(xdo);
}

int main(int argc, char **argv) {
	openkey_context_t ctx = openkey_init();

	if(ctx == NULL) {
		fprintf(stderr, "Could not init openkey\n");
		exit(1);
	}

	if(openkey_role_add(ctx, OPENKEY_ROLE_CARD_AUTHENTICATOR, SECRETS_PATH) < 0) {
		fprintf(stderr, "Could not add card authenticator role\n");
		exit(2);
	}

	int r = openkey_authenticator_prepare(ctx);
	if(r < 0) {
		fprintf(stderr, "Could not prepare card authenticator role\n");
		exit(3);
	} else {
		printf("Card authenticator prepared\n");
	}


	nfc_connstring connstring;
	nfc_context *context;
	nfc_init(&context);

	size_t device_count = nfc_list_devices(context, &connstring, 1);
	if(device_count <= 0) {
		fprintf(stderr, "No NFC device found\n");
		exit(4);
	}

	char* username = 0;

	nfc_device *device = nfc_open (context, connstring);

	MifareTag *tags = freefare_get_tags(device);
	if(!tags) {
		nfc_close (device);
		fprintf(stderr, "Error while listing Mifare tags\n");
		exit(5);
	}

	int i;
	for(i = 0; tags[i]; i++) {
		if(freefare_get_tag_type(tags[i]) != DESFIRE)
			continue;

		char *card_id = NULL;
		int r = openkey_authenticator_card_authenticate(ctx, tags[i], &card_id);

		if(r >= 0) {
			find_user(card_id, &username);
			printf("Card authenticated: %s\n", username);
		} else {
			fprintf(stderr, "Could not authenticate card\n");
		}
		if(card_id != NULL) {
			free(card_id);
		}

		break;
	}

	freefare_free_tags(tags);

	nfc_exit(context);
	openkey_fini(ctx);

	if(username) {
		login_username(username);
		free(username);
	} else {
		fprintf(stderr, "No Mifare DESfire tags found\n");
		return 1;
	}	
	
	return 0;
}
