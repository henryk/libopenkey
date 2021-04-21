/*
 * openkey-authenticator.c
 *
 *  Created on: 3 Feb 2013
 *      Author: henryk
 */

#include "openkey.h"
#include "helpers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static void usage(const char *prog, int usage_only)
{
	if(!usage_only) {
		fprintf(stderr, "== libopenkey card authenticator tool ==\n"
			"This program allows to authenticate NXP DESfire EV1 cards in a lock\n"
			"domain within the libopenkey framework for secure authentication.\n");
	}

	fprintf(stderr, "Usage: %s [-p] base_directory\n\n"
			"Options: \n"
			"\t-p\tAsk for and use a PIN or password in card authentication\n\n"
			"Arguments: \n"
			"\tbase_directory\tThe name of the directory in which all\n\t\t\tkeys and associated data shall be stored\n",
			prog);
}

int main(int argc, char **argv)
{
	int option;
	int use_pin = 0;

	while( (option = getopt(argc, argv, "p")) != -1 ) {
		switch(option) {
		case 'p':
			use_pin = 1;
			break;
		default:
			usage(argv[0], 0);
			return -1;
		}
	}

	if(optind+1 > argc) {
		fprintf(stderr, "Error: Need to specify the base directory\n\n");
		usage(argv[0], 1);
		return -1;
	}

	char *base_directory = argv[optind++];

	if(optind != argc) {
		fprintf(stderr, "Error: Too many arguments\n\n");
		usage(argv[0], 1);
		return -1;
	}

	int retval = -1;
	char *last_tag = NULL;
	openkey_context_t ctx = openkey_init();

	if(ctx == NULL) {
		fprintf(stderr, "Error: Couldn't initialize openkey context\n");
		goto abort;
	}

	if(openkey_role_add(ctx, OPENKEY_ROLE_CARD_AUTHENTICATOR, base_directory) < 0) {
		fprintf(stderr, "Error: Couldn't add the card authenticator role to the openkey context\n");
		goto abort;
	}

	int r = openkey_authenticator_prepare(ctx);
	if(r < 0) {
		fprintf(stderr, "Error: Couldn't prepare the card authenticator\n");
		goto abort;
	}

	FreefareTag tag = NULL;


	while(1) {
		if(helpers_first_tag(NULL, &tag) > 0) {
			do {
				if(freefare_get_tag_type(tag) != MIFARE_DESFIRE) {
					continue;
				}

				char *card_id = NULL;
				char *pin = NULL;

				if(use_pin) {
					pin = helpers_getpin(0);
					if(pin == NULL) {
						fprintf(stderr, "Error: Couldn't get PIN\n");
					}
				}

				int r;
				if(pin == NULL) {
					r = openkey_authenticator_card_authenticate(ctx, tag, &card_id);
				} else {
					r = openkey_authenticator_card_authenticate_pw(ctx, tag, &card_id, pin, strlen(pin));
					memset(pin, 0, strlen(pin));
					free(pin);
				}

				if(r < 0) {
					if(last_tag != NULL) {
						free(last_tag);
						last_tag = NULL;
					}
				} else {
					if(last_tag == NULL || strcmp(card_id, last_tag) != 0) {
						printf("%s\n", card_id);
						if(last_tag != NULL) {
							free(last_tag);
						}
						last_tag = strdup(card_id);
					}
				}

				free(card_id);

			} while(helpers_next_tag(NULL, &tag) > 0);
		}

		const struct timespec sleeptime = {0, 100000000L}; // 0.1s
		nanosleep(&sleeptime, NULL);
	}

abort:
	if(last_tag != NULL) {
		free(last_tag);
	}
	if(ctx != NULL) {
		openkey_fini(ctx);
	}

	helpers_cleanup();

	return retval;
}
