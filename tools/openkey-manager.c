/*
 * openkey-manager.c
 *
 *  Created on: 3 Feb 2013
 *      Author: henryk
 */

#include "openkey.h"
#include "helpers.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

static void usage(const char *prog, int usage_only)
{
	if(!usage_only) {
		fprintf(stderr, "== libopenkey lock manager tool ==\n"
			"This program allows to associate NXP DESfire EV1 cards with a lock\n"
			"domain within the libopenkey framework for secure authentication.\n");
	}

	fprintf(stderr, "Usage: %s [-b | -y [-s slot] [-p] ] base_directory [transport_file]\n\n"
			"Options: \n"
			"\t-b\tOnly bootstrap the lock manager, do not operate on a card\n"
			"\t-y\tOperate on a card and do not ask for confirmation before\n\t\tdoing so (DANGEROUS)\n"
			"\t-s slot\tThe preferred slot (%i through %i, inclusive) of this lock\n\t\tdomain. Only evaluated at first bootstrap.\n"
			"\t-p\tAsk for and use a PIN or password in card authentication\n\n"
			"Arguments: \n"
			"\tbase_directory\tThe name of the directory in which all\n\t\t\tkeys and associated data shall be stored\n"
			"\ttransport_file\tThe file containing the slot transport keys\n\t\t\tMandatory when not only bootstrapping\n",
			prog, OPENKEY_SLOT_MIN, OPENKEY_SLOT_MAX);
}

int main(int argc, char **argv)
{
	int option;
	int bootstrap_only = 0;
	int no_confirmation = 0;
	int use_pin = 0;
	int slot = -1;

	while( (option = getopt(argc, argv, "bys:p")) != -1 ) {
		switch(option) {
		case 'b':
			bootstrap_only = 1;
			break;
		case 'y':
			no_confirmation = 1;
			break;
		case 'p':
			use_pin = 1;
			break;
		case 's':
			{
				char *end;
				slot = strtol(optarg, &end, 10);
				if(!(optarg[0] != 0 && end[0] == 0) || !(slot == -1 || (slot >= OPENKEY_SLOT_MIN && slot <= OPENKEY_SLOT_MAX) )) {
					fprintf(stderr, "Error: -s Option must be an integer between %i and %i (inclusive), or -1\n\n", OPENKEY_SLOT_MIN, OPENKEY_SLOT_MAX);
					usage(argv[0], 1);
					return -1;
				}
			}
			break;
		default:
			usage(argv[0], 0);
			return -1;
		}
	}

	if(bootstrap_only && (no_confirmation || use_pin)) {
		fprintf(stderr, "Error: Only bootstrapping and card operation without confirmation or with PIN are mutually exclusive\n\n");
		usage(argv[0], 1);
		return -1;
	}

	if(optind+1 > argc) {
		fprintf(stderr, "Error: Need to specify the base directory\n\n");
		usage(argv[0], 1);
		return -1;
	}

	char *base_directory = argv[optind++];
	char *transport_key_file = NULL;

	if(!bootstrap_only) {
		if(optind+1 > argc) {
			fprintf(stderr, "Error: Need to specify the transport key file name\n\n");
			usage(argv[0], 1);
			return -1;
		}
		transport_key_file = argv[optind++];
	}

	if(optind != argc) {
		fprintf(stderr, "Error: Too many arguments\n\n");
		usage(argv[0], 1);
		return -1;
	}

	int retval = -1;
	openkey_context_t ctx = openkey_init();

	if(ctx == NULL) {
		fprintf(stderr, "Error: Couldn't initialize openkey context\n");
		goto abort;
	}

	if(openkey_role_add(ctx, OPENKEY_ROLE_LOCK_MANAGER, base_directory) < 0) {
		fprintf(stderr, "Error: Couldn't add the lock manager role to the openkey context\n");
		goto abort;
	}

	if(!openkey_manager_is_bootstrapped(ctx)) {
		printf("Note: Bootstrapping lock manager role and generating secret keys\n");
		printf("\tThis may take some time ... \n");
	}

	int r = openkey_manager_bootstrap(ctx, slot);
	if(r < 0) {
		fprintf(stderr, "Error: Couldn't bootstrap the lock manager\n");
		goto abort;
	} else if(r == 0) {
		printf("Lock manager was successfully bootstrapped\n");
	}

	if(bootstrap_only) {
		retval = 0;
		goto abort;
	}

	MifareTag tag = NULL;
	retval = 0;

	if(helpers_first_tag(NULL, &tag) > 0) {
		do {
			if(freefare_get_tag_type(tag) != DESFIRE) {
				continue;
			}

			char *tag_uid = freefare_get_tag_uid(tag);
			const char *tag_name = freefare_get_tag_friendly_name(tag);

			printf("Found %s with UID %s", tag_name, tag_uid);
			free(tag_uid);

			bool confirm = 0;

			if(!no_confirmation) {
				printf(": Try to associate this card with this lock domain? (y/n) ");
				confirm = helpers_confirm();
			} else {
				printf(". ");
			}

			if(confirm || no_confirmation) {
				char *pin = NULL;
				if(use_pin) {
					pin = helpers_getpin(1);
					if(pin == NULL) {
						fprintf(stderr, "Error getting PIN, aborting\n");
						retval = -1;
						goto abort;
					}
				}

				printf("Associating card ...\n");

				int r;
				if(pin == NULL) {
					r = openkey_manager_card_own(ctx, tag, slot, transport_key_file);
				} else {
					r = openkey_manager_card_own_pw(ctx, tag, slot, transport_key_file, pin, strlen(pin));
					memset(pin, 0, strlen(pin));
					free(pin);
				}

				if(r < 0) {
					printf("Error while operating on card. Error code: %i\n", r);
					retval = -1;
				} else {
					printf("Card successfully associated\n");
				}
			}

		} while(helpers_next_tag(NULL, &tag) > 0);
	} else {
		fprintf(stderr, "No card to associate found\n");
		retval = -1;
	}

abort:
	if(ctx != NULL) {
		openkey_fini(ctx);
	}

	helpers_cleanup();

	return retval;
}
