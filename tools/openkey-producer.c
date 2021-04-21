/*
 * openkey-producer.c
 *
 *  Created on: 2 Feb 2013
 *      Author: henryk
 */

#include "openkey.h"
#include "helpers.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void usage(const char *prog, int usage_only)
{
	if(!usage_only) {
		fprintf(stderr, "== libopenkey card producer tool ==\n"
			"This program allows to format NXP DESfire EV1 cards for use with the\n"
			"libopenkey framework for secure authentication.\n");
	}

	fprintf(stderr, "Usage: %s [-b | [-r] -y] base_directory [card_name [card_id]]\n\n"
			"Options: \n"
			"\t-b\tOnly bootstrap the card producer, do not produce a card\n"
			"\t-y\tProduce a card and do not ask for confirmation before\n\t\tdoing so (DANGEROUS)\n"
			"\t-r\tRe-Produce a card: Erase all slots on it and produce it\n\t\tas an empty card (DANGEROUS)\n\n"
			"Arguments: \n"
			"\tbase_directory\tThe name of the directory in which all\n\t\t\tkeys and associated data shall be stored\n"
			"\tcard_name\tThe friendly name of the card to be initialized\n\t\t\tMandatory when not only bootstrapping\n"
			"\tcard_id\t\tA card identifier (old card_name or UID)\n\t\t\tOptionally used for re-production\n",
			prog);
}

int main(int argc, char **argv)
{
	int option;
	int bootstrap_only = 0;
	int no_confirmation = 0;
	int recreate = 0;

	while( (option = getopt(argc, argv, "byr")) != -1 ) {
		switch(option) {
		case 'b':
			bootstrap_only = 1;
			break;
		case 'y':
			no_confirmation = 1;
			break;
		case 'r':
			recreate = 1;
			break;
		default:
			usage(argv[0], 0);
			return -1;
		}
	}

	if(bootstrap_only && (no_confirmation || recreate)) {
		fprintf(stderr, "Error: Only bootstrapping and card production are mutually exclusive\n\n");
		usage(argv[0], 1);
		return -1;
	}

	if(optind+1 > argc) {
		fprintf(stderr, "Error: Need to specify the base directory\n\n");
		usage(argv[0], 1);
		return -1;
	}

	char *base_directory = argv[optind++];
	char *card_name = NULL;
	char *card_id = NULL;

	if(!bootstrap_only) {
		if(optind+1 > argc) {
			fprintf(stderr, "Error: Need to specify the card name\n\n");
			usage(argv[0], 1);
			return -1;
		}
		card_name = argv[optind++];
	}

	if(recreate) {
		if(optind+1 <= argc) {
			card_id = argv[optind++];
		}
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

	if(openkey_role_add(ctx, OPENKEY_ROLE_CARD_PRODUCER, base_directory) < 0) {
		fprintf(stderr, "Error: Couldn't add the card producer role to the openkey context\n");
		goto abort;
	}

	if(!openkey_producer_is_bootstrapped(ctx)) {
		printf("Note: Bootstrapping card producer role and generating secret keys\n");
		printf("\tThis may take some time ... \n");
	}

	int r = openkey_producer_bootstrap(ctx);
	if(r < 0) {
		fprintf(stderr, "Error: Couldn't bootstrap the card producer\n");
		goto abort;
	} else if(r == 0) {
		printf("Card producer was successfully bootstrapped\n");
	}

	if(bootstrap_only) {
		retval = 0;
		goto abort;
	}

	FreefareTag tag = NULL;
	retval = 0;

	if(helpers_first_tag(NULL, &tag) > 0) {
		do {
			if(freefare_get_tag_type(tag) != MIFARE_DESFIRE) {
				continue;
			}

			char *tag_uid = freefare_get_tag_uid(tag);
			const char *tag_name = freefare_get_tag_friendly_name(tag);

			printf("Found %s with UID %s", tag_name, tag_uid);
			free(tag_uid);

			bool confirm = 0;

			if(!no_confirmation) {
				printf(": %sInitialize this card for use with openkey? (y/n) ", recreate ? "Re-" : "");
				confirm = helpers_confirm();
			} else {
				printf(". ");
			}

			if(confirm || no_confirmation) {
				printf("Initializing card ...\n");
				int r = -1;

				if(recreate) {
					r = openkey_producer_card_recreate(ctx, tag, card_name, card_id);
				} else {
					r = openkey_producer_card_create(ctx, tag, card_name);
				}
				if(r < 0) {
					printf("Error while initializing card. Error code: %i\n", r);
					retval = -1;
				} else {
					printf("Card successfully initialized\n");
				}
			}

		} while(helpers_next_tag(NULL, &tag) > 0);
	} else {
		fprintf(stderr, "No card to initialize found\n");
		retval = -1;
	}

abort:
	if(ctx != NULL) {
		openkey_fini(ctx);
	}

	helpers_cleanup();

	return retval;
}
