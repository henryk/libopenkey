/*-
 * Copyright (C) 2013, Henryk Plötz
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

#include <nfc/nfc.h>

int main(void) {
	openkey_context_t ctx = openkey_init();

	if(ctx == NULL) {
		fprintf(stderr, "Could not init openkey\n");
		exit(1);
	}

	if(openkey_role_add(ctx, OPENKEY_ROLE_CARD_PRODUCER, "foo") < 0) {
		fprintf(stderr, "Could not add card producer role\n");
		exit(2);
	}

	int r = openkey_producer_bootstrap(ctx);
	if(r < 0) {
		fprintf(stderr, "Could not bootstrap card producer role\n");
		exit(3);
	} else if(r == 0) {
		printf("Card producer bootstrapped\n");
	} else {
		printf("Card producer was already bootstrapped\n");
	}


	nfc_connstring devices[8];
	nfc_context *context;
	nfc_init(&context);

	size_t device_count = nfc_list_devices(context, devices, 8);
	if(device_count <= 0) {
		fprintf(stderr, "No NFC device found\n");
		exit(4);
	}

	int didone = 0;
	for(size_t d = 0; d < device_count; d++) {
		nfc_device *device = nfc_open (context, devices[d]);
		if(!device) {
			continue;
		}

		FreefareTag *tags = freefare_get_tags(device);
		if(!tags) {
			nfc_close (device);
			fprintf(stderr, "Error while listing Mifare tags\n");
			exit(5);
		}

		for(int i = 0; tags[i]; i++) {
			if(freefare_get_tag_type(tags[i]) != MIFARE_DESFIRE)
				continue;

			printf("Make card result: %i\n", openkey_producer_card_create(ctx, tags[i], "Testtag"));
			didone = 1;

			break;
		}

		freefare_free_tags(tags);
		if(didone) {
			break;
		}
	}

	if(!didone) {
		fprintf(stderr, "No Mifare DESfire tags found\n");
	}


	nfc_exit(context);
	openkey_fini(ctx);

	return 0;
}
