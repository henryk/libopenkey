#include "libopenkey.h"

#include <stdio.h>
#include <stdlib.h>

#include <nfc/nfc.h>

int main(int argc, char **argv) {
	openkey_context_t ctx = openkey_init();

	if(ctx == NULL) {
		fprintf(stderr, "Could not init openkey\n");
		exit(1);
	}

	if(openkey_role_add(ctx, OPENKEY_ROLE_LOCK_MANAGER, "foo") < 0) {
		fprintf(stderr, "Could not add lock manager role\n");
		exit(2);
	}

	int r = openkey_manager_bootstrap(ctx, 5);
	if(r < 0) {
		fprintf(stderr, "Could not bootstrap lock manager role\n");
		exit(3);
	} else if(r == 0) {
		printf("Lock manager bootstrapped\n");
	} else {
		printf("Lock manager was already bootstrapped\n");
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

		MifareTag *tags = freefare_get_tags(device);
		if(!tags) {
			nfc_close (device);
			fprintf(stderr, "Error while listing Mifare tags\n");
			exit(5);
		}

		for(int i = 0; tags[i]; i++) {
			if(freefare_get_tag_type(tags[i]) != DESFIRE)
				continue;

			printf("Own card result: %i\n", openkey_manager_card_own(ctx, tags[i], -1, argv[1]));
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
