/*
 * nfc_helpers.c
 *
 *  Created on: 3 Feb 2013
 *      Author: henryk
 */

#include "helpers.h"

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

static nfc_connstring devices[8];
static nfc_context *context = NULL;

static size_t devices_length;
static size_t devices_index;

MifareTag *tags;
static size_t tags_index;

static nfc_device *device;

int helpers_first_tag(nfc_connstring **device_connstring, MifareTag *tag)
{
	if(context == NULL) {
		tags_index = -1;
		devices_index = -1;
		nfc_init(&context);
		if(context == NULL) {
			fprintf(stderr, "Error initializing libnfc");
			return -1;
		}
	}

	if(tags != NULL) {
		freefare_free_tags(tags);
		tags = NULL;
	}

	if(device != NULL) {
		nfc_close(device);
		device = NULL;
	}

	tags_index = 0;
	devices_index = 0;

	devices_length = nfc_list_devices(context, devices, sizeof(devices)/sizeof(devices[0]));
	if(devices_length == 0) {
		return 0;
	}


	return helpers_next_tag(device_connstring, tag);
}

int helpers_next_tag(nfc_connstring **device_connstring, MifareTag *tag)
{
	if(context == NULL) {
		return helpers_first_tag(device_connstring, tag);
	}

	if(devices_index < devices_length) for(; devices_index < devices_length; devices_index++) {
		if(device == NULL) {
			device = nfc_open(context, devices[devices_index]);
			if(tags != NULL) {
				freefare_free_tags(tags);
				tags = NULL;
				tags_index = 0;
			}
			if(device == NULL) {
				continue;
			}
		}

		if(tags == NULL) {
			tags = freefare_get_tags(device);
			if(tags == NULL) {
				return -1;
			}
		}

		while(tags[tags_index]) {
			if(device_connstring != NULL) {
				*device_connstring = devices + devices_index;
			}
			if(tag != NULL) {
				*tag = tags[tags_index];
			}
			tags_index++;
			return 1;
		}

		freefare_free_tags(tags);
		tags = NULL;
		tags_index = 0;
	}

	return 0;
}


void helpers_cleanup(void)
{
	if(tags != NULL) {
		freefare_free_tags(tags);
		tags = NULL;
	}

	if(device != NULL) {
		nfc_close(device);
		device = NULL;
	}

	if(context != NULL) {
		nfc_exit(context);
		context = NULL;
	}
}

bool helpers_confirm(void)
{
	int c;
	while( (c = getchar()) != EOF) {
		switch(c) {
		case 'y': // Fall-through
		case 'Y':
			return 1;
		case 'n':
		case 'N':
			return 0;
		}
	}
	return 0;
}

char *helpers_getpin(int repeat)
{
	char *result = NULL;
	char *tmp = NULL; // Statically allocated by getpass, do not free
	char *pin = NULL, *pin_repeat = NULL;

	tmp = getpass("PIN: ");
	if(tmp == NULL) {
		goto abort;
	}

	pin = strdup(tmp);
	if(pin == NULL) {
		goto abort;
	}
	memset(tmp, 0, strlen(tmp));

	if(repeat) {
		tmp = getpass("PIN (repeat): ");
		if(tmp == NULL) {
			goto abort;
		}
		pin_repeat = strdup(tmp);
		if(pin_repeat == NULL) {
			goto abort;
		}
		memset(tmp, 0, strlen(tmp));

		if(strlen(pin) != strlen(pin_repeat)) {
			goto abort;
		}
		if(strcmp(pin, pin_repeat) != 0) {
			goto abort;
		}
	}

	result = pin;

abort:
	if(tmp != NULL) {
		memset(tmp, 0, strlen(tmp));
	}

	if(pin_repeat != NULL) {
		memset(pin_repeat, 0, strlen(pin_repeat));
		free(pin_repeat);
	}

	if(pin != NULL && result == NULL) {
		memset(pin, 0, strlen(pin));
		free(pin);
	}
	return result;
}
