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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>

#include <gcrypt.h>
#include <uuid/uuid.h>

static const char * const OPENKEY_PRODUCER_MAGIC_V1 = "libopenkey producer secret key storage v1";
static const char * const OPENKEY_LOCK_MAGIC_V1 = "libopenkey lock secret key storage v1";
static const char * const OPENKEY_TRANSPORT_MAGIC_V1 = "libopenkey transport key file v1";

static const char * const PATH_SEPARATOR = "/";

#define OPENKEY_INITIAL_APPLICATION_SETTINGS 0x9
#define OPENKEY_FINAL_APPLICATION_SETTINGS 0xE0
#define OPENKEY_FINAL_PICC_SETTINGS 0x08
#define OPENKEY_INITIAL_FILE_SETTINGS 0x0000
#define OPENKEY_FINAL_FILE_SETTINGS 0x1FFF

#define SLOT_MASK_DATA_TYPE uint16_t

#define AES_KEY_LENGTH 16
#define AES_KEY_LINE_LENGTH  (2*(AES_KEY_LENGTH*3)) /* Includes some allowance for editing and extra spaces */
#define MAX_KEY_LENGTH 24
#define UUID_STRING_LENGTH 36

#define MASTER_AID 0x0

#define ROLEMASK(x) (1<<(x))

struct openkey_context {
	uint8_t roles_initialized;

	struct {
		char *producer_path;
		int bootstrapped;

		uint8_t master_key[AES_KEY_LENGTH];
	} p;

	struct {
		char *manager_path;
		int bootstrapped;

		struct lock_data {
			int slot_list[16 + 1];
			size_t slot_list_length;

			uint8_t read_key[AES_KEY_LENGTH];
			uint8_t master_authentication_key[AES_KEY_LENGTH];
		} l;
	} m;

	struct {
		char *authenticator_path;
		int prepared;

		struct lock_data l;
	} a;
};

struct card_data {
	char *card_name;
	uint8_t uid[10];
	size_t uid_length;

	enum desfire_authentication_type {
		DESFIRE_AUTHENTICATION_TYPE_DES,
		DESFIRE_AUTHENTICATION_TYPE_3DES,
		DESFIRE_AUTHENTICATION_TYPE_AES,
	} old_desfire_authentication_type;
	uint8_t old_master_key[MAX_KEY_LENGTH];

	uint8_t picc_master_key[AES_KEY_LENGTH];

	struct openkey_application {
		uint8_t old_app_key[AES_KEY_LENGTH];

		uuid_t app_uuid;
		uint8_t app_master_key[AES_KEY_LENGTH];
		uint8_t app_transport_read_key[AES_KEY_LENGTH];
		uint8_t app_transport_authentication_key[AES_KEY_LENGTH];
	} app[15];
};

struct transport_key_data {
	char *card_name;
	uuid_t app_uuid;
	uint8_t app_transport_read_key[AES_KEY_LENGTH];
	uint8_t app_transport_authentication_key[AES_KEY_LENGTH];
};

openkey_context_t openkey_init()
{
	if(!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
		if(!gcry_check_version(NULL)) {
			return NULL;
		}
	}

	struct openkey_context *retval = gcry_calloc_secure(1, sizeof(*retval));
	if(retval == NULL) {
		return NULL;
	}

	return retval;
}

int openkey_fini(openkey_context_t ctx)
{
	if(ctx == NULL) {
		return -1;
	}

	if(ctx->p.producer_path != NULL) free(ctx->p.producer_path);
	if(ctx->m.manager_path != NULL) free(ctx->m.manager_path);
	if(ctx->a.authenticator_path != NULL) free(ctx->a.authenticator_path);

	memset(ctx, 0, sizeof(*ctx));
	gcry_free(ctx);

	return 0;
}

static int _add_producer(openkey_context_t ctx, const char *base_path);
static int _add_manager(openkey_context_t ctx, const char *base_path);
static int _add_authenticator(openkey_context_t ctx, const char *base_path);

int openkey_role_add(openkey_context_t ctx, enum openkey_role role, const char *private_base_path)
{
	if(ctx == NULL) {
		return -1;
	}

	if(private_base_path == NULL) {
		return -4;
	}

	if(ctx->roles_initialized & ROLEMASK(role)) {
		return -2;
	}

	switch(role) {
	case OPENKEY_ROLE_CARD_PRODUCER:
		return _add_producer(ctx, private_base_path);
		break;
	case OPENKEY_ROLE_LOCK_MANAGER:
		return _add_manager(ctx, private_base_path);
		break;
	case OPENKEY_ROLE_CARD_AUTHENTICATOR:
		return _add_authenticator(ctx, private_base_path);
		break;
	default:
		return -3;
	}
}

static char *_serialize_key(const uint8_t *key, size_t key_length)
{
	size_t serialized_length = key_length * 3;
	char *serialized = gcry_malloc_secure(serialized_length);
	if(serialized == NULL) {
		return NULL;
	}

	for(size_t i=0; i<key_length; i++) {
		uint8_t b = key[i] >> 4;
		serialized[ i*3 ] = (b < 0xa) ? (b + '0') : ((b-0xa) + 'A');
		b = key[i] & 0xf;
		serialized[ i*3 + 1 ] = (b < 0xa) ? (b + '0') : ((b-0xa) + 'A');

		if(i == key_length-1) {
			serialized[ i*3 + 2 ] = 0;
		} else {
			serialized[ i*3 + 2 ] = ' ';
		}
	}

	return serialized;
}

static int _unserialize_key(const char *input, uint8_t *output, size_t output_length)
{
	size_t inpos = 0, outpos = 0;
	uint8_t b = 0;

	if(input[inpos] != 0) {
		do {
			int nibble = -1;

			if(input[inpos] >= '0' && input[inpos] <= '9') {
				nibble = input[inpos] - '0';
			} else if(input[inpos] >= 'A' && input[inpos] <= 'F') {
				nibble = input[inpos] - 'A' + 0xa;
			} else if(input[inpos] >= 'a' && input[inpos] <= 'f') {
				nibble = input[inpos] - 'a' + 0xa;
			}

			if(nibble != -1) {
				b = (b<<4) | nibble;
				if(outpos % 2 == 1) {
					output[outpos/2] = b;
					b = 0;
				}
				outpos++;
			}

		} while(input[++inpos] != 0);
	}

	if(outpos == 2*output_length) {
		return 0;
	} else {
		return -1;
	}
}

static int _read_key(FILE *fh, uint8_t *key, size_t key_length)
{
	int retval = -1;
	size_t buf_length = AES_KEY_LINE_LENGTH;

	char *buf = gcry_malloc_secure(buf_length);
	if(buf == NULL) {
		goto abort;
	}

	if(fgets(buf, buf_length, fh) == NULL) {
		goto abort;
	}

	if(_unserialize_key(buf, key, key_length) < 0) {
		goto abort;
	}

	retval = 0;

abort:
	if(buf != NULL) {
		memset(buf, 0, buf_length);
		gcry_free(buf);
	}
	return retval;
}

static char *_concat_paths(const char *a, const char *b)
{
	if(a == NULL || b == NULL) {
		return NULL;
	}

	size_t path_length = strlen(a) + strlen(PATH_SEPARATOR) + strlen(b) + 1;
	char *path = malloc( path_length );
	if(path == NULL) {
		return NULL;
	}

	path[0] = 0;
	strncat(path, a, path_length);
	strncat(path, PATH_SEPARATOR, path_length);
	strncat(path, b, path_length);

	return path;
}

static FILE *_fopen_in_dir(const char *dir, const char *file, const char *mode, mode_t mask)
{
	char *file_path = _concat_paths(dir, file);

	if(file_path == NULL) {
		return NULL;
	}

	mode_t oldmask = umask(mask);
	FILE *retval = fopen(file_path, mode);
	free(file_path);
	umask(oldmask);

	return retval;
}

static int _unlink_in_dir(const char *dir, const char *file)
{
	char *file_path = _concat_paths(dir, file);
	if(file_path == NULL) {
		return -1;
	}

	int retval = unlink(file_path);
	free(file_path);

	return retval;
}

static int _ensure_directory(const char *dirname)
{
	struct stat statbuf;
	memset(&statbuf, 0, sizeof(statbuf));

	if(stat(dirname, &statbuf) >= 0 && S_ISDIR(statbuf.st_mode)) {
		return 0;
	} else {
		if(mkdir(dirname, S_IRUSR|S_IWUSR|S_IXUSR | S_IXGRP) < 0) {
			return -1;
		} else {
			return 0;
		}
	}
}

static int _add_producer(openkey_context_t ctx, const char *base_path)
{
	if(_ensure_directory(base_path) < 0) {
		return -0x10;
	}

	ctx->p.producer_path = strdup(base_path);


	FILE *producer_store = _fopen_in_dir(ctx->p.producer_path, "producer", "r", 0);
	char *buf = NULL;
	size_t buf_length = 0;
	int retval = -0x11;

	if(producer_store != NULL) {
		size_t r = getline(&buf, &buf_length, producer_store);

		if( (r < 0) || (r < strlen(OPENKEY_PRODUCER_MAGIC_V1)+1) || (buf_length < strlen(OPENKEY_PRODUCER_MAGIC_V1)) ) {
			goto abort;
		}
		if(strncmp(buf, OPENKEY_PRODUCER_MAGIC_V1, strlen(OPENKEY_PRODUCER_MAGIC_V1)) != 0) {
			goto abort;
		}

		if(_read_key(producer_store, ctx->p.master_key, sizeof(ctx->p.master_key)) < 0) {
			goto abort;
		}

		ctx->p.bootstrapped = 1;
	}

	ctx->roles_initialized |= ROLEMASK(OPENKEY_ROLE_CARD_PRODUCER);
	retval = 0;

abort:
	if(producer_store != NULL) {
		fclose(producer_store);
	}

	if(buf != NULL) {
		memset(buf, 0, buf_length);
		free(buf);
	}

	if(!ctx->p.bootstrapped) {
		memset(ctx->p.master_key, 0, sizeof(ctx->p.master_key));
	}

	return retval;
}

static int _load_lock_data(struct lock_data *ld, const char *path)
{
	FILE *lock_store = _fopen_in_dir(path, "lock", "r", 0);
	char *buf = NULL;
	size_t buf_length = 0;
	int retval = -1;

	if(lock_store != NULL) {
		size_t r = getline(&buf, &buf_length, lock_store);

		if( (r < 0) || (r < strlen(OPENKEY_LOCK_MAGIC_V1)+1) || (buf_length < strlen(OPENKEY_LOCK_MAGIC_V1)) ) {
			goto abort;
		}
		if(strncmp(buf, OPENKEY_LOCK_MAGIC_V1, strlen(OPENKEY_LOCK_MAGIC_V1)) != 0) {
			goto abort;
		}

		r = getline(&buf, &buf_length, lock_store);
		if(r < 0) {
			goto abort;
		}

		ld->slot_list_length = 0;
		char *strtol_begin = buf;
		while(ld->slot_list_length < (sizeof(ld->slot_list)/sizeof(ld->slot_list[0]))) {
			char *strtol_end = NULL;

			int value = strtol(strtol_begin, &strtol_end, 0);

			if(strtol_begin == strtol_end) {
				break;
			}

			if(value != -1 && (value < OPENKEY_SLOT_MIN || value > OPENKEY_SLOT_MAX)) {
				goto abort;
			}

			ld->slot_list[ld->slot_list_length++] = value;

			strtol_begin = strtol_end;
		}

		if(ld->slot_list_length == 0) {
			ld->slot_list[0] = -1;
			ld->slot_list_length = 1;
		}

		if(_read_key(lock_store, ld->read_key, sizeof(ld->read_key)) < 0) {
			goto abort;
		}

		if(_read_key(lock_store, ld->master_authentication_key, sizeof(ld->master_authentication_key)) < 0) {
			goto abort;
		}

		retval = 1;
	} else {
		retval = 0;
	}

abort:
	if(lock_store != NULL) {
		fclose(lock_store);
	}

	if(buf != NULL) {
		memset(buf, 0, buf_length);
		free(buf);
	}

	if(retval <= 0) {
		ld->slot_list_length = 0;
		memset(ld->read_key, 0, sizeof(ld->read_key));
		memset(ld->master_authentication_key, 0, sizeof(ld->master_authentication_key));
	}

	return retval;
}


static int _add_manager(openkey_context_t ctx, const char *base_path)
{
	if(_ensure_directory(base_path) < 0) {
		return -0x10;
	}

	ctx->m.manager_path = strdup(base_path);

	int r = _load_lock_data(&ctx->m.l, ctx->m.manager_path);
	int retval = -0x11;

	if(r == 1) {
		ctx->m.bootstrapped = 1;
	} else if(r < 0) {
		goto abort;
	}

	ctx->roles_initialized |= ROLEMASK(OPENKEY_ROLE_LOCK_MANAGER);
	retval = 0;

abort:

	return retval;
}

static int _add_authenticator(openkey_context_t ctx, const char *base_path)
{
	if(_ensure_directory(base_path) < 0) {
		return -0x10;
	}

	ctx->a.authenticator_path = strdup(base_path);

	int r = _load_lock_data(&ctx->a.l, ctx->a.authenticator_path);
	int retval = -0x11;

	if(r == 1) {
		ctx->a.prepared = 1;
	} else if(r < 0) {
		goto abort;
	}

	ctx->roles_initialized |= ROLEMASK(OPENKEY_ROLE_CARD_AUTHENTICATOR);
	retval = 0;

abort:

	return retval;
}

bool openkey_producer_is_bootstrapped(openkey_context_t ctx)
{
	if(ctx == NULL || !(ctx->roles_initialized & ROLEMASK(OPENKEY_ROLE_CARD_PRODUCER))) {
		return 0;
	}

	return ctx->p.bootstrapped;
}

int openkey_producer_bootstrap(openkey_context_t ctx)
{
	if(ctx == NULL || !(ctx->roles_initialized & ROLEMASK(OPENKEY_ROLE_CARD_PRODUCER))) {
		return -1;
	}

	if(ctx->p.bootstrapped) {
		return 1;
	}

	gcry_randomize(ctx->p.master_key, sizeof(ctx->p.master_key), GCRY_VERY_STRONG_RANDOM);

	FILE *fh = NULL;
	char *serialized_key = NULL;
	int retval = -1;
	fh = _fopen_in_dir(ctx->p.producer_path, "producer", "w", S_IRWXG | S_IRWXO);

	if(fh == NULL) {
		goto abort;
	}

	serialized_key = _serialize_key(ctx->p.master_key, sizeof(ctx->p.master_key));
	if(serialized_key == NULL) {
		goto abort;
	}

	int written = fprintf(fh, "%s\n%s\n", OPENKEY_PRODUCER_MAGIC_V1, serialized_key);
	if(written < strlen(OPENKEY_PRODUCER_MAGIC_V1) + 1 + strlen(serialized_key) + 1) {
		goto abort;
	}

	retval = 0;
	ctx->p.bootstrapped = 1;

abort:
	if(serialized_key != NULL) {
		memset(serialized_key, 0, strlen(serialized_key));
		gcry_free(serialized_key);
	}

	if(fh != NULL) {
		fclose(fh);
	}

	if(retval < 0) {
		memset(ctx->p.master_key, 0, sizeof(ctx->p.master_key));
		_unlink_in_dir(ctx->p.producer_path, "producer");
	}

	return retval;
}

bool openkey_manager_is_bootstrapped(openkey_context_t ctx)
{
	if(ctx == NULL || !(ctx->roles_initialized & ROLEMASK(OPENKEY_ROLE_LOCK_MANAGER))) {
		return 0;
	}

	return ctx->m.bootstrapped;
}

int openkey_manager_bootstrap(openkey_context_t ctx, int preferred_slot)
{
	if(ctx == NULL || !(ctx->roles_initialized & ROLEMASK(OPENKEY_ROLE_LOCK_MANAGER))) {
		return -1;
	}

	if(ctx->m.bootstrapped) {
		return 1;
	}

	if(preferred_slot == -1) {
		ctx->m.l.slot_list[0] = preferred_slot;
		ctx->m.l.slot_list_length = 1;
	} else if(preferred_slot >= OPENKEY_SLOT_MIN && preferred_slot <= OPENKEY_SLOT_MAX) {
		ctx->m.l.slot_list[0] = preferred_slot;
		ctx->m.l.slot_list[1] = -1;
		ctx->m.l.slot_list_length = 2;
	} else {
		return -1;
	}

	gcry_randomize(ctx->m.l.read_key, sizeof(ctx->m.l.read_key), GCRY_VERY_STRONG_RANDOM);
	gcry_randomize(ctx->m.l.master_authentication_key, sizeof(ctx->m.l.master_authentication_key), GCRY_VERY_STRONG_RANDOM);

	FILE *fh = NULL;
	char *serialized_authentication_key = NULL, *serialized_read_key = NULL;
	int retval = -1;
	fh = _fopen_in_dir(ctx->m.manager_path, "lock", "w", S_IRWXG | S_IRWXO);

	if(fh == NULL) {
		goto abort;
	}

	serialized_authentication_key = _serialize_key(ctx->m.l.master_authentication_key, sizeof(ctx->m.l.master_authentication_key));
	if(serialized_authentication_key == NULL) {
		goto abort;
	}

	serialized_read_key = _serialize_key(ctx->m.l.read_key, sizeof(ctx->m.l.read_key));
	if(serialized_read_key == NULL) {
		goto abort;
	}

	int written = fprintf(fh, "%s\n", OPENKEY_LOCK_MAGIC_V1);
	if(written < strlen(OPENKEY_LOCK_MAGIC_V1) + 1) {
		goto abort;
	}

	for(int i=0; i<ctx->m.l.slot_list_length; i++) {
		written = fprintf(fh, (i==0) ? "%i" : " %i", ctx->m.l.slot_list[i]);
		if(written <= 0) {
			goto abort;
		}
	}

	written = fprintf(fh, "\n");
	if(written != 1) {
		goto abort;
	}

	written = fprintf(fh, "%s\n%s\n", serialized_read_key, serialized_authentication_key);
	if(written < strlen(serialized_read_key) + 1 + strlen(serialized_authentication_key) + 1) {
		goto abort;
	}

	retval = 0;
	ctx->m.bootstrapped = 1;

abort:
	if(serialized_authentication_key != NULL) {
		memset(serialized_authentication_key, 0, strlen(serialized_authentication_key));
		gcry_free(serialized_authentication_key);
	}

	if(serialized_read_key != NULL) {
		memset(serialized_read_key, 0, strlen(serialized_read_key));
		gcry_free(serialized_read_key);
	}

	if(fh != NULL) {
		fclose(fh);
	}

	if(retval < 0) {
		memset(ctx->m.l.read_key, 0, sizeof(ctx->m.l.read_key));
		memset(ctx->m.l.master_authentication_key, 0, sizeof(ctx->m.l.master_authentication_key));
		_unlink_in_dir(ctx->m.manager_path, "lock");
	}

	return retval;

}

int openkey_authenticator_prepare(openkey_context_t ctx)
{
	if(ctx == NULL || !(ctx->roles_initialized & ROLEMASK(OPENKEY_ROLE_CARD_AUTHENTICATOR))) {
		return -1;
	}

	if(ctx->a.prepared) {
		return 1;
	}

	return -1;
}

#define HMAC_ALGORITHM GCRY_MD_SHA256
int openkey_kdf(const uint8_t *master_key, size_t master_key_length, uint32_t aid, uint8_t key_no,
		const uint8_t *data, size_t data_length,
		uint8_t *derived_key, size_t derived_key_length)
{
	int retval = -1;
	gcry_md_hd_t md = NULL;

	if(derived_key_length > gcry_md_get_algo_dlen(HMAC_ALGORITHM)) {
		goto abort;
	}

	if(master_key == NULL || derived_key == NULL) {
		goto abort;
	}

	if(data == NULL && data_length != 0) {
		goto abort;
	}

	int r = gcry_md_open(&md, HMAC_ALGORITHM, GCRY_MD_FLAG_SECURE|GCRY_MD_FLAG_HMAC);
	if(r) {
		goto abort;
	}

	r = gcry_md_setkey(md, master_key, master_key_length);
	if(r) {
		goto abort;
	}

	gcry_md_putc(md, (aid >> 0)&0xff);
	gcry_md_putc(md, (aid >> 8)&0xff);
	gcry_md_putc(md, (aid >> 16)&0xff);

	gcry_md_putc(md, key_no);

	if(data != NULL) {
		gcry_md_write(md, data, data_length);
	}

	gcry_md_final(md);

	memcpy(derived_key, gcry_md_read(md, HMAC_ALGORITHM), derived_key_length);

	retval = 0;

abort:
	if(md != NULL) {
		gcry_md_close(md);
	}
	return retval;
}

static char *_sanitize_card_name(const char *card_name)
{
	if(card_name == NULL) {
		return NULL;
	}

	size_t card_name_length = strlen(card_name) + 1;
	char *result = malloc(card_name_length);
	if(result == NULL) {
		return NULL;
	}

	for(int i=0; i<card_name_length-1; i++) {
		if( (card_name[i] >= 'a' && card_name[i] <= 'z')
				|| (card_name[i] >= 'A' && card_name[i] <= 'Z')
				|| (card_name[i] >= '0' && card_name[i] <= '9')
				|| card_name[i] == '-' || card_name[i] == '_' ) {
			result[i] = card_name[i];
		} else {
			result[i] = '_';
		}
	}
	result[card_name_length - 1] = 0;

	return result;
}

#define DO_ABORT(x) { retval = x; goto abort; }
int openkey_producer_card_create(openkey_context_t ctx, MifareTag tag, const char *card_name)
{
	int retval = -1;
	struct card_data *cd = NULL;
	struct mifare_desfire_version_info version_info;
	char *card_path = NULL, *app_name = NULL;
	char *serialized_key = NULL;
	FILE *app_file = NULL;
	FILE *log_file = NULL;
	MifareDESFireAID aid = NULL;
	MifareDESFireKey old_key = NULL, picc_master_key = NULL, old_app_key = NULL;
	MifareDESFireKey app_master_key = NULL, app_transport_read_key = NULL, app_transport_authentication_key = NULL;

	if(ctx == NULL || tag == NULL || !ctx->p.bootstrapped) {
		return -1;
	}

	cd = gcry_calloc_secure(1, sizeof(*cd));
	if(cd == NULL)
		DO_ABORT(-2)

	cd->card_name = _sanitize_card_name(card_name);
	if(cd->card_name == NULL)
		DO_ABORT(-3)

	/* 0th connect */
	int r = mifare_desfire_connect(tag);
	if(r < 0)
		DO_ABORT(-4);

	/* 1st read UID */
	r = mifare_desfire_get_version(tag, &version_info);
	if(r < 0)
		DO_ABORT(-5);

	uint8_t zero_uid[7] = {0};
	assert(sizeof(zero_uid) == sizeof(version_info.uid));
	if(memcmp(version_info.uid, zero_uid, sizeof(zero_uid)) == 0)
		DO_ABORT(-6); /* Random UID is already enabled */

	memcpy(cd->uid, version_info.uid, sizeof(version_info.uid));
	cd->uid_length = sizeof(version_info.uid);

	/* 2nd derive all derived keys */
	r = openkey_kdf(ctx->p.master_key, sizeof(ctx->p.master_key), MASTER_AID, 0x00, cd->uid, cd->uid_length,
			cd->picc_master_key, sizeof(cd->picc_master_key));
	if(r  < 0 )
		DO_ABORT(-7);

	for(int slot = OPENKEY_SLOT_MIN; slot <= OPENKEY_SLOT_MAX; slot++) {
		r = openkey_kdf(ctx->p.master_key, sizeof(ctx->p.master_key), OPENKEY_BASE_AID + slot, 0x00, cd->uid, cd->uid_length,
				cd->app[slot].app_master_key, sizeof(cd->app[slot].app_master_key));
		if(r  < 0 )
			DO_ABORT(-8);
	}

	/* 3rd generate the UUIDs and transport keys */
	for(int slot = OPENKEY_SLOT_MIN; slot <= OPENKEY_SLOT_MAX; slot++) {
		uuid_generate(cd->app[slot].app_uuid);
		gcry_randomize(cd->app[slot].app_transport_authentication_key, sizeof(cd->app[slot].app_transport_authentication_key), GCRY_STRONG_RANDOM);
		gcry_randomize(cd->app[slot].app_transport_read_key, sizeof(cd->app[slot].app_transport_read_key), GCRY_STRONG_RANDOM);
	}

	/* 4th write the card */
	switch(cd->old_desfire_authentication_type) {
	case DESFIRE_AUTHENTICATION_TYPE_DES:
		old_key = mifare_desfire_des_key_new(cd->old_master_key);
		break;
	case DESFIRE_AUTHENTICATION_TYPE_3DES:
		old_key = mifare_desfire_3des_key_new(cd->old_master_key);
		break;
	case DESFIRE_AUTHENTICATION_TYPE_AES:
		old_key = mifare_desfire_aes_key_new(cd->old_master_key);
		break;
	}
	if(old_key == NULL)
		DO_ABORT(-9);

	picc_master_key = mifare_desfire_aes_key_new(cd->picc_master_key);
	if(picc_master_key == NULL)
		DO_ABORT(-10);


	for(int slot = OPENKEY_SLOT_MIN; slot <= OPENKEY_SLOT_MAX; slot++) {
		/* 4th a) create and write each application */
		struct openkey_application *app = cd->app + slot;
		char uuid_unparsed[36 + 1];

		uuid_unparse_lower(app->app_uuid, uuid_unparsed);

		old_app_key = mifare_desfire_aes_key_new(app->old_app_key);
		app_master_key = mifare_desfire_aes_key_new(app->app_master_key);
		app_transport_read_key = mifare_desfire_aes_key_new(app->app_transport_read_key);
		app_transport_authentication_key = mifare_desfire_aes_key_new(app->app_transport_authentication_key);
		if(old_app_key == NULL || app_master_key == NULL || app_transport_read_key == NULL || app_transport_authentication_key == NULL)
			DO_ABORT(-11);

		r = mifare_desfire_select_application(tag, NULL);
		if(r < 0)
			DO_ABORT(-12);

		r = mifare_desfire_authenticate(tag, 0, old_key);
		if(r < 0)
			DO_ABORT(-13);

		aid = mifare_desfire_aid_new(OPENKEY_BASE_AID + slot);
		if(aid == NULL)
			DO_ABORT(-14);

		r = mifare_desfire_create_application_aes(tag, aid, OPENKEY_INITIAL_APPLICATION_SETTINGS, 3);
		if(r < 0)
			DO_ABORT(-15);

		r = mifare_desfire_select_application(tag, aid);
		if(r < 0)
			DO_ABORT(-16);

		free(aid); aid = NULL;

		r = mifare_desfire_authenticate_aes(tag, 0, old_app_key);
		if(r < 0)
			DO_ABORT(-17);

		r = mifare_desfire_change_key(tag, 1, app_transport_read_key, NULL);
		if(r < 0)
			DO_ABORT(-18);

		r = mifare_desfire_change_key(tag, 2, app_transport_authentication_key, NULL);
		if(r < 0)
			DO_ABORT(-19);

		r = mifare_desfire_create_std_data_file(tag, 1, MDCM_PLAIN, OPENKEY_INITIAL_FILE_SETTINGS, sizeof(uuid_unparsed)-1);
		if(r < 0)
			DO_ABORT(-20);

		r = mifare_desfire_write_data_ex(tag, 1, 0, sizeof(uuid_unparsed)-1, uuid_unparsed, MDCM_PLAIN);
		if(r < 0)
			DO_ABORT(-21);

		r = mifare_desfire_change_file_settings(tag, 1, MDCM_ENCIPHERED, OPENKEY_FINAL_FILE_SETTINGS);
		if(r < 0)
			DO_ABORT(-22);

		r = mifare_desfire_change_key(tag, 0, app_master_key, NULL);
		if(r < 0)
			DO_ABORT(-23);

		r = mifare_desfire_authenticate_aes(tag, 0, app_master_key);
		if(r < 0)
			DO_ABORT(-24);

		r = mifare_desfire_change_key_settings(tag, OPENKEY_FINAL_APPLICATION_SETTINGS);
		if(r < 0)
			DO_ABORT(-25);

		mifare_desfire_key_free(old_app_key); old_app_key = NULL;
		mifare_desfire_key_free(app_master_key); app_master_key = NULL;
		mifare_desfire_key_free(app_transport_read_key); app_transport_read_key = NULL;
		mifare_desfire_key_free(app_transport_authentication_key); app_transport_authentication_key = NULL;

	}

	/* 4th b) Change master key and PICC settings */
	r = mifare_desfire_select_application(tag, NULL);
	if(r < 0)
		DO_ABORT(-26);

	r = mifare_desfire_authenticate(tag, 0, old_key);
	if(r < 0)
		DO_ABORT(-27);

	r = mifare_desfire_change_key(tag, 0, picc_master_key, NULL);
	if(r < 0)
		DO_ABORT(-28);

	r = mifare_desfire_authenticate_aes(tag, 0, picc_master_key);
	if(r < 0)
		DO_ABORT(-29);

	r = mifare_desfire_change_key_settings(tag, OPENKEY_FINAL_PICC_SETTINGS);
	if(r < 0)
		DO_ABORT(-30);

	r = mifare_desfire_set_configuration(tag, 0, 1);
	if(r < 0)
		DO_ABORT(-31);

	/* 5th write the transport key files */
	for(int slot = OPENKEY_SLOT_MIN; slot <= OPENKEY_SLOT_MAX; slot++) {
		struct openkey_application *app = cd->app + slot;
		char uuid_unparsed[36 + 1];

		uuid_unparse_lower(app->app_uuid, uuid_unparsed);

		size_t card_path_length = strlen(ctx->p.producer_path) + strlen(PATH_SEPARATOR);
		card_path_length += cd->uid_length*2 + 1 + strlen(cd->card_name) + 1;
		size_t app_name_length = strlen(cd->card_name) + 1 + 2 + 1;

		card_path = malloc(card_path_length);
		app_name = malloc(app_name_length);
		if(card_path == NULL || app_name == NULL)
			DO_ABORT(-32);

		card_path[0] = 0;
		app_name[0] = 0;

		if( snprintf(card_path, card_path_length,
				"%s%s%02X%02X%02X%02X%02X%02X%02X-%s",
				ctx->p.producer_path, PATH_SEPARATOR,
				cd->uid[0], cd->uid[1], cd->uid[2], cd->uid[3], cd->uid[4], cd->uid[5], cd->uid[6],
				cd->card_name) >= card_path_length )
			DO_ABORT(-33);

		if(snprintf(app_name, app_name_length, "%s-%i",
				cd->card_name, slot) >= app_name_length)
			DO_ABORT(-34);

		if(_ensure_directory(card_path) < 0)
			DO_ABORT(-35);

		app_file = _fopen_in_dir(card_path, app_name, "w", S_IRWXO);
		if(app_file == NULL)
			DO_ABORT(-36);

		if(fprintf(app_file, "%s\n%s\n%s\n", OPENKEY_TRANSPORT_MAGIC_V1, cd->card_name, uuid_unparsed) < 0)
			DO_ABORT(-37);

		serialized_key = _serialize_key(app->app_transport_read_key, sizeof(app->app_transport_read_key));
		if(fprintf(app_file, "%s\n", serialized_key) < 0)
			DO_ABORT(-38);
		memset(serialized_key, 0, strlen(serialized_key));
		gcry_free(serialized_key);
		serialized_key = NULL;

		serialized_key = _serialize_key(app->app_transport_authentication_key, sizeof(app->app_transport_authentication_key));
		if(fprintf(app_file, "%s\n", serialized_key) < 0)
			DO_ABORT(-39);
		memset(serialized_key, 0, strlen(serialized_key));
		gcry_free(serialized_key);
		serialized_key = NULL;

		free(card_path); card_path = NULL;
		free(app_name); app_name = NULL;
		fclose(app_file); app_file = NULL;
	}

	log_file = _fopen_in_dir(ctx->p.producer_path, "log", "a", 0);
	if(log_file == NULL)
		DO_ABORT(-40);


	char time_buf[64] = {0};
	time_t now = time(NULL);
	struct tm tm;
	gmtime_r(&now, &tm);
	strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm);
	if(fprintf(log_file, "%s %02X%02X%02X%02X%02X%02X%02X %s\n",
			time_buf,
			cd->uid[0], cd->uid[1], cd->uid[2], cd->uid[3], cd->uid[4], cd->uid[5], cd->uid[6],
			cd->card_name) < 0)
		DO_ABORT(-41)

	retval = 0;

abort:
	mifare_desfire_disconnect(tag);

	memset(&version_info, 0, sizeof(version_info));
	if(cd != NULL) {
		if(cd->card_name != NULL) {
			free(cd->card_name);
		}
		memset(cd, 0, sizeof(*cd));
		gcry_free(cd);
	}
	if(aid != NULL) {
		free(aid);
	}
	if(card_path != NULL) {
		free(card_path);
	}
	if(app_name != NULL) {
		free(app_name);
	}
	if(serialized_key != NULL) {
		memset(serialized_key, 0, strlen(serialized_key));
		gcry_free(serialized_key);
	}
	if(app_file != NULL) {
		fclose(app_file);
	}
	if(log_file != NULL) {
		fclose(log_file);
	}

	if(old_key != NULL) {
		mifare_desfire_key_free(old_key);
	}
	if(picc_master_key != NULL) {
		mifare_desfire_key_free(picc_master_key);
	}
	if(old_app_key != NULL) {
		mifare_desfire_key_free(old_app_key);
	}

	if(app_master_key != NULL) {
		mifare_desfire_key_free(app_master_key);
	}
	if(app_transport_read_key != NULL) {
		mifare_desfire_key_free(app_transport_read_key);
	}
	if(app_transport_authentication_key != NULL) {
		mifare_desfire_key_free(app_transport_authentication_key);
	}

	return retval;
}

static struct transport_key_data *_load_transport_data(const char *file)
{
	struct transport_key_data *result = NULL;
	char *buf = NULL;
	size_t buf_length = 0;
	int error = 1;

	FILE *fh = fopen(file, "r");
	if(fh == NULL) {
		goto abort;
	}

	result = gcry_calloc_secure(1, sizeof(*result));
	if(result == NULL) {
		goto abort;
	}

	size_t r = getline(&buf, &buf_length, fh);
	if( (r < 0) || (r < strlen(OPENKEY_TRANSPORT_MAGIC_V1)+1) || (buf_length < strlen(OPENKEY_TRANSPORT_MAGIC_V1)) ) {
		goto abort;
	}
	if(strncmp(buf, OPENKEY_TRANSPORT_MAGIC_V1, strlen(OPENKEY_TRANSPORT_MAGIC_V1)) != 0) {
		goto abort;
	}

	r = getline(&buf, &buf_length, fh);
	if(r < 0) {
		goto abort;
	}

	result->card_name = _sanitize_card_name(buf);
	if(result->card_name == NULL) {
		goto abort;
	}

	r = getline(&buf, &buf_length, fh);
	if(r < 0) {
		goto abort;
	}

	if(buf_length < UUID_STRING_LENGTH) {
		goto abort;
	}
	buf[UUID_STRING_LENGTH] = 0;

	if(uuid_parse(buf, result->app_uuid) < 0) {
		goto abort;
	}

	if( _read_key(fh, result->app_transport_read_key, sizeof(result->app_transport_read_key)) < 0) {
		goto abort;
	}

	if( _read_key(fh, result->app_transport_authentication_key, sizeof(result->app_transport_authentication_key)) < 0) {
		goto abort;
	}

	error = 0;

abort:
	if(error) {
		if(result->card_name != NULL) {
			free(result->card_name);
		}
		gcry_free(result);
		result = NULL;
	}

	if(buf != NULL) {
		memset(buf, 0, buf_length);
		free(buf);
	}

	if(fh != NULL) {
		fclose(fh);
	}

	return result;
}

static int _do_own_slot(openkey_context_t ctx, MifareTag tag, int slot, struct transport_key_data *td)
{
	/* Note: As of 2013-02-02 mifare_desfire_read_ex() with cipher/mac has a bug in that it will
	 * need a buffer that is large enough to hold both the payload data and mac/padding. So we'll
	 * allocate a larger buffer here and use UUID_STRING_LENGTH explicitly.
	 */
	char uuid_buffer[UUID_STRING_LENGTH + 2*16 + 1];
	int retval = -1;
	uuid_t app_uuid;
	MifareDESFireAID aid = mifare_desfire_aid_new(OPENKEY_BASE_AID + slot);
	MifareDESFireKey transport_read_key = NULL, transport_authentication_key = NULL;
	MifareDESFireKey read_key = NULL, authentication_key = NULL;
	size_t derived_authentication_key_length = AES_KEY_LENGTH;
	uint8_t *derived_authentication_key = NULL;

	if(aid == NULL) {
		goto abort;
	}

	int r = mifare_desfire_select_application(tag, aid);
	if(r < 0) {
		goto abort;
	}

	transport_read_key = mifare_desfire_aes_key_new(td->app_transport_read_key);
	if(transport_read_key == NULL) {
		goto abort;
	}

	r = mifare_desfire_authenticate_aes(tag, 1, transport_read_key);
	if(r < 0) {
		goto abort;
	}

	memset(uuid_buffer, 0, sizeof(uuid_buffer));
	if( mifare_desfire_read_data_ex(tag, 1, 0, UUID_STRING_LENGTH, uuid_buffer, MDCM_ENCIPHERED) != UUID_STRING_LENGTH) {
		goto abort;
	}

	uuid_buffer[UUID_STRING_LENGTH] = 0;

	if(uuid_parse(uuid_buffer, app_uuid) < 0) {
		goto abort;
	}

	if(uuid_compare(app_uuid, td->app_uuid) != 0) {
		goto abort;
	}

	derived_authentication_key = gcry_calloc_secure(1, derived_authentication_key_length);
	if(derived_authentication_key == NULL) {
		goto abort;
	}

	memset(uuid_buffer, 0, sizeof(uuid_buffer));
	uuid_unparse_lower(td->app_uuid, uuid_buffer);

	r = openkey_kdf(ctx->m.l.master_authentication_key, sizeof(ctx->m.l.master_authentication_key),
			mifare_desfire_aid_get_aid(aid), 2, (unsigned char*)uuid_buffer, UUID_STRING_LENGTH,
			derived_authentication_key, derived_authentication_key_length);
	if(r < 0) {
		goto abort;
	}

	transport_authentication_key = mifare_desfire_aes_key_new(td->app_transport_authentication_key);
	read_key = mifare_desfire_aes_key_new(ctx->m.l.read_key);
	authentication_key = mifare_desfire_aes_key_new(derived_authentication_key);

	if(transport_authentication_key == NULL || read_key == NULL || authentication_key == NULL) {
		goto abort;
	}

	if(mifare_desfire_authenticate_aes(tag, 2, transport_authentication_key) < 0) {
		goto abort;
	}

	if(mifare_desfire_change_key(tag, 2, authentication_key, NULL) < 0) {
		goto abort;
	}

	if(mifare_desfire_authenticate_aes(tag, 1, transport_read_key) < 0) {
		goto abort;
	}

	if(mifare_desfire_change_key(tag, 1, read_key, NULL) < 0) {
		goto abort;
	}

	retval = 0;

abort:
	memset(uuid_buffer, 0, sizeof(uuid_buffer));
	uuid_clear(app_uuid);

	if(transport_read_key != NULL) {
		mifare_desfire_key_free(transport_read_key);
	}
	if(transport_authentication_key != NULL) {
		mifare_desfire_key_free(transport_authentication_key);
	}
	if(read_key != NULL) {
		mifare_desfire_key_free(read_key);
	}
	if(authentication_key != NULL) {
		mifare_desfire_key_free(authentication_key);
	}

	if(aid != NULL) {
		free(aid);
	}

	if(derived_authentication_key != NULL) {
		memset(derived_authentication_key, 0, derived_authentication_key_length);
		gcry_free(derived_authentication_key);
	}

	return retval;
}

static int _copy_transport_file(const char *base_path, struct transport_key_data *td, const char *key_file)
{
	char *cards_path = _concat_paths(base_path, "cards");
	char uuid[UUID_STRING_LENGTH + 1];
	FILE *fh_in = NULL, *fh_out = NULL;
	int retval = -1;
	if(cards_path == NULL) {
		goto abort;
	}

	if(_ensure_directory(cards_path) < 0) {
		goto abort;
	}

	memset(uuid, 0, sizeof(uuid));
	uuid_unparse_lower(td->app_uuid, uuid);

	fh_in = fopen(key_file, "r");
	if(fh_in == NULL) {
		goto abort;
	}

	fh_out = _fopen_in_dir(cards_path, uuid, "w", S_IRWXG | S_IRWXO);
	if(fh_out == NULL) {
		goto abort;
	}

	uint8_t buf[1024];
	size_t buf_length = sizeof(buf);
	size_t r, w;

	while( (r=fread(buf, 1, buf_length, fh_in)) != 0 ) {
		w = fwrite(buf, 1, r, fh_out);
		if(w != r) {
			goto abort;
		}
	}

	if(feof(fh_in) && !ferror(fh_in) && !ferror(fh_out)) {
		retval = 0;
	}

abort:
	if(cards_path != NULL) {
		free(cards_path);
	}
	memset(uuid, 0, sizeof(uuid));
	if(fh_in != NULL) {
		fclose(fh_in);
	}
	if(fh_out != NULL) {
		fclose(fh_out);
	}
	return retval;
}

static int _delete_transport_file(const char *base_path, struct transport_key_data *td)
{
	char *cards_path = _concat_paths(base_path, "cards");
	char *file_path = NULL;
	char uuid[UUID_STRING_LENGTH + 1];
	int retval = -1;
	if(cards_path == NULL) {
		goto abort;
	}

	memset(uuid, 0, sizeof(uuid));
	uuid_unparse_lower(td->app_uuid, uuid);

	file_path = _concat_paths(cards_path, uuid);
	if(file_path == NULL) {
		goto abort;
	}

	retval = unlink(file_path);

abort:
	if(cards_path != NULL) {
		free(cards_path);
	}
	if(file_path != NULL) {
		free(file_path);
	}
	memset(uuid, 0, sizeof(uuid));
	return retval;
}

int openkey_manager_card_own(openkey_context_t ctx, MifareTag tag, int slot, const char *key_file)
{
	if(ctx == NULL || tag == NULL || !ctx->m.bootstrapped) {
		return -1;
	}

	int retval = -1;
	struct transport_key_data *td = NULL;

	td = _load_transport_data(key_file);
	if(td == NULL)
		DO_ABORT(-2);

	if(_copy_transport_file(ctx->m.manager_path, td, key_file) < 0)
		DO_ABORT(-3);

	if(mifare_desfire_connect(tag) < 0)
		DO_ABORT(-4);

	if(slot == -1) {
		SLOT_MASK_DATA_TYPE slots_tried = 0;
		/* 1st: Try to deduce the slot name from the file name */
		char *s = strrchr(key_file, '-');
		if(s != NULL) {
			s++;
			char *end = NULL;
			int slot = strtol(s, &end, 10);
			if(s[0] != 0 && end[0] == 0) {
				slots_tried |= 1<<slot;

				int r = _do_own_slot(ctx, tag, slot, td);
				if(r >= 0) {
					retval = r;
					slots_tried = ~0;
				}
			}
		}

		/* 2nd: Try to use our slot list */
		for(int i=0; i<ctx->m.l.slot_list_length; i++) {
			int slot = ctx->m.l.slot_list[i];
			if(slot == -1) {
				continue;
			}
			if(slots_tried & (1<<slot)) {
				continue;
			}
			slots_tried |= 1<<slot;

			int r = _do_own_slot(ctx, tag, slot, td);
			if(r >= 0) {
				retval = r;
				slots_tried = ~0;
				break;
			}
		}

		/* 3rd: If applicable, try the remaining slots */
		if(ctx->m.l.slot_list_length > 0 && ctx->m.l.slot_list[ctx->m.l.slot_list_length-1] == -1) {
			for(int slot = OPENKEY_SLOT_MIN; slot <= OPENKEY_SLOT_MAX; slot++) {
				if(slots_tried & (1<<slot)) {
					continue;
				}
				slots_tried |= 1<<slot;

				int r = _do_own_slot(ctx, tag, slot, td);
				if(r >= 0) {
					retval = r;
					slots_tried = ~0;
					break;
				}
			}
		}

	} else if(slot >= OPENKEY_SLOT_MIN && slot <= OPENKEY_SLOT_MAX) {
		retval = _do_own_slot(ctx, tag, slot, td);
	} else {
		goto abort;
	}

abort:
	mifare_desfire_disconnect(tag);

	if(td != NULL) {
		if(retval < 0) {
			_delete_transport_file(ctx->m.manager_path, td);
		}

		if(td->card_name != NULL)
			free(td->card_name);
		memset(td, 0, sizeof(*td));
		gcry_free(td);
	}
	return retval;
}

static int _do_authenticate_slot(openkey_context_t ctx, MifareTag tag, int slot, char **card_id)
{
	char uuid_buffer[UUID_STRING_LENGTH + 2*16 + 1];
	int retval = -1;
	uuid_t app_uuid;
	MifareDESFireAID aid = mifare_desfire_aid_new(OPENKEY_BASE_AID + slot);
	MifareDESFireKey read_key = NULL, authentication_key = NULL;
	size_t derived_authentication_key_length = AES_KEY_LENGTH;
	uint8_t *derived_authentication_key = NULL;

	if(aid == NULL)
		DO_ABORT(-1);

	int r = mifare_desfire_select_application(tag, aid);
	if(r < 0)
		DO_ABORT(-2);

	read_key = mifare_desfire_aes_key_new(ctx->a.l.read_key);
	if(read_key == NULL)
		DO_ABORT(-3);

	r = mifare_desfire_authenticate_aes(tag, 1, read_key);
	if(r < 0)
		DO_ABORT(-4);

	memset(uuid_buffer, 0, sizeof(uuid_buffer));
	if( mifare_desfire_read_data_ex(tag, 1, 0, UUID_STRING_LENGTH, uuid_buffer, MDCM_ENCIPHERED) != UUID_STRING_LENGTH)
		DO_ABORT(-5);

	uuid_buffer[UUID_STRING_LENGTH] = 0;

	if(uuid_parse(uuid_buffer, app_uuid) < 0)
		DO_ABORT(-6);

	derived_authentication_key = gcry_calloc_secure(1, derived_authentication_key_length);
	if(derived_authentication_key == NULL)
		DO_ABORT(-7);

	memset(uuid_buffer, 0, sizeof(uuid_buffer));
	uuid_unparse_lower(app_uuid, uuid_buffer);

	r = openkey_kdf(ctx->a.l.master_authentication_key, sizeof(ctx->a.l.master_authentication_key),
			mifare_desfire_aid_get_aid(aid), 2, (unsigned char*)uuid_buffer, UUID_STRING_LENGTH,
			derived_authentication_key, derived_authentication_key_length);
	if(r < 0)
		DO_ABORT(-8);

	authentication_key = mifare_desfire_aes_key_new(derived_authentication_key);
	if(authentication_key == NULL)
		DO_ABORT(-9);

	r = mifare_desfire_authenticate_aes(tag, 2, authentication_key);
	if(r < 0)
		DO_ABORT(-10);

	if(card_id != NULL) {
		*card_id = strdup(uuid_buffer);
		if(*card_id == NULL)
			DO_ABORT(-11);
	}

	retval = 0;

abort:
	memset(uuid_buffer, 0, sizeof(uuid_buffer));
	uuid_clear(app_uuid);

	if(read_key != NULL) {
		mifare_desfire_key_free(read_key);
	}
	if(authentication_key != NULL) {
		mifare_desfire_key_free(authentication_key);
	}

	if(derived_authentication_key != NULL) {
		memset(derived_authentication_key, 0, derived_authentication_key_length);
		gcry_free(derived_authentication_key);
	}

	if(aid != NULL) {
		free(aid);
	}

	return retval;
}


int openkey_authenticator_card_authenticate(openkey_context_t ctx, MifareTag tag, char **card_id)
{
	if(ctx == NULL || tag == NULL || !ctx->a.prepared) {
		return -1;
	}

	int r = mifare_desfire_connect(tag);
	int retval = -2;
	if(r < 0) {
		goto abort;
	}

	retval = -3;

	SLOT_MASK_DATA_TYPE slots_tried = 0;
	for(int i = 0; i < ctx->a.l.slot_list_length; i++) {
		int slot = ctx->a.l.slot_list[i];
		if(slot == -1) {
			for(slot = OPENKEY_SLOT_MIN; slot <= OPENKEY_SLOT_MAX; slot++) {
				if(slots_tried & (1<<slot)) {
					continue;
				}
				slots_tried |= 1<<slot;

				r = _do_authenticate_slot(ctx, tag, slot, card_id);
				if(r >= 0) {
					retval = r;
					goto abort;
				}
			}
		} else if(slot >= OPENKEY_SLOT_MIN && slot <= OPENKEY_SLOT_MAX) {
			if(slots_tried & (1<<slot)) {
				continue;
			}
			slots_tried |= 1<<slot;

			r = _do_authenticate_slot(ctx, tag, slot, card_id);
			if(r >= 0) {
				retval = r;
				goto abort;
			}
		} else {
			continue;
		}
	}

abort:
	mifare_desfire_disconnect(tag);
	return retval;
}
