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
#include <dirent.h>

#include <gcrypt.h>
#include <uuid/uuid.h>

#define OPENKEY_KDF_HMAC_ALGORITHM GCRY_MD_SHA256
#define OPENKEY_PBKDF_HMAC_ALGORITHM GCRY_MD_SHA256
#define OPENKEY_PBKDF_PRF GCRY_MD_SHA256
#define OPENKEY_PBKDF_ITERATIONS_DEFAULT 2048
#define OPENKEY_PBKDF_KDF_LENGTH 32
#define OPENKEY_PBKDF_PBKDF2_LENGTH 32
#define OPENKEY_ECDSA_HASH GCRY_MD_SHA256
#define OPENKEY_ECDSA_CURVE "NIST P-256"

static const char * const OPENKEY_PRODUCER_MAGIC_V1 = "libopenkey producer secret key storage v1";
static const char * const OPENKEY_MANAGER_MAGIC_V1 = "libopenkey manager secret key storage v1";
static const char * const OPENKEY_LOCK_MAGIC_V1 = "libopenkey lock secret key storage v1";
static const char * const OPENKEY_TRANSPORT_MAGIC_V1 = "libopenkey transport key file v1";

static const char * const OPENKEY_PRODUCER_FILENAME = "producer";
static const char * const OPENKEY_MANAGER_FILENAME = "manager";
static const char * const OPENKEY_LOCK_FILENAME = "lock";
static const char * const OPENKEY_PRODUCER_LOG = "log";

static const char * const PATH_SEPARATOR = "/";

#define OPENKEY_INITIAL_APPLICATION_SETTINGS 0x9
#define OPENKEY_FINAL_APPLICATION_SETTINGS 0xE0
#define OPENKEY_INITIAL_PICC_SETTINGS 0x09
#define OPENKEY_FINAL_PICC_SETTINGS 0x08
#define OPENKEY_INITIAL_UUID_FILE_SETTINGS 0x0000
#define OPENKEY_FINAL_UUID_FILE_SETTINGS 0x1FFF
#define OPENKEY_FINAL_AUTHENTICITY_FILE_SETTINGS 0x2F33
#define OPENKEY_AUTHENTICITY_R_LENGTH 32
#define OPENKEY_AUTHENTICITY_S_LENGTH 32
#define OPENKEY_AUTHENTICITY_FILE_SIZE (OPENKEY_AUTHENTICITY_R_LENGTH+OPENKEY_AUTHENTICITY_S_LENGTH)

#define SLOT_MASK_DATA_TYPE uint16_t

#define AES_KEY_LENGTH 16
#define AES_KEY_LINE_LENGTH  (2*(AES_KEY_LENGTH*3)) /* Includes some allowance for editing and extra spaces */
#define MAX_KEY_LENGTH 24
#define UUID_STRING_LENGTH 36
#define UUID_MANGLED_LENGTH 32

#define MASTER_AID 0x0

#define ROLEMASK(x) (1<<(x))

/* Hack: libfreefare allows no direct access to the nfc_device. However, a pointer
 * to it is the first member of the FreefareTag structure, so a cast will do for now
 */
#define RFERROR(tag) (nfc_device_get_last_error(*(nfc_device**)tag) == NFC_ERFTRANS)

struct openkey_context {
	uint8_t roles_initialized;

	struct {
		char *producer_path;
		int bootstrapped;

		uint8_t master_key[AES_KEY_LENGTH];
	} p;

	struct {
		char *manager_path;
		struct __attribute__((packed)) {
			unsigned int lock_bootstrapped:1;
			unsigned int lock_needs_upgrade:1;
			unsigned int manager_bootstrapped:1;
		} flags;

		gcry_sexp_t creation_priv_key;
		uint8_t master_authenticity_update_key[AES_KEY_LENGTH];

		struct lock_data {
			int slot_list[16 + 1];
			size_t slot_list_length;

			gcry_sexp_t creation_pub_key;
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
		uint8_t app_transport_authenticity_update_key[AES_KEY_LENGTH];
	} app[15];
};

struct transport_key_data {
	char *card_name;
	uuid_t app_uuid;
	uint8_t app_transport_read_key[AES_KEY_LENGTH];
	uint8_t app_transport_authentication_key[AES_KEY_LENGTH];
	uint8_t app_transport_authenticity_update_key[AES_KEY_LENGTH];
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

	gcry_sexp_release(ctx->m.l.creation_pub_key); ctx->m.l.creation_pub_key = NULL;
	gcry_sexp_release(ctx->m.creation_priv_key); ctx->m.creation_priv_key = NULL;

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

static const int UUID_PART_SIZES[] = { 8, 4, 4, 4, 12 };

static int _mangle_uuid(const char *uuid, size_t uuid_length, char *mangled_uuid, size_t mangled_uuid_length)
{
	size_t inpos = 0, outpos = 0;

	if(uuid == NULL || uuid_length == 0 ||mangled_uuid == NULL || mangled_uuid_length == 0) {
		return -1;
	}

	for(int i=0; i< sizeof(UUID_PART_SIZES)/sizeof(UUID_PART_SIZES[0]); i++) {
		if(i != 0) {
			if(inpos >= uuid_length) {
				return -1;
			}
			if( uuid[inpos++] != '-' ) {
				return -1;
			}
		}
		for(int j=0; j<UUID_PART_SIZES[i]; j++) {
			if(outpos >= mangled_uuid_length || inpos >= uuid_length) {
				return -1;
			}

			char in = uuid[inpos++];
			if( (in >= '0' && in <= '9') || (in >= 'a' && in <= 'f') ) {
				mangled_uuid[outpos++] = in;
			} else {
				return -1;
			}
		}
	}

	return 0;
}

static int _unmangle_uuid(const char *mangled_uuid, size_t mangled_uuid_length, char *uuid, size_t uuid_length)
{
	size_t inpos = 0, outpos = 0;

	if(uuid == NULL || uuid_length == 0 || mangled_uuid == NULL || mangled_uuid_length == 0) {
		return -1;
	}

	for(int i=0; i< sizeof(UUID_PART_SIZES)/sizeof(UUID_PART_SIZES[0]); i++) {
		if(i != 0) {
			if(outpos >= uuid_length) {
				return -1;
			}
			uuid[outpos++] = '-';
		}

		for(int j=0; j<UUID_PART_SIZES[i]; j++) {
			if(inpos >= mangled_uuid_length || outpos >= uuid_length) {
				return -1;
			}

			char in = mangled_uuid[inpos++];
			if( (in >= '0' && in <= '9') || (in >= 'a' && in <= 'f') ) {
				uuid[outpos++] = in;
			} else {
				return -1;
			}
		}
	}

	return 0;
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
	strcpy(path, a);
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


	FILE *producer_store = _fopen_in_dir(ctx->p.producer_path, OPENKEY_PRODUCER_FILENAME, "r", 0);
	char *buf = NULL;
	size_t buf_length = 0;
	int retval = -0x11;

	if(producer_store != NULL) {
		ssize_t r = getline(&buf, &buf_length, producer_store);

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
	FILE *lock_store = _fopen_in_dir(path, OPENKEY_LOCK_FILENAME, "r", 0);
	char *buf = NULL;
	size_t buf_length = 0;
	int retval = -1;

	if(lock_store != NULL) {
		ssize_t r = getline(&buf, &buf_length, lock_store);

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

		r = getline(&buf, &buf_length, lock_store);
		if(r > 0) {
			r = gcry_sexp_new(&(ld->creation_pub_key), buf, r, 1);
			if(r) {
				goto abort;
			}
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
		gcry_sexp_release(ld->creation_pub_key); ld->creation_pub_key = NULL;
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
	FILE *fh = NULL;
	char *buf = NULL;
	size_t buf_length = 0;

	if(r == 1) {
		if(ctx->m.l.creation_pub_key == NULL) {
			ctx->m.flags.lock_needs_upgrade = 1;
		}
		ctx->m.flags.lock_bootstrapped = 1;
	} else if(r < 0) {
		goto abort;
	}

	retval = -0x12;
	fh = _fopen_in_dir(ctx->m.manager_path, OPENKEY_MANAGER_FILENAME, "r", 0);
	if(fh != NULL) {
		ssize_t r = getline(&buf, &buf_length, fh);

		if( (r < 0) || (r < strlen(OPENKEY_MANAGER_MAGIC_V1)+1) || (buf_length < strlen(OPENKEY_MANAGER_MAGIC_V1)) ) {
			goto abort;
		}
		if(strncmp(buf, OPENKEY_MANAGER_MAGIC_V1, strlen(OPENKEY_MANAGER_MAGIC_V1)) != 0) {
			goto abort;
		}

		if(_read_key(fh, ctx->m.master_authenticity_update_key, sizeof(ctx->m.master_authenticity_update_key)) < 0) {
			goto abort;
		}

		r = getline(&buf, &buf_length, fh);
		if(r > 0) {
			r = gcry_sexp_new(&(ctx->m.creation_priv_key), buf, r, 1);
			if(r) {
				goto abort;
			}
		}

		if(gcry_pk_testkey(ctx->m.creation_priv_key)) {
			goto abort;
		}

		ctx->m.flags.manager_bootstrapped = 1;
	}


	ctx->roles_initialized |= ROLEMASK(OPENKEY_ROLE_LOCK_MANAGER);
	retval = 0;

abort:
	if(fh != NULL) {
		fclose(fh);
	}
	if(buf != NULL) {
		memset(buf, 0, buf_length);
		free(buf);
	}
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
	fh = _fopen_in_dir(ctx->p.producer_path, OPENKEY_PRODUCER_FILENAME, "w", S_IRWXG | S_IRWXO);

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
		_unlink_in_dir(ctx->p.producer_path, OPENKEY_PRODUCER_FILENAME);
	}

	return retval;
}

bool openkey_manager_is_bootstrapped(openkey_context_t ctx)
{
	if(ctx == NULL || !(ctx->roles_initialized & ROLEMASK(OPENKEY_ROLE_LOCK_MANAGER))) {
		return 0;
	}

	return ctx->m.flags.lock_bootstrapped && ctx->m.flags.manager_bootstrapped;
}

int openkey_manager_bootstrap(openkey_context_t ctx, int preferred_slot)
{
	if(ctx == NULL || !(ctx->roles_initialized & ROLEMASK(OPENKEY_ROLE_LOCK_MANAGER))) {
		return -1;
	}

	if(openkey_manager_is_bootstrapped(ctx)) {
		return 1;
	}


	FILE *lock_fh = NULL, *manager_fh = NULL, *lock_upgrade_fh = NULL;
	char *serialized_authentication_key = NULL, *serialized_read_key = NULL, *serialized_update_key = NULL;
	int retval = -1;
	gcry_sexp_t key_spec = NULL, key_pair = NULL, q = NULL, d = NULL;
	gcry_mpi_t q_mpi = NULL, d_mpi = NULL;
	uint8_t *q_buf = NULL, *d_buf = NULL;
	size_t q_buf_length = 0, d_buf_length = 0;

	if(!ctx->m.flags.manager_bootstrapped) {
		if(ctx->m.flags.lock_bootstrapped && !ctx->m.flags.lock_needs_upgrade) {
			/* Bootstrapping the manager private key means that either the lock must not have been bootstrapped at all
			 * yet, or be marked for an upgrade.
			 */
			goto abort;
		}

		int r = gcry_sexp_build(&key_spec, NULL, "(genkey (ECDSA (curve \"" OPENKEY_ECDSA_CURVE "\")))");
		if(r) {
			goto abort;
		}

		r = gcry_pk_genkey(&key_pair, key_spec);
		if(r) {
			goto abort;
		}

		ctx->m.l.creation_pub_key = gcry_sexp_find_token(key_pair, "public-key", 0);
		if(!ctx->m.l.creation_pub_key) {
			goto abort;
		}

		ctx->m.creation_priv_key = gcry_sexp_find_token(key_pair, "private-key", 0);
		if(!ctx->m.creation_priv_key) {
			goto abort;
		}

		q = gcry_sexp_find_token(ctx->m.creation_priv_key, "q", 0);
		d = gcry_sexp_find_token(ctx->m.creation_priv_key, "d", 0);
		if(!q || !d) {
			goto abort;
		}

		q_mpi = gcry_sexp_nth_mpi(q, 1, GCRYMPI_FMT_USG);
		d_mpi = gcry_sexp_nth_mpi(d, 1, GCRYMPI_FMT_USG);
		if(!q_mpi || !d_mpi) {
			goto abort;
		}

		if(gcry_mpi_aprint(GCRYMPI_FMT_HEX, &q_buf, &q_buf_length, q_mpi)) {
			goto abort;
		}

		if(gcry_mpi_aprint(GCRYMPI_FMT_HEX, &d_buf, &d_buf_length, d_mpi)) {
			goto abort;
		}

		gcry_randomize(ctx->m.master_authenticity_update_key, sizeof(ctx->m.master_authenticity_update_key), GCRY_VERY_STRONG_RANDOM);

		manager_fh = _fopen_in_dir(ctx->m.manager_path, OPENKEY_MANAGER_FILENAME, "w", S_IRWXG | S_IRWXO);
		if(manager_fh == NULL) {
			goto abort;
		}

		int written = fprintf(manager_fh, "%s\n", OPENKEY_MANAGER_MAGIC_V1);
		if(written < strlen(OPENKEY_MANAGER_MAGIC_V1) + 1) {
			goto abort;
		}

		serialized_update_key = _serialize_key(ctx->m.master_authenticity_update_key, sizeof(ctx->m.master_authenticity_update_key));
		if(serialized_update_key == NULL) {
			goto abort;
		}

		written = fprintf(manager_fh, "%s\n", serialized_update_key);
		if(written <= 0) {
			goto abort;
		}

		written = fprintf(manager_fh, "(private-key (ecdsa (curve \"" OPENKEY_ECDSA_CURVE "\") (q #%s#) (d #%s#) ) )\n", q_buf, d_buf);
		if(written <= 0) {
			goto abort;
		}

		ctx->m.flags.manager_bootstrapped = 1;
	}

	if(!ctx->m.flags.lock_bootstrapped) {
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

		lock_fh = _fopen_in_dir(ctx->m.manager_path, OPENKEY_LOCK_FILENAME, "w", S_IRWXG | S_IRWXO);

		if(lock_fh == NULL) {
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

		int written = fprintf(lock_fh, "%s\n", OPENKEY_LOCK_MAGIC_V1);
		if(written < strlen(OPENKEY_LOCK_MAGIC_V1) + 1) {
			goto abort;
		}

		for(int i=0; i<ctx->m.l.slot_list_length; i++) {
			written = fprintf(lock_fh, (i==0) ? "%i" : " %i", ctx->m.l.slot_list[i]);
			if(written <= 0) {
				goto abort;
			}
		}

		written = fprintf(lock_fh, "\n");
		if(written != 1) {
			goto abort;
		}

		written = fprintf(lock_fh, "%s\n%s\n", serialized_read_key, serialized_authentication_key);
		if(written < strlen(serialized_read_key) + 1 + strlen(serialized_authentication_key) + 1) {
			goto abort;
		}

		written = fprintf(lock_fh, "(public-key (ecdsa (curve \"" OPENKEY_ECDSA_CURVE "\") (q #%s#) ) )\n", q_buf);
		if(written <= 0) {
			goto abort;
		}

		ctx->m.flags.lock_bootstrapped = 1;
	} else if(ctx->m.flags.lock_needs_upgrade) {
		lock_upgrade_fh = _fopen_in_dir(ctx->m.manager_path, OPENKEY_LOCK_FILENAME, "a", S_IRWXG | S_IRWXO);

		int written = fprintf(lock_upgrade_fh, "(public-key (ecdsa (curve \"" OPENKEY_ECDSA_CURVE "\") (q #%s#) ) )\n", q_buf);
		if(written <= 0) {
			goto abort;
		}

		ctx->m.flags.lock_needs_upgrade = 0;
	}

	retval = 0;

abort:
	gcry_sexp_release(key_pair);
	gcry_sexp_release(key_spec);
	gcry_sexp_release(q);
	gcry_sexp_release(d);
	gcry_mpi_release(q_mpi);
	gcry_mpi_release(d_mpi);

	if(serialized_authentication_key != NULL) {
		memset(serialized_authentication_key, 0, strlen(serialized_authentication_key));
		gcry_free(serialized_authentication_key);
	}

	if(serialized_read_key != NULL) {
		memset(serialized_read_key, 0, strlen(serialized_read_key));
		gcry_free(serialized_read_key);
	}

	if(q_buf != NULL) {
		memset(q_buf, 0, q_buf_length);
		gcry_free(q_buf);
	}

	if(d_buf != NULL) {
		memset(d_buf, 0, d_buf_length);
		gcry_free(d_buf);
	}

	if(lock_fh != NULL) {
		fclose(lock_fh);
		if(retval < 0) {
			_unlink_in_dir(ctx->m.manager_path, OPENKEY_LOCK_FILENAME);
		}
	}

	if(lock_upgrade_fh != NULL) {
		fclose(lock_upgrade_fh);
	}

	if(manager_fh != NULL) {
		fclose(manager_fh);
		if(retval < 0) {
			_unlink_in_dir(ctx->m.manager_path, OPENKEY_MANAGER_FILENAME);
		}
	}

	if(retval < 0) {
		memset(ctx->m.l.read_key, 0, sizeof(ctx->m.l.read_key));
		memset(ctx->m.l.master_authentication_key, 0, sizeof(ctx->m.l.master_authentication_key));
		gcry_sexp_release(ctx->m.l.creation_pub_key); ctx->m.l.creation_pub_key = NULL;
		gcry_sexp_release(ctx->m.creation_priv_key); ctx->m.creation_priv_key = NULL;
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

int openkey_kdf(const uint8_t *master_key, size_t master_key_length, uint32_t aid, uint8_t key_no,
		const uint8_t *data, size_t data_length,
		uint8_t *derived_key, size_t derived_key_length)
{
	int retval = -1;
	gcry_md_hd_t md = NULL;

	if(derived_key_length > gcry_md_get_algo_dlen(OPENKEY_KDF_HMAC_ALGORITHM)) {
		goto abort;
	}

	if(master_key == NULL || derived_key == NULL) {
		goto abort;
	}

	if(data == NULL && data_length != 0) {
		goto abort;
	}

	int r = gcry_md_open(&md, OPENKEY_KDF_HMAC_ALGORITHM, GCRY_MD_FLAG_SECURE|GCRY_MD_FLAG_HMAC);
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

	memcpy(derived_key, gcry_md_read(md, OPENKEY_KDF_HMAC_ALGORITHM), derived_key_length);

	retval = 0;

abort:
	if(md != NULL) {
		gcry_md_close(md);
	}
	return retval;
}

int openkey_pbkdf(const uint8_t *master_key, size_t master_key_length, uint32_t aid, uint8_t key_no,
		const uint8_t *data, size_t data_length,
		const uint8_t *pw, size_t pw_length, int iterations,
		uint8_t *derived_key, size_t derived_key_length)
{
	int retval = -1;
	gcry_md_hd_t md = NULL;
	uint8_t *kdf_key = NULL, *pbkdf2_key = NULL;
	size_t kdf_key_length = OPENKEY_PBKDF_KDF_LENGTH, pbkdf2_key_length = OPENKEY_PBKDF_PBKDF2_LENGTH;

	if(derived_key_length > gcry_md_get_algo_dlen(OPENKEY_PBKDF_HMAC_ALGORITHM)) {
		goto abort;
	}

	if(iterations == 0) {
		iterations = OPENKEY_PBKDF_ITERATIONS_DEFAULT;
	}

	if(data == NULL && data_length != 0) {
		goto abort;
	}

	kdf_key = gcry_calloc_secure(1, kdf_key_length);
	pbkdf2_key = gcry_calloc_secure(1, pbkdf2_key_length);

	if(kdf_key == NULL || pbkdf2_key == NULL) {
		goto abort;
	}

	if(openkey_kdf(master_key, master_key_length, aid, key_no, data, data_length, kdf_key, kdf_key_length) < 0) {
		goto abort;
	}

	if(gcry_kdf_derive(pw, pw_length, GCRY_KDF_PBKDF2, OPENKEY_PBKDF_PRF, data, data_length, iterations, pbkdf2_key_length, pbkdf2_key) != 0) {
		goto abort;
	}

	int r = gcry_md_open(&md, OPENKEY_PBKDF_HMAC_ALGORITHM, GCRY_MD_FLAG_SECURE|GCRY_MD_FLAG_HMAC);
	if(r) {
		goto abort;
	}

	r = gcry_md_setkey(md, kdf_key, kdf_key_length);
	if(r) {
		goto abort;
	}

	gcry_md_write(md, pbkdf2_key, pbkdf2_key_length);

	gcry_md_final(md);

	memcpy(derived_key, gcry_md_read(md, OPENKEY_PBKDF_HMAC_ALGORITHM), derived_key_length);

	retval = 0;

abort:
	if(md != NULL) {
		gcry_md_close(md);
	}
	if(pbkdf2_key != NULL) {
		memset(pbkdf2_key, 0, pbkdf2_key_length);
		gcry_free(pbkdf2_key);
	}
	if(kdf_key != NULL) {
		memset(kdf_key, 0, kdf_key_length);
		gcry_free(kdf_key);
	}
	return retval;
}


static char *_sanitize_card_name(const char *card_name)
{
	if(card_name == NULL) {
		return NULL;
	}
	char * result=NULL;
	size_t card_name_length = strlen(card_name) + 1;
	result = malloc(card_name_length);
	if(result == NULL) {
		return NULL;
	}

	for(int i=0; i<card_name_length-1; i++) {
		if( (card_name[i] >= 'a' && card_name[i] <= 'z')
				|| (card_name[i] >= 'A' && card_name[i] <= 'Z')
				|| (card_name[i] >= '0' && card_name[i] <= '9')
				|| card_name[i] == '-' || card_name[i] == '_'
				|| card_name[i] == ' ' ) {
			result[i] = card_name[i];
		} else {
			result[i] = '_';
		}
	}
	result[card_name_length - 1] = 0;

	return result;
}

#define DO_ABORT(x) { retval = x; goto abort; }
static int _openkey_producer_card_create(openkey_context_t ctx, FreefareTag tag, const char *card_name,
		const uint8_t *old_derived_key, size_t old_derived_key_length,
		const uint8_t *old_uid, size_t old_uid_length)
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
	MifareDESFireKey app_master_key = NULL, app_transport_read_key = NULL, app_transport_authentication_key = NULL, app_transport_update_key = NULL;

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

	if(old_uid == NULL) {
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
	} else {
		if(old_uid_length > sizeof(cd->uid_length))
			DO_ABORT(-46);

		memcpy(cd->uid, old_uid, old_uid_length);
		cd->uid_length = old_uid_length;
	}

	if(old_derived_key != NULL) {
		memcpy(cd->old_master_key, old_derived_key, old_derived_key_length);
		cd->old_desfire_authentication_type = DESFIRE_AUTHENTICATION_TYPE_AES;
	}

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
		gcry_randomize(cd->app[slot].app_transport_authenticity_update_key, sizeof(cd->app[slot].app_transport_authenticity_update_key), GCRY_STRONG_RANDOM);
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
		char uuid_unparsed[UUID_STRING_LENGTH + 1];
		char uuid_mangled[UUID_MANGLED_LENGTH];

		uuid_unparse_lower(app->app_uuid, uuid_unparsed);

		old_app_key = mifare_desfire_aes_key_new(app->old_app_key);
		app_master_key = mifare_desfire_aes_key_new(app->app_master_key);
		app_transport_read_key = mifare_desfire_aes_key_new(app->app_transport_read_key);
		app_transport_authentication_key = mifare_desfire_aes_key_new(app->app_transport_authentication_key);
		app_transport_update_key = mifare_desfire_aes_key_new(app->app_transport_authenticity_update_key);
		if(old_app_key == NULL || app_master_key == NULL || app_transport_read_key == NULL || app_transport_authentication_key == NULL || app_transport_update_key == NULL)
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

		r = mifare_desfire_create_application_aes(tag, aid, OPENKEY_INITIAL_APPLICATION_SETTINGS, 4);
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

		r = mifare_desfire_change_key(tag, 3, app_transport_update_key, NULL);
		if(r < 0)
			DO_ABORT(-20);

		r = mifare_desfire_create_std_data_file(tag, 1, MDCM_PLAIN, OPENKEY_INITIAL_UUID_FILE_SETTINGS, sizeof(uuid_mangled));
		if(r < 0)
			DO_ABORT(-21);

		if(_mangle_uuid(uuid_unparsed, sizeof(uuid_unparsed)-1, uuid_mangled, sizeof(uuid_mangled)) < 0)
			DO_ABORT(-22);

		r = mifare_desfire_write_data_ex(tag, 1, 0, sizeof(uuid_mangled), uuid_mangled, MDCM_PLAIN);
		if(r < 0)
			DO_ABORT(-23);

		r = mifare_desfire_change_file_settings(tag, 1, MDCM_ENCIPHERED, OPENKEY_FINAL_UUID_FILE_SETTINGS);
		if(r < 0)
			DO_ABORT(-24);

		r = mifare_desfire_create_std_data_file(tag, 2, MDCM_ENCIPHERED, OPENKEY_FINAL_AUTHENTICITY_FILE_SETTINGS, OPENKEY_AUTHENTICITY_FILE_SIZE);
		if(r < 0)
			DO_ABORT(-25);

		r = mifare_desfire_change_key(tag, 0, app_master_key, NULL);
		if(r < 0)
			DO_ABORT(-26);

		r = mifare_desfire_authenticate_aes(tag, 0, app_master_key);
		if(r < 0)
			DO_ABORT(-27);

		r = mifare_desfire_change_key_settings(tag, OPENKEY_FINAL_APPLICATION_SETTINGS);
		if(r < 0)
			DO_ABORT(-28);

		mifare_desfire_key_free(old_app_key); old_app_key = NULL;
		mifare_desfire_key_free(app_master_key); app_master_key = NULL;
		mifare_desfire_key_free(app_transport_read_key); app_transport_read_key = NULL;
		mifare_desfire_key_free(app_transport_authentication_key); app_transport_authentication_key = NULL;
		mifare_desfire_key_free(app_transport_update_key); app_transport_update_key = NULL;

	}

	/* 4th b) Change master key and PICC settings */
	r = mifare_desfire_select_application(tag, NULL);
	if(r < 0)
		DO_ABORT(-29);

	r = mifare_desfire_authenticate(tag, 0, old_key);
	if(r < 0)
		DO_ABORT(-30);

	r = mifare_desfire_change_key_settings(tag, OPENKEY_INITIAL_PICC_SETTINGS);
	if(r < 0)
		DO_ABORT(-47);

	r = mifare_desfire_change_key(tag, 0, picc_master_key, NULL);
	if(r < 0)
		DO_ABORT(-31);

	r = mifare_desfire_authenticate_aes(tag, 0, picc_master_key);
	if(r < 0)
		DO_ABORT(-32);

	r = mifare_desfire_change_key_settings(tag, OPENKEY_FINAL_PICC_SETTINGS);
	if(r < 0)
		DO_ABORT(-33);

	if(old_uid == NULL) {
		r = mifare_desfire_set_configuration(tag, 0, 1);
		if(r < 0)
			DO_ABORT(-34);
	}


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
			DO_ABORT(-35);

		card_path[0] = 0;
		app_name[0] = 0;

		if( snprintf(card_path, card_path_length,
				"%s%s%02X%02X%02X%02X%02X%02X%02X-%s",
				ctx->p.producer_path, PATH_SEPARATOR,
				cd->uid[0], cd->uid[1], cd->uid[2], cd->uid[3], cd->uid[4], cd->uid[5], cd->uid[6],
				cd->card_name) >= card_path_length )
			DO_ABORT(-36);

		if(snprintf(app_name, app_name_length, "%s-%i",
				cd->card_name, slot) >= app_name_length)
			DO_ABORT(-37);

		if(_ensure_directory(card_path) < 0)
			DO_ABORT(-38);

		app_file = _fopen_in_dir(card_path, app_name, "w", S_IRWXO);
		if(app_file == NULL)
			DO_ABORT(-39);

		if(fprintf(app_file, "%s\n%s\n%s\n", OPENKEY_TRANSPORT_MAGIC_V1, cd->card_name, uuid_unparsed) < 0)
			DO_ABORT(-40);

		serialized_key = _serialize_key(app->app_transport_read_key, sizeof(app->app_transport_read_key));
		if(fprintf(app_file, "%s\n", serialized_key) < 0)
			DO_ABORT(-41);
		memset(serialized_key, 0, strlen(serialized_key));
		gcry_free(serialized_key);
		serialized_key = NULL;

		serialized_key = _serialize_key(app->app_transport_authentication_key, sizeof(app->app_transport_authentication_key));
		if(fprintf(app_file, "%s\n", serialized_key) < 0)
			DO_ABORT(-42);
		memset(serialized_key, 0, strlen(serialized_key));
		gcry_free(serialized_key);
		serialized_key = NULL;

		serialized_key = _serialize_key(app->app_transport_authenticity_update_key, sizeof(app->app_transport_authenticity_update_key));
		if(fprintf(app_file, "%s\n", serialized_key) < 0)
			DO_ABORT(-43);
		memset(serialized_key, 0, strlen(serialized_key));
		gcry_free(serialized_key);
		serialized_key = NULL;

		free(card_path); card_path = NULL;
		free(app_name); app_name = NULL;
		fclose(app_file); app_file = NULL;
	}

	log_file = _fopen_in_dir(ctx->p.producer_path, OPENKEY_PRODUCER_LOG, "a", 0);
	if(log_file == NULL)
		DO_ABORT(-44);


	char time_buf[64] = {0};
	time_t now = time(NULL);
	struct tm tm;
	gmtime_r(&now, &tm);
	strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm);
	if(fprintf(log_file, "%s %02X%02X%02X%02X%02X%02X%02X %s\n",
			time_buf,
			cd->uid[0], cd->uid[1], cd->uid[2], cd->uid[3], cd->uid[4], cd->uid[5], cd->uid[6],
			cd->card_name) < 0)
		DO_ABORT(-45)

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
	if(app_transport_update_key != NULL) {
		mifare_desfire_key_free(app_transport_update_key);
	}

	return retval;
}

int openkey_producer_card_create(openkey_context_t ctx, FreefareTag tag, const char *card_name)
{
	return _openkey_producer_card_create(ctx, tag, card_name, NULL, 0, NULL, 0);
}

static int _try_uid(openkey_context_t ctx, FreefareTag tag, const uint8_t *uid, size_t uid_length, uint8_t **out_key, size_t *out_key_length)
{
	uint8_t *derived_key = NULL;
	size_t derived_key_length = AES_KEY_LENGTH;
	MifareDESFireKey key = NULL;
	int retval = -1;

	if(ctx == NULL || tag == NULL) {
		goto abort;
	}

	derived_key = gcry_calloc_secure(1, derived_key_length);
	if(derived_key == NULL) {
		goto abort;
	}

	if(openkey_kdf(ctx->p.master_key, sizeof(ctx->p.master_key), MASTER_AID, 0x00, uid, uid_length, derived_key, derived_key_length) < 0) {
		goto abort;
	}

	key = mifare_desfire_aes_key_new(derived_key);
	if(key == NULL) {
		goto abort;
	}

	int r = mifare_desfire_select_application(tag, NULL);
	if(r < 0) {
		goto abort;
	}

	r = mifare_desfire_authenticate_aes(tag, 0, key);
	if(r < 0) {
		goto abort;
	}

	retval = 0;

abort:
	if(retval >= 0) {
		*out_key = derived_key;
		*out_key_length = derived_key_length;
	} else {
		if(derived_key != NULL) {
			memset(derived_key, 0, derived_key_length);
			gcry_free(derived_key);
		}
	}
	if(key != NULL) {
		mifare_desfire_key_free(key);
	}
	return retval;
}

int openkey_producer_card_recreate(openkey_context_t ctx, FreefareTag tag, const char *card_name, const char *old_id)
{
	int retval = -1;
	int uid_found = 0;

	FILE *log_fh = NULL;
	char *buf = NULL;
	size_t buf_length = 0;

	uint8_t uid[7];
	size_t uid_length = sizeof(uid);

	uint8_t *derived_key = NULL;
	size_t derived_key_length = 0;

	MifareDESFireKey key = NULL;

	DIR *cards_dir = NULL;
	struct dirent *entry = NULL, *result = NULL;

	char *sanitized_old_id = NULL;

	if(ctx == NULL || tag == NULL || !ctx->p.bootstrapped) {
		return -1;
	}


	if(mifare_desfire_connect(tag) < 0) {
		goto abort;
	}

	if(old_id == NULL) {
		log_fh = _fopen_in_dir(ctx->p.producer_path, OPENKEY_PRODUCER_LOG, "r", 0);
		if(log_fh == NULL) {
			goto abort;
		}

		while(1) {
			ssize_t r = getline(&buf, &buf_length, log_fh);
			char *item = NULL;
			char *saveptr = NULL;
			if(r < 0) {
				break;
			}

			item = strtok_r(buf, " ", &saveptr);
			if(item == NULL) { // Should be date
				goto abort;
			}

			item = strtok_r(NULL, " ", &saveptr);
			if(item == NULL) { // Should be time
				goto abort;
			}

			item = strtok_r(NULL, " ", &saveptr);
			if(item == NULL) { // Should be UID
				goto abort;
			}

			if(sscanf(item, "%2hhX%2hhX%2hhX%2hhX%2hhX%2hhX%2hhX",
					uid+0, uid+1, uid+2, uid+3, uid+4, uid+5, uid+6) != uid_length) {
				continue;
			}

			if(_try_uid(ctx, tag, uid, uid_length, &derived_key, &derived_key_length) >= 0) {
				uid_found = 1;
				break;
			}
		}
	}

	if(!uid_found && old_id != NULL) {
		if(sscanf(old_id, "%2hhX%2hhX%2hhX%2hhX%2hhX%2hhX%2hhX",
				uid+0, uid+1, uid+2, uid+3, uid+4, uid+5, uid+6) == uid_length) {
			if(_try_uid(ctx, tag, uid, uid_length, &derived_key, &derived_key_length) >= 0) {
				uid_found = 1;
			}
		}
	}

	if(!uid_found && old_id != NULL) {
		/* Try old_id as card_name, locate UID-card_name directory, try UID */
		sanitized_old_id = _sanitize_card_name(old_id);
		if(sanitized_old_id == NULL) {
			goto abort;
		}

		cards_dir = opendir(ctx->p.producer_path);
		if(cards_dir == NULL) {
			goto abort;
		}

		int len = offsetof(struct dirent, d_name) + pathconf(ctx->p.producer_path, _PC_NAME_MAX) + 1;
		entry = malloc(len);
		if(entry == NULL) {
			goto abort;
		}

		while(NULL != readdir(cards_dir)) {
			if(result == NULL) {
				break;
			}

			if(strcmp(sanitized_old_id, result->d_name + (2*uid_length) + 1) == 0) {
				if(sscanf(result->d_name, "%2hhX%2hhX%2hhX%2hhX%2hhX%2hhX%2hhX",
						uid+0, uid+1, uid+2, uid+3, uid+4, uid+5, uid+6) == uid_length) {
					if(_try_uid(ctx, tag, uid, uid_length, &derived_key, &derived_key_length) >= 0) {
						uid_found = 1;
						break;
					}
				}
			}

		}

	}

	if(uid_found) {
		int r = mifare_desfire_select_application(tag, NULL);
		if(r < 0) {
			goto abort;
		}

		key = mifare_desfire_aes_key_new(derived_key);
		if(key == NULL) {
			goto abort;
		}

		r = mifare_desfire_authenticate(tag, 0, key);
		if(r < 0) {
			goto abort;
		}

		r = mifare_desfire_format_picc(tag);
		if(r < 0) {
			goto abort;
		}
	}

	if(mifare_desfire_disconnect(tag) < 0) {
		goto abort;
	}

	if(uid_found) {
		retval = _openkey_producer_card_create(ctx, tag, card_name, derived_key, derived_key_length, uid, uid_length);
	}

abort:
	if(derived_key != NULL) {
		memset(derived_key, 0, derived_key_length);
		gcry_free(derived_key);
	}
	if(log_fh != NULL) {
		fclose(log_fh);
	}
	if(buf != NULL) {
		memset(buf, 0, buf_length);
		free(buf);
	}
	if(key != NULL) {
		mifare_desfire_key_free(key);
	}
	if(sanitized_old_id != NULL) {
		free(sanitized_old_id);
	}

	if(cards_dir != NULL) {
		closedir(cards_dir);
	}
	if(entry != NULL) {
		free(entry);
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

	ssize_t r = getline(&buf, &buf_length, fh);
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

	if( _read_key(fh, result->app_transport_authenticity_update_key, sizeof(result->app_transport_authenticity_update_key)) < 0) {
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

static int _do_own_slot(openkey_context_t ctx, FreefareTag tag, int slot, struct transport_key_data *td, const uint8_t *pw, size_t pw_length)
{
	/* Note: As of 2013-02-02 mifare_desfire_read_ex() with cipher/mac has a bug in that it will
	 * need a buffer that is large enough to hold both the payload data and mac/padding. So we'll
	 * allocate a larger buffer here and use UUID_MANGLED_LENGTH explicitly.
	 */
	char uuid_mangled[UUID_MANGLED_LENGTH + 2*16 + 1];
	char uuid_buffer[UUID_STRING_LENGTH + 1];
	int retval = -1;
	uuid_t app_uuid;
	MifareDESFireAID aid = mifare_desfire_aid_new(OPENKEY_BASE_AID + slot);
	MifareDESFireKey transport_read_key = NULL, transport_authentication_key = NULL, transport_update_key = NULL;
	MifareDESFireKey read_key = NULL, authentication_key = NULL, update_key = NULL;
	size_t derived_authentication_key_length = AES_KEY_LENGTH;
	uint8_t *derived_authentication_key = NULL;
	size_t derived_update_key_length = AES_KEY_LENGTH;
	uint8_t *derived_update_key = NULL;
	gcry_md_hd_t uuid_hash_md = NULL;
	gcry_sexp_t sig_data = NULL, sig_result = NULL, r_data = NULL, s_data = NULL;
	const char *r_buffer, *s_buffer; // Note: These are *inside* r_data and s_data, so don't need to be freed
	size_t r_buffer_length, s_buffer_length;

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

	memset(uuid_mangled, 0, sizeof(uuid_mangled));
	memset(uuid_buffer, 0, sizeof(uuid_buffer));
	if( mifare_desfire_read_data_ex(tag, 1, 0, UUID_MANGLED_LENGTH, uuid_mangled, MDCM_ENCIPHERED) != UUID_MANGLED_LENGTH) {
		goto abort;
	}

	if(_unmangle_uuid(uuid_mangled, sizeof(uuid_mangled), uuid_buffer, sizeof(uuid_buffer)) < 0) {
		goto abort;
	}

	if(uuid_buffer[UUID_STRING_LENGTH] != 0) {
		goto abort;
	}

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

	derived_update_key = gcry_calloc_secure(1, derived_update_key_length);
	if(derived_update_key == NULL) {
		goto abort;
	}

	memset(uuid_buffer, 0, sizeof(uuid_buffer));
	uuid_unparse_lower(td->app_uuid, uuid_buffer);

	if(pw == NULL) {
		r = openkey_kdf(ctx->m.l.master_authentication_key, sizeof(ctx->m.l.master_authentication_key),
				mifare_desfire_aid_get_aid(aid), 2, (unsigned char*)uuid_buffer, UUID_STRING_LENGTH,
				derived_authentication_key, derived_authentication_key_length);
	} else {
		r = openkey_pbkdf(ctx->m.l.master_authentication_key, sizeof(ctx->m.l.master_authentication_key),
				mifare_desfire_aid_get_aid(aid), 2, (unsigned char*)uuid_buffer, UUID_STRING_LENGTH,
				pw, pw_length, 0,
				derived_authentication_key, derived_authentication_key_length);

	}
	if(r < 0) {
		goto abort;
	}

	r = openkey_kdf(ctx->m.master_authenticity_update_key, sizeof(ctx->m.master_authenticity_update_key),
			mifare_desfire_aid_get_aid(aid), 3, (unsigned char*)uuid_buffer, UUID_STRING_LENGTH,
			derived_update_key, derived_update_key_length);
	if(r < 0) {
		goto abort;
	}

	if(gcry_md_open(&uuid_hash_md, OPENKEY_ECDSA_HASH, 0)) {
		goto abort;
	}

	gcry_md_write(uuid_hash_md, uuid_buffer, UUID_STRING_LENGTH);

	r = gcry_sexp_build(&sig_data, NULL, "(data (value %b ) )",
			gcry_md_get_algo_dlen(OPENKEY_ECDSA_HASH), gcry_md_read(uuid_hash_md, OPENKEY_ECDSA_HASH) );
	if(r) {
		goto abort;
	}

	r = gcry_pk_sign(&sig_result, sig_data, ctx->m.creation_priv_key);
	if(r) {
		goto abort;
	}

	r_data = gcry_sexp_find_token(sig_result, "r", 0);
	s_data = gcry_sexp_find_token(sig_result, "s", 0);
	if(r_data == NULL || s_data == NULL) {
		goto abort;
	}

	r_buffer = gcry_sexp_nth_data(r_data, 1, &r_buffer_length);
	s_buffer = gcry_sexp_nth_data(s_data, 1, &s_buffer_length);
	if(r_buffer == NULL || s_buffer == NULL) {
		goto abort;
	}

	if(r_buffer_length != OPENKEY_AUTHENTICITY_R_LENGTH || s_buffer_length != OPENKEY_AUTHENTICITY_S_LENGTH) {
		goto abort;
	}

	transport_authentication_key = mifare_desfire_aes_key_new(td->app_transport_authentication_key);
	transport_update_key = mifare_desfire_aes_key_new(td->app_transport_authenticity_update_key);
	read_key = mifare_desfire_aes_key_new(ctx->m.l.read_key);
	authentication_key = mifare_desfire_aes_key_new(derived_authentication_key);
	update_key = mifare_desfire_aes_key_new(derived_update_key);

	if(transport_authentication_key == NULL || transport_update_key == NULL
			|| read_key == NULL || authentication_key == NULL || update_key == NULL) {
		goto abort;
	}

	if(mifare_desfire_authenticate_aes(tag, 3, transport_update_key) < 0) {
		goto abort;
	}

	if(mifare_desfire_change_key(tag, 3, update_key, NULL) < 0) {
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

	if(mifare_desfire_authenticate_aes(tag, 3, update_key) < 0) {
		goto abort;
	}

	if(mifare_desfire_write_data_ex(tag, 2, 0, r_buffer_length, r_buffer, MDCM_ENCIPHERED) < 0) {
		goto abort;
	}

	if(mifare_desfire_write_data_ex(tag, 2, r_buffer_length, s_buffer_length, s_buffer, MDCM_ENCIPHERED) < 0) {
		goto abort;
	}

	retval = 0;

abort:
	memset(uuid_mangled, 0, sizeof(uuid_mangled));
	memset(uuid_buffer, 0, sizeof(uuid_buffer));
	uuid_clear(app_uuid);
	gcry_md_close(uuid_hash_md);
	gcry_sexp_release(sig_data);
	gcry_sexp_release(sig_result);
	gcry_sexp_release(r_data);
	gcry_sexp_release(s_data);

	if(transport_read_key != NULL) {
		mifare_desfire_key_free(transport_read_key);
	}
	if(transport_authentication_key != NULL) {
		mifare_desfire_key_free(transport_authentication_key);
	}
	if(transport_update_key != NULL) {
		mifare_desfire_key_free(transport_update_key);
	}
	if(read_key != NULL) {
		mifare_desfire_key_free(read_key);
	}
	if(authentication_key != NULL) {
		mifare_desfire_key_free(authentication_key);
	}
	if(update_key != NULL) {
		mifare_desfire_key_free(update_key);
	}

	if(aid != NULL) {
		free(aid);
	}

	if(derived_authentication_key != NULL) {
		memset(derived_authentication_key, 0, derived_authentication_key_length);
		gcry_free(derived_authentication_key);
	}

	if(derived_update_key != NULL) {
		memset(derived_update_key, 0, derived_update_key_length);
		gcry_free(derived_update_key);
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

int openkey_manager_card_own_pw(openkey_context_t ctx, FreefareTag tag, int slot, const char *key_file, const uint8_t *pw, size_t pw_length)
{
	if(ctx == NULL || tag == NULL || !openkey_manager_is_bootstrapped(ctx)) {
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

				int r = _do_own_slot(ctx, tag, slot, td, pw, pw_length);
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

			int r = _do_own_slot(ctx, tag, slot, td, pw, pw_length);
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

				int r = _do_own_slot(ctx, tag, slot, td, pw, pw_length);
				if(r >= 0) {
					retval = r;
					slots_tried = ~0;
					break;
				}
			}
		}

	} else if(slot >= OPENKEY_SLOT_MIN && slot <= OPENKEY_SLOT_MAX) {
		retval = _do_own_slot(ctx, tag, slot, td, pw, pw_length);
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

int openkey_manager_card_own(openkey_context_t ctx, FreefareTag tag, int slot, const char *key_file)
{
	return openkey_manager_card_own_pw(ctx, tag, slot, key_file, NULL, 0);
}

static int _do_authenticate_slot(openkey_context_t ctx, FreefareTag tag, int slot, char **card_id, const uint8_t *pw, size_t pw_length)
{
	char uuid_mangled[UUID_MANGLED_LENGTH + 2*16 + 1];
	char uuid_buffer[UUID_STRING_LENGTH + 1];
	char authenticity_data[OPENKEY_AUTHENTICITY_FILE_SIZE + 2*16 + 1];
	int retval = -1;
	uuid_t app_uuid;
	MifareDESFireAID aid = mifare_desfire_aid_new(OPENKEY_BASE_AID + slot);
	MifareDESFireKey read_key = NULL, authentication_key = NULL;
	size_t derived_authentication_key_length = AES_KEY_LENGTH;
	uint8_t *derived_authentication_key = NULL;
	gcry_sexp_t sig_data = NULL, sig_val = NULL;
	gcry_md_hd_t uuid_hash_md = NULL;

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
	memset(uuid_mangled, 0, sizeof(uuid_mangled));
	if( mifare_desfire_read_data_ex(tag, 1, 0, UUID_MANGLED_LENGTH, uuid_mangled, MDCM_ENCIPHERED) != UUID_MANGLED_LENGTH)
		DO_ABORT(-5);

	if(_unmangle_uuid(uuid_mangled, sizeof(uuid_mangled), uuid_buffer, sizeof(uuid_buffer)) < 0)
		DO_ABORT(-6);

	if(uuid_buffer[UUID_STRING_LENGTH] != 0)
		DO_ABORT(-7);

	if(uuid_parse(uuid_buffer, app_uuid) < 0)
		DO_ABORT(-8);

	derived_authentication_key = gcry_calloc_secure(1, derived_authentication_key_length);
	if(derived_authentication_key == NULL)
		DO_ABORT(-9);

	memset(uuid_buffer, 0, sizeof(uuid_buffer));
	uuid_unparse_lower(app_uuid, uuid_buffer);

	if(pw == NULL) {
		r = openkey_kdf(ctx->a.l.master_authentication_key, sizeof(ctx->a.l.master_authentication_key),
				mifare_desfire_aid_get_aid(aid), 2, (unsigned char*)uuid_buffer, UUID_STRING_LENGTH,
				derived_authentication_key, derived_authentication_key_length);
	} else {
		r = openkey_pbkdf(ctx->a.l.master_authentication_key, sizeof(ctx->a.l.master_authentication_key),
				mifare_desfire_aid_get_aid(aid), 2, (unsigned char*)uuid_buffer, UUID_STRING_LENGTH,
				pw, pw_length, 0,
				derived_authentication_key, derived_authentication_key_length);

	}
	if(r < 0)
		DO_ABORT(-10);

	authentication_key = mifare_desfire_aes_key_new(derived_authentication_key);
	if(authentication_key == NULL)
		DO_ABORT(-11);

	r = mifare_desfire_authenticate_aes(tag, 2, authentication_key);
	if(r < 0)
		DO_ABORT(-12);

	memset(authenticity_data, 0, sizeof(authenticity_data));
	if( mifare_desfire_read_data_ex(tag, 2, 0, OPENKEY_AUTHENTICITY_FILE_SIZE, authenticity_data, MDCM_ENCIPHERED) != OPENKEY_AUTHENTICITY_FILE_SIZE)
		DO_ABORT(-13);


	if(gcry_md_open(&uuid_hash_md, OPENKEY_ECDSA_HASH, 0))
		DO_ABORT(-14);

	gcry_md_write(uuid_hash_md, uuid_buffer, UUID_STRING_LENGTH);

	r = gcry_sexp_build(&sig_data, NULL, "(data (value %b ) )",
			gcry_md_get_algo_dlen(OPENKEY_ECDSA_HASH), gcry_md_read(uuid_hash_md, OPENKEY_ECDSA_HASH) );
	if(r)
		DO_ABORT(-15);

	r = gcry_sexp_build(&sig_val, NULL, "(sig-val (ecdsa (r %b) (s %b) ) )",
			OPENKEY_AUTHENTICITY_R_LENGTH, authenticity_data,
			OPENKEY_AUTHENTICITY_S_LENGTH, authenticity_data + OPENKEY_AUTHENTICITY_R_LENGTH);

	r = gcry_pk_verify(sig_val, sig_data, ctx->a.l.creation_pub_key);
	if(r)
		DO_ABORT(-16);


	if(card_id != NULL) {
		*card_id = strdup(uuid_buffer);
		if(*card_id == NULL)
			DO_ABORT(-17);
	}

	retval = 0;

abort:
	memset(uuid_buffer, 0, sizeof(uuid_buffer));
	memset(uuid_mangled, 0, sizeof(uuid_mangled));
	memset(authenticity_data, 0, sizeof(authenticity_data));
	gcry_sexp_release(sig_data);
	gcry_sexp_release(sig_val);
	gcry_md_close(uuid_hash_md);
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


int openkey_authenticator_card_authenticate_pw(openkey_context_t ctx, FreefareTag tag, char **card_id, const uint8_t *pw, size_t pw_length)
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

				r = _do_authenticate_slot(ctx, tag, slot, card_id, pw, pw_length);
				if(r >= 0) {
					retval = r;
					goto abort;
				} else if(RFERROR(tag)) {
					break;
				}
			}
		} else if(slot >= OPENKEY_SLOT_MIN && slot <= OPENKEY_SLOT_MAX) {
			if(slots_tried & (1<<slot)) {
				continue;
			}
			slots_tried |= 1<<slot;

			r = _do_authenticate_slot(ctx, tag, slot, card_id, pw, pw_length);
			if(r >= 0) {
				retval = r;
				goto abort;
			} else if(RFERROR(tag)) {
				break;
			}
		} else {
			continue;
		}
	}

abort:
	mifare_desfire_disconnect(tag);
	return retval;
}

int openkey_authenticator_card_authenticate(openkey_context_t ctx, FreefareTag tag, char **card_id)
{
	return openkey_authenticator_card_authenticate_pw(ctx, tag, card_id, NULL, 0);
}
