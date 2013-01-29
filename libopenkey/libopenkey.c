#include "libopenkey.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gcrypt.h>
#include <uuid/uuid.h>

static const char * const OPENKEY_PRODUCER_MAGIC_V1 = "libopenkey producer secret key storage v1";
static const char * const OPENKEY_LOCK_MAGIC_V1 = "libopenkey lock secret key storage v1";

#define SLOT_MIN 0
#define SLOT_MAX 14

#define AES_KEY_LENGTH 16
#define AES_KEY_LINE_LENGTH  (2*(AES_KEY_LENGTH*3)) /* Includes some allowance for editing and extra spaces */

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

	uint8_t picc_master_key[AES_KEY_LENGTH];

	struct {
		uuid_t app_uuid;
		uint8_t app_master_key[AES_KEY_LENGTH];
		uint8_t app_transport_read_key[AES_KEY_LENGTH];
		uint8_t app_transport_authentication_key[AES_KEY_LENGTH];
	} app[15];
};

openkey_context_t openkey_init()
{
	if(!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
		/* TODO: Maybe print a warning here? */
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

static char *_concat_paths(const char *a, const char *b)
{
	if(a == NULL || b == NULL) {
		return NULL;
	}

	size_t path_length = strlen(a) + 1 + strlen(b) + 1;
	char *path = malloc( path_length );
	if(path == NULL) {
		return NULL;
	}

	path[0] = 0;
	strncat(path, a, path_length);
	strncat(path, "/", path_length);
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
	char *line_buffer = NULL;
	size_t line_buffer_length = AES_KEY_LINE_LENGTH;
	int retval = -0x11;

	if(producer_store != NULL) {
		line_buffer = gcry_malloc_secure(line_buffer_length);
		if(line_buffer == NULL) {
			goto abort;
		}

		if(fgets(line_buffer, line_buffer_length, producer_store) == NULL) {
			goto abort;
		}

		size_t l = strlen(line_buffer);
		if(l != strlen(OPENKEY_PRODUCER_MAGIC_V1)+1) {
			goto abort;
		}

		if(strncmp(OPENKEY_PRODUCER_MAGIC_V1, line_buffer, strlen(OPENKEY_PRODUCER_MAGIC_V1)) != 0) {
			goto abort;
		}

		if(fgets(line_buffer, line_buffer_length, producer_store) == NULL) {
			goto abort;
		}

		if(_unserialize_key(line_buffer, ctx->p.master_key, sizeof(ctx->p.master_key)) < 0) {
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

	if(line_buffer != NULL) {
		memset(line_buffer, 0, line_buffer_length);
		gcry_free(line_buffer);
	}

	if(!ctx->p.bootstrapped) {
		memset(ctx->p.master_key, 0, sizeof(ctx->p.master_key));
	}

	return retval;
}

static int _load_lock_data(struct lock_data *ld, const char *path)
{
	FILE *lock_store = _fopen_in_dir(path, "lock", "r", 0);
	char *line_buffer = NULL;
	size_t line_buffer_length = AES_KEY_LINE_LENGTH;
	int retval = -1;

	if(lock_store != NULL) {
		line_buffer = gcry_malloc_secure(line_buffer_length);
		if(line_buffer == NULL) {
			goto abort;
		}

		if(fgets(line_buffer, line_buffer_length, lock_store) == NULL) {
			goto abort;
		}

		size_t l = strlen(line_buffer);
		if(l != strlen(OPENKEY_LOCK_MAGIC_V1)+1) {
			goto abort;
		}

		if(strncmp(OPENKEY_LOCK_MAGIC_V1, line_buffer, strlen(OPENKEY_LOCK_MAGIC_V1)) != 0) {
			goto abort;
		}

		if(fgets(line_buffer, line_buffer_length, lock_store) == NULL) {
			goto abort;
		}

		ld->slot_list_length = 0;
		char *strtol_begin = line_buffer;
		while(ld->slot_list_length < (sizeof(ld->slot_list)/sizeof(ld->slot_list[0]))) {
			char *strtol_end = NULL;

			int value = strtol(strtol_begin, &strtol_end, 0);

			if(strtol_begin == strtol_end) {
				break;
			}

			if(value != -1 && (value < SLOT_MIN || value > SLOT_MAX)) {
				goto abort;
			}

			ld->slot_list[ld->slot_list_length++] = value;

			strtol_begin = strtol_end;
		}

		if(ld->slot_list_length == 0) {
			ld->slot_list[0] = -1;
			ld->slot_list_length = 1;
		}

		if(fgets(line_buffer, line_buffer_length, lock_store) == NULL) {
			goto abort;
		}

		if(_unserialize_key(line_buffer, ld->read_key, sizeof(ld->read_key)) < 0) {
			goto abort;
		}

		if(fgets(line_buffer, line_buffer_length, lock_store) == NULL) {
			goto abort;
		}

		if(_unserialize_key(line_buffer, ld->master_authentication_key, sizeof(ld->master_authentication_key)) < 0) {
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

	if(line_buffer != NULL) {
		memset(line_buffer, 0, line_buffer_length);
		gcry_free(line_buffer);
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

int openkey_manager_bootstrap(openkey_context_t ctx, int preferred_slot)
{
	if(ctx == NULL || !(ctx->roles_initialized & ROLEMASK(OPENKEY_ROLE_LOCK_MANAGER))) {
		return -1;
	}

	if(ctx->m.bootstrapped) {
		return 1;
	}

	ctx->m.l.slot_list[0] = preferred_slot;
	ctx->m.l.slot_list[1] = -1;
	ctx->m.l.slot_list_length = 2;

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
