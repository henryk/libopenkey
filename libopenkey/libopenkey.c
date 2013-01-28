#include "libopenkey.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gcrypt.h>

static const char * const OPENKEY_PRODUCER_MAGIC_V1 = "libopenkey producer secret key storage v1";

#define AES_KEY_LENGTH 16

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
	free(ctx);

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
	ctx->p.producer_path = strdup(base_path);

	if(_ensure_directory(ctx->p.producer_path) < 0) {
		return -0x10;
	}

	FILE *producer_store = _fopen_in_dir(ctx->p.producer_path, "producer", "r", 0);
	if(producer_store != NULL) {
		/* TODO Read producer key, set bootstrapped to 1 */

		fclose(producer_store);
	}

	ctx->roles_initialized |= ROLEMASK(OPENKEY_ROLE_CARD_PRODUCER);

	return 0;
}

static int _add_manager(openkey_context_t ctx, const char *base_path)
{
	return -1;
}

static int _add_authenticator(openkey_context_t ctx, const char *base_path)
{
	return -1;
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

abort:
	if(serialized_key != NULL) {
		memset(serialized_key, 0, strlen(serialized_key));
		gcry_free(serialized_key);
	}

	if(retval < 0) {
		memset(ctx->p.master_key, 0, sizeof(ctx->p.master_key));
		if(fh != NULL) {
			fclose(fh);
		}
		_unlink_in_dir(ctx->p.producer_path, "producer");
	}

	return retval;
}
