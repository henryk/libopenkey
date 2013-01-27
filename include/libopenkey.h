#ifndef libopenkey_H
#define libopenkey_H

#include <stdint.h>
#include <freefare.h>

enum openkey_role {
	OPENKEY_ROLE_CARD_PRODUCER = 0,
	OPENKEY_ROLE_LOCK_MANAGER = 1,
	OPENKEY_ROLE_CARD_AUTHENTICATOR = 2,
};

typedef struct openkey_context *openkey_context_t;

extern openkey_context_t openkey_init();

extern int openkey_role_add(openkey_context_t ctx, enum openkey_role role, const char *private_base_path);

extern int openkey_producer_bootstrap(openkey_context_t ctx);
extern int openkey_producer_card_create(openkey_context_t ctx, MifareTag tag, const char *card_name);

extern int openkey_manager_bootstrap(openkey_context_t ctx, unsigned int preferred_slot);
extern int openkey_manager_card_own(openkey_context_t ctx, MifareTag tag, const char *key_file);
#if 0
/* May be implemented later, not necessary for core operation */
extern int openkey_manager_card_disown(openkey_context_t ctx, MifareTag tag, const char *card_name);
#endif

extern int openkey_authenticator_prepare(openkey_context_t ctx, unsigned int preferred_slot);
extern int openkey_authenticator_card_authenticate(openkey_context_t ctx, MifareTag tag, char **card_id);

extern int openkey_fini(openkey_context_t ctx);

#endif
