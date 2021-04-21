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


#ifndef OPENKEY_H
#define OPENKEY_H

#include <stdint.h>
#include <freefare.h>

#define OPENKEY_SLOT_MIN 0
#define OPENKEY_SLOT_MAX 14

enum openkey_role {
	OPENKEY_ROLE_CARD_PRODUCER = 0,
	OPENKEY_ROLE_LOCK_MANAGER = 1,
	OPENKEY_ROLE_CARD_AUTHENTICATOR = 2,
};

typedef struct openkey_context *openkey_context_t;

#define OPENKEY_BASE_AID 0xff77f0

extern openkey_context_t openkey_init();

extern int openkey_role_add(openkey_context_t ctx, enum openkey_role role, const char *private_base_path);

extern bool openkey_producer_is_bootstrapped(openkey_context_t ctx);
extern int openkey_producer_bootstrap(openkey_context_t ctx);
extern int openkey_producer_card_create(openkey_context_t ctx, FreefareTag tag, const char *card_name);
extern int openkey_producer_card_recreate(openkey_context_t ctx, FreefareTag tag, const char *card_name, const char *old_id);

extern bool openkey_manager_is_bootstrapped(openkey_context_t ctx);
extern int openkey_manager_bootstrap(openkey_context_t ctx, int preferred_slot);
extern int openkey_manager_card_own(openkey_context_t ctx, FreefareTag tag, int slot, const char *key_file);
extern int openkey_manager_card_own_pw(openkey_context_t ctx, FreefareTag tag, int slot, const char *key_file, const uint8_t *pw, size_t pw_length);
#if 0
/* May be implemented later, not necessary for core operation */
extern int openkey_manager_card_disown(openkey_context_t ctx, FreefareTag tag, const char *card_name);
#endif

extern int openkey_authenticator_prepare(openkey_context_t ctx);
extern int openkey_authenticator_card_authenticate(openkey_context_t ctx, FreefareTag tag, char **card_id);
extern int openkey_authenticator_card_authenticate_pw(openkey_context_t ctx, FreefareTag tag, char **card_id, const uint8_t *pw, size_t pw_length);

extern int openkey_fini(openkey_context_t ctx);

extern int openkey_kdf(const uint8_t *master_key, size_t master_key_length, uint32_t aid, uint8_t key_no,
		const uint8_t *data, size_t data_length,
		uint8_t *derived_key, size_t derived_key_length);

extern int openkey_pbkdf(const uint8_t *master_key, size_t master_key_length, uint32_t aid, uint8_t key_no,
		const uint8_t *data, size_t data_length,
		const uint8_t *pw, size_t pw_length, int iterations,
		uint8_t *derived_key, size_t derived_key_length);

#endif
