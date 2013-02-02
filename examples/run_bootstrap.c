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

	if(r >= 0) {
		if(openkey_role_add(ctx, OPENKEY_ROLE_LOCK_MANAGER, "foo") < 0) {
			fprintf(stderr, "Could not add lock manager role\n");
			exit(4);
		}

		r = openkey_manager_bootstrap(ctx, 5);
		if(r < 0) {
			fprintf(stderr, "Could not bootstrap lock manager role\n");
			exit(5);
		} else if(r == 0) {
			printf("Lock manager bootstrapped\n");
		} else {
			printf("Lock manager was already bootstrapped\n");
		}
	}

	if(r >= 0) {
		if(openkey_role_add(ctx, OPENKEY_ROLE_CARD_AUTHENTICATOR, "foo") < 0) {
			fprintf(stderr, "Could not add card authenticator role\n");
			exit(6);
		}

		r = openkey_authenticator_prepare(ctx);
		if(r < 0) {
			fprintf(stderr, "Could not prepare card authenticator role\n");
			exit(7);
		} else {
			printf("Card authenticator prepared\n");
		}
	}

	openkey_fini(ctx);

	return 0;
}
