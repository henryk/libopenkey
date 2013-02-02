/*
 ============================================================================
 Name        : exampleProgram.c
 Author      : Henryk Plötz
 Version     :
 Copyright   : (c) 2013 Henryk Plötz
 Description : Uses shared library to print greeting
               To run the resulting executable the LD_LIBRARY_PATH must be
               set to ${project_loc}/libopenkey/.libs
               Alternatively, libtool creates a wrapper shell script in the
               build directory of this program which can be used to run it.
               Here the script will be called exampleProgram.
 ============================================================================
 */

#include "libopenkey.h"

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