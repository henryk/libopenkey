#include "libopenkey.h"

struct openkey_context {
	uint8_t roles_initialized;

	struct {
		char *producer_path;
		int bootstrapped;
	} p;

	struct {
		char *manager_path;
		int bootstrapped;
		int preferred_slot;
	} m;

	struct {
		char *authenticator_path;
		int bootstrapped;
	} a;
};
