/*
 * nfc_helpers.h
 *
 *  Created on: 3 Feb 2013
 *      Author: henryk
 */

#ifndef NFC_HELPERS_H_
#define NFC_HELPERS_H_

#include <nfc/nfc.h>
#include <freefare.h>

extern int helpers_first_tag(nfc_connstring **device_connstring, MifareTag *tag);
extern int helpers_next_tag(nfc_connstring **device_connstring, MifareTag *tag);
extern void helpers_cleanup(void);
extern bool helpers_confirm(void);
extern char *helpers_getpin(int repeat);

#endif /* NFC_HELPERS_H_ */
