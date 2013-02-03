# libopenkey - Open framework to use DESfire cards as secure pseudonymous authentication tokens.

This library provides a framework to use NXP DESfire EV1 cards as authentication tokens, e.g. for opening a door, with a security level that equals or exceeds all similar existing systems and some unique anonymity/pseudonymity functions.

## Features
<dl>
  <dt>One card in many contexts</dt>
  <dd>Each card has multiple fully independent slots, each can be used with a different lock/system.</dd>
  <dt>Separation of roles</dt>
  <dd>The party doing the card initialization is fully independent from the party doing the authentication.</dd> 
  <dt>Secure</dt>
  <dd>All security is based on AES 128 bit. Master keys are randomly generated. All authentication keys are derived from master keys with card and/or slot specific identifiers.</dd>
  <dt>Full anonymity on the radio channel</dt>
  <dd>No card identifying information is transmitted unencrypted on the radio channel after card initialization time.</dd>
  <dt>Optional pseudonymity for authentication</dt>
  <dd>The identifiers used by authenticating parties are different for each slot and can not be correlated. (However, an authenticating party acting in bad faith <em>can</em> read the card unique identifier.)</dd>
</dl>

## Requirements
 * libgcrypt - For cryptographic operations and random numbers.
 * libuuid - For handling and generation of Universally Unique IDentifiers.
 * libfreefare >= 0.3.5 - For the actual DESfire communication.
 * libnfc >= 1.7.0-rc3 - For contactless card communication (also required by libfreefare).
 * autotools and libtool - For automatic configuration and makefiles
 * A libnfc supported reader
 * DESfire EV1 cards

## Installation
    git clone https://github.com/henryk/libopenkey.git
    cd libopenkey
    autoreconf -vis
    ./configure
    make
    make install
 
## Roles
 
libopenkey distinguishes three roles: card producer, lock manager and card authenticator. Keys and other data for each role are stored in directories and files under a given base directory. File/directory names are designed in such a way that all three roles may use the same directory, for maximum convenience in simple installations where all roles are associated with the same entity.   
 
### Card producer
The card producer initializes an empty DESfire EV1 card to be used with the libopenkey framework and handles all related key management. This should be an entity trusted by the user, for example the user him- or herself. When producing a card all keys relevant to the authentication procedure are set to random transport keys. These are also stored in transport key files (one file per slot), to enable communication with the lock manager.
 
### Lock manager
The lock manager handles key management for one lock domain (e.g. one or multiple locks with the same key) and, when provided with the transport key file, can take possession of one slot on an initialized card.
 
### Card authenticator
The card authenticator receives the master keys from the lock manager and uses them to authenticate cards. Authentication will yield two results: Proof that a slot on the card was previously associated with this lock domain through the lock manager, and a card/slot specific authenticated UUID that can be used for further actions (e.g. compared to a blacklist).

## Use cases

### Simple home use: One entity does everything
In this example we'll store all secret keys and related data in a directory called openkey_secrets under the current working directory. You may change this path to something more fitting if you want to, but need to adjust all example commands accordingly.

Initialize an empty card and call it "my_card" with 

    openkey-producer openkey_secrets my_card

which will create a subdirectory under openkey_secrets with a name that includes the card UID and the given card name (e.g. 04654CEA641E80-my_card). In this directory there will be one file for each slot (e.g. my_card-0 through my_card-14).

Using a slot transport key file (e.g. openkey_secrets/04654CEA641E80-my_card/my_card-0) associate the card with your authenticator with

    openkey-manager openkey_secrets openkey_secrets/04654CEA641E80-my_card/my_card-0

which will copy the transport key file into a subdirectory under openkey_secrets named cards into a file named for the slot UUID (e.g. b8bc2410-19f4-4547-b86e-a1317d89c88a).

Now when you run the authenticator in stdout mode

    openkey-authenticator openkey_secrets

it will print the slot UUID any time that you present the card.
