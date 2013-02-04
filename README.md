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

**Note**: Sadly, the NXP DESfire EV1 functional specification and documentation are subject to a non disclosure agreement (NDA). However, no DESfire operation in this framework is handled by the framework itself, all operations are done with functionality or documentation from libfreefare. It is the author's opinion that, given the prior publication of libfreefare and accompanying documentation, the publication of libopenkey does not violate the DESfire NDA.
Is is also for this reason that libopenkey does not use the NXP SAM AV1 or AV2 standard key derivation mechanisms: They are not included in libfreefare and to the best of the author's knowledge still fall under the NDA. Instead, libopenkey uses a custom, simple HMAC-SHA256 based construction.

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

### Complex multi-party case
In this example we'll have one user Alice who want to use the system at her home, at her hacker space (administrated by Jane) and her workplace (administrated by John). We'll also assume that Alice doesn't use the same computer to create cards and to verify cards at the door, which we guess to be the default case with larger installations (such as hacker spaces and work places) as well.

#### Alice's preparation
Alice uses her initialization and managing computer to initialize a card and associate it with her lock domain (we'll use wildcards for the UID, because it's not really important):

    openkey-producer alices_home_secrets Alices_card
    openkey-manager alices_home_secrets alices_home_secrets/*-Alices_card/Alices_card-0

this will initialize the card and associate it with Alice's newly created lock domain. Alice then copies the file alices_home_secrets/lock to her door lock computer which is the only file the door lock needs in order to authenticate cards.

#### Jane's preparation
It is recommended that any lock domain except home use choose a default slot number different from 0. Jane is a bit of an Illuminatus! fan and chooses five. She then bootstraps only her lock manager, since she doesn't want to initialize any cards:

    openkey-manager -b -s 5 hackspace_secrets

which will create a new file hackspace_secrets/lock that Jane needs to distribute to all locks under her control. Jane also needs to communicate "We're using slot five, so when you want to associate your card, preferably bring the transport key file for slot five" to Alice.

#### John's preparation
John arbitrarily chooses seven as the slot number for his company. He initializes his lock domain with:

    openkey-manager -b -s 7 workplace_secrets

and also transfers the workplace_secrets/lock file to his locks and communicates the slot number to Alice.

#### Alice's association with Jane
In order for her card to be incorporated into the system Alice transmits the alices_home_secrets/*-Alices_card/Alices_card-5 transport key file to Jane (for example on an USB stick, or through encrypted mail). Alice then visits Jane and puts her card on Jane's card reader. Jane commands:

    openkey-manager hackspace_secrets Alices_card-5

after which slot five on Alice's card is associated with Jane's lock domain. This creates a copy of the transport key file in the hackspace_secrets secrets directory with a file name equally the slot UUID, so that Jane can see which cards she previously associated with her domain.

#### Alice's association with John
The process with John is just the same, except now Alice transmits and John uses the Alices_card-7 file:

    openkey-manager workplace_secrets Alices_card-7

after this command slot seven on Alice's card is associated with John's lock domain.

#### Happy end
Alice can now use her card at home (with slot 0), at her hacker space (with slot 5) and in her work place (with slot 7). Since no identifying information about a lock domain is stored on the card in the process, Alice's employer can not find out from the card to which hacker space Alice goes. Also a thief/dishonest finder who happens upon the card has no way of knowing on which locks it will be of use.
