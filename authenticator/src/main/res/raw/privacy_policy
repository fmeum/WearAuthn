# WearAuthn Privacy Policy

The Wear OS app [WearAuthn](https://play.google.com/store/apps/details?id=me.henneke.wearauthn.authenticator) is a U2F/FIDO2-compliant authenticator. It can be used to register with and, afterwards, log in to websites that use WebAuthn for second-factor or single-factor login.

WearAuthn only exchanges data with previously paired and connected Bluetooth devices and via NFC, and only to the extent of the [CTAP2 specification](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html) for FIDO2-compliant authenticators. In particular, WearAuthn does not transmit (or receive) data over the internet and does not contain trackers or advertisement of any kind.

WearAuthn can be operated in second-factor or single-factor mode. In second-factor mode, WearAuthn will

* only after acquiring consent from the user, create a random, uniquely identifying public/private key pair on the watch, store the private key pair in secure OS facilities, and share the public key with the device that requested so via Bluetooth or NFC. This public key will be forwarded to the website the user is currently registering with by that device.
* only after acquiring consent from the user, reveal the possession of a private key belonging to either a provided public key or a provided website identifier and perform cryptographic operations using that private key. If the user has granted explicit consent at registration time and on a per-key basis, this action may also take place silently ("silent authentication").
* only after acquiring consent from the user, store the identifiers of websites with which it has been registered.
* maintain a usage counter for every key pair.
* **not** store any personal information.

Additionally, in single-factor mode, WearAuthn will

* only after acquiring consent from the user, store a username and real name received from a connected device and associate this information with a key pair. This personal information is encrypted with the user's screen lock credential and will be deleted if the screen lock is disabled.
* only after acquiring consent from the user and if the watch has recently been unlocked, show usernames and real names associated with key pairs on the watch or send them to the connected device.
* **not** reveal any personal information unless the device is unlocked and the screen lock credential has recently been confirmed.
