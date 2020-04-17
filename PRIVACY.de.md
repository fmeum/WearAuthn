# Datenschutzhinweise für WearAuthn

Die Wear OS-App [WearAuthn](https://play.google.com/store/apps/details?id=me.henneke.wearauthn.authenticator) ist ein U2F/FIDO2-kompatibler Sicherheitsschlüssel. Sie kann als zweiter oder einziger Faktor für die Anmeldung auf Webseiten benutzt werden.

WearAuthn tauscht Daten nur mit vorher gekoppelten und verbundenen Bluetooth-Geräten und per NFC aus. Beides geschieht ausschließlich im Rahmen der [CTAP 2.1-Spezifikation](https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html) für FIDO2-kompatible Sicherheitsschlüssel. Inbesondere überträgt (oder empfängt) WearAuthn selbst keine Daten über das Internet und enhält keine "Tracker" oder Werbund in jedweder Form.

WearAuthn kann im Zwei-Faktor- oder im passwortlosen Modus betrieben werden. Im Zwei-Faktor-Modus wird WearAuthn

* nur mit expliziter Zustimmung des Nutzers ein zufällig erzeugtes und eindeutig identifizierendes Schlüsselpaar auf der Uhr erstellen, von dem der private Schlüssel in sicheren Betriebssystemelementen gespeichert und der öffentliche Schlüssel per Bluetooth oder NFC an das anfordernde Gerät übertragen wird. Der öffentliche Schlüssel wird dann von diesem Gerät an die Webseite weitergeleitet, auf der der Nutzer sich gerade registriert.
* nur mit expliziter Zustimmung des Nutzers den Besitz eines privaten Schlüssels offenbaren, der zu einem gegebenen öffentlichen Schlüssel oder einer gegebenen Webseite gehört, und kryptographische Operationen mit diesem Schlüssel ausführen. Dies kann auch ohne die Zustimmung der Nutzers erfolgen ("silent authentication"), falls das verbundene Gerät dies verlangt, hierbei wird dem Ergebnis allerdings eine spezifische kryptographische Markierung hinzugefügt.
* nur mit expliziter Zustimmung der Nutzers die Adressen von Webseiten speichern, für die eine Registrierung vorliegt.
* für jedes Schlüsselpaar die Häufigkeit der Benutzung speichern.
* **keinerlei** persönliche Daten speichern.

Im passwortlosen Modus wird WearAuthn zusätzlich

* nur mit expliziter Zustimmung des Nutzers den Nutzernamen sowie den realen Namen, die von einem verbundenen Gerät empfangen wurden, speichern und mit einem Schlüsselpaar verknüpfen. Diese persönlichen Informationen werden indirekt mit dem Displaysperrenpasswort der Uhr verschlüsselt und unkenntlich gemacht, sobald die Displaysperre deaktiviert wird.
* nur mit expliziter Zustimmung des Nutzers und falls die Uhr vor kurzer Zeit entsperrt wurde die Nutzernamen und realen Namen, die mit Schlüsselpaaren auf der Uhr verknüpft sind, anzeigen oder an verbundene Geräte senden.
* **keinerlei** persönliche Daten offenbaren, ohne dass die Uhr entsperrt ist und vor kurzer Zeit das Displaysperrenpasswort eingegeben wurde.
