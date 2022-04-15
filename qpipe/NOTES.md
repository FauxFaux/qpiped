### mint_client

This should probably generate the client key on the client, and
ask the server to sign the cert (on the ssh/eke side); instead of
generating the key on the server and sending it over. I haven't done
this due to issues with `rcgen`/`rustls` not having a convenient API
for signing an arbitrary certificate; instead only making it easy to
sign one they've just generated.

Threat model change: attacker who can observe the contents of the
ssh/eke session can auth in the future, and .. maybe they can
interfere with session setup and observe bulk traffic? Not clear FS
protects against an attacker with the private key? Should probably
know this.

An attacker with full access to the ssh session, or some other access
to  the issuer, can already auth themselves, and likely control the
server process.

Look, the client private key isn't used for session establishment in
client-private-key-less key exchanges, surely they wouldn't have
made it worse. Surely.
