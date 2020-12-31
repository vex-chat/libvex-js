# vex-js

nodejs for interfacing with xchat server. Use it for a client, a bot, whatever you'd like to conncet to vex.

<a href="https://vex-chat.github.io/libvex-js/">Documentation</a>

## Quickstart

```ts
import { Client } from "@vex-chat/libvex";

async function main() {
    // generate a secret key to use, save this somewhere permanent
    const privateKey = Client.generateSecretKey();

    const client = new Client(privateKey);

    /* the ready event is emitted when init() is finished.
    you must wait until this event fires to perform 
    registration or login. */
    client.on("ready", async () => {
        // you must register once before you can log in
        await client.register(Client.randomUsername());
        await client.login();
    });

    /* The authed event fires when login() successfully completes
    and the server indicates you are authorized. You must wait to
    perform any operations besides register() and login() until
    this occurs. */
    client.on("authed", async () => {
        const me = await client.users.me();

        // send a message
        await client.messages.send(me.userID, "Hello world!");
    });

    /* Outgoing and incoming messages are emitted here. */
    client.on("message", (message) => {
        console.log("message:", message);
    });

    /* you must call init() to initialize the keyring and 
    start the client. */
    client.init();
}

main();
```

## Cryptography Notice

This distribution includes cryptographic software. The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software.
BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, or use, and re-export of encryption software, to see if this is permitted.
See <http://www.wassenaar.org/> for more information.

The U.S. Government Department of Commerce, Bureau of Industry and Security (BIS), has classified this software as Export Commodity Control Number (ECCN) 5D002.C.1, which includes information security software using or performing cryptographic functions with asymmetric algorithms.
The form and manner of this distribution makes it eligible for export under the License Exception ENC Technology Software Unrestricted (TSU) exception (see the BIS Export Administration Regulations, Section 740.13) for both object code and source code.
