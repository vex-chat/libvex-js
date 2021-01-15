# libvex-js

![build](https://github.com/vex-chat/libvex-js/workflows/build/badge.svg)

nodejs for interfacing with xchat server. Use it for a client, a bot, whatever you'd like to connect to vex.

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
