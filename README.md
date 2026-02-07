# libvex-js

![build](https://github.com/vex-chat/libvex-js/workflows/build/badge.svg)

nodejs for interfacing with xchat server. Use it for a client, a bot, whatever you'd like to connect to vex.

<a href="https://vex-chat.github.io/libvex-js/">Documentation</a>

## Quickstart

The client now uses an asynchronous factory pattern. You must use `Client.create()` instead of `new Client()`.

```typescript
import { Client } from "@vex-chat/libvex";

async function main() {
    // Generate a secret key (save this securely, it is your identity)
    const privateKey = Client.generateSecretKey();

    // Client.create handles the database connection and crypto initialization for you.
    const client = await Client.create(privateKey, {
        host: "api.vex.wtf",
        logLevel: "info",
    });

    // Register (only needed once per new key)
    // await client.register("Username", "Password123");

    // Login
    await client.login("Username", "Password123");

    // Connect to the WebSocket
    // This establishes the real-time connection.
    await client.connect();

    // Listen for events
    client.on("connected", async () => {
        console.log("Connected as", client.toString());
        const me = client.me.user();

        // Send a message
        await client.messages.send(me.userID, "Hello world!");
    });

    client.on("message", (message) => {
        console.log(
            `Received message from ${message.sender}:`,
            message.message
        );
    });
}

main();
```
