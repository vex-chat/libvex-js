# vex-js

nodejs for interfacing with xchat server.

## Quickstart

```ts
export function initClient(): void {
    const PK = Client.generateSecretKey();
    client = new Client(PK, {
        dbFolder: progFolder,
        logLevel: "info",
    });
    client.on("ready", async () => {
        // you can retrieve users before you login
        const registeredUser = await client.users.retrieve(
            client.getKeys().public
        );
        if (registeredUser) {
            await client.login();
        } else {
            await client.register("MyUsername");
            await client.login();
        }
    });
    client.on("authed", async () => {
        const familiars = await client.users.familiars();
        for (const user of familiars) {
            client.messages.send(user.userID, "Hello world!");
        }
    });
    client.init();
}

initClient();
```
