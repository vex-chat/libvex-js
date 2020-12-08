# xchat-js

nodejs for interfacing with xchat server.

Example usage:

```ts
import { Client, IMessage } from ".";

main();

async function main() {
    // initialize the client. you can provide your secret key
    // as the first parameter or one will be generated for you.
    const client = new Client();

    client.on("ready", async () => {
        console.log("Client ready.");

        // we get the secret key and save it somewhere permanent and safe
        console.log("secret", client.getSecret());

        /* you must register your identity with the server
        before logging in the first time. usernames and keys 
        must be unique */
        let [user, err] = await client.register("my-username");
        if (err) {
            console.error(err);
        }

        // login to the server
        err = await client.login();
        if (err) {
            console.error(err);
            process.exit(1);
        }
    });

    client.on("authed", async () => {
        console.log("Client authorized.");

        // get the accounts we know about
        const familiars = await client.familiars.retrieve();

        // send each of them a message
        for (const user of familiars) {
            client.messages.send(user.userID, "hello friend");
        }
    });

    // listen for new messages
    client.on("message", (message: IMessage) => {
        console.log("message", message);
    });

    // start the client
    client.init();
}
```
