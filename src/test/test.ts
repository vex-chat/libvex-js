// tslint:disable: prefer-const
import { XUtils } from "@vex-chat/crypto-js";
import nacl from "tweetnacl";
import { Client, IMessage } from "..";
import { loadEnv } from "./loadEnv";

main();

async function main() {
    loadEnv();

    /* PK is a ed25519 private key encoded as hex
    If you don't provide it, one will be generated */
    const { PK } = process.env;

    const client = new Client(undefined, {
        logLevel: "info",
        dbFolder: "databases",
    });

    client.on("ready", async () => {
        console.log("Client ready.");

        // get our private keys and store them somewhere safe.
        console.log("keys", client.getKeys());

        /* you must register your identity with the server
        before logging in the first time. usernames and keys 
        must be unique */
        let [user, err] = await client.register(Client.randomUsername());
        if (err) {
            console.error(err);
        }

        // login to the server
        err = await client.login();
        if (err) {
            console.warn(err);
            process.exit(1);
        }
    });

    client.on("authed", async () => {
        console.log("Client authorized.");
        // print our user info
        console.log("user", client.users.me());

        setInterval(async () => {
            // get the accounts we know about
            const familiars = await client.familiars.retrieve();
            // send each of them a message
            for (const user of familiars) {
                client.messages.send(
                    user.userID,
                    Buffer.from(nacl.randomBytes(8)).toString("base64")
                );

                // message history
                const history = await client.messages.retrieve(user.userID);
            }
        }, 1000 * 10);

        // get all of our sessions
        const sessions = await client.sessions.retrieve();

        for (const session of sessions) {
            console.log(session);
            console.log(client.sessions.verify(session));
        }
        // verify the mnemonic with the other user through a secure channel
    });

    // listen for new messages
    client.on("message", (message: IMessage) => {
        console.log("message", message);
    });

    // start the client
    client.init();
}
