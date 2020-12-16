// tslint:disable: prefer-const
import { Client, IMessage } from "..";
import { loadEnv } from "./loadEnv";

main();

/**
 * @ignore
 */
async function main() {
    loadEnv();

    /* PK is a ed25519 private key encoded as hex
    If you don't provide it, one will be generated */
    const { PK } = process.env;

    const client = new Client(PK, {
        logLevel: "error",
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
        await client.servers.create("hello");

        const servers = await client.servers.retrieve();
        for (const server of servers) {
            const channels = await client.channels.retrieve(server.serverID);
            for (const channel of channels) {
                await client.messages.group(channel.channelID, "Hello world!");
            }
        }
    });

    // listen for new messages
    client.on("message", (message: IMessage) => {
        console.log("IN", "message", message);
    });

    // start the client
    client.init();
}
