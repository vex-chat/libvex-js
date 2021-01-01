import { sleep } from "@extrahash/sleep";
import fs from "fs";
import _ from "lodash";
import { Client, IClientOptions } from "..";

test("Register", async (done) => {
    const SK = Client.generateSecretKey();
    const client = new Client(SK);

    Client.saveKeyFile("./test.key", "hunter2", client.getKeys().private);

    client.on("ready", async () => {
        const username = Client.randomUsername();
        const [user, err] = await client.register(username);
        if (err) {
            throw err;
        }
        expect(user!.username === username).toBe(true);
        done();
    });

    client.init();
});

test("Login", async (done) => {
    const SK = Client.loadKeyFile("test.key", "hunter2");
    const client = new Client(SK);

    client.on("ready", async () => {
        login(client);
    });

    client.on("authed", async () => {
        await client.close();
    });

    client.on("closed", () => {
        done();
    });

    client.init();
});

test("Direct messaging", async (done) => {
    const SK = Client.loadKeyFile("test.key", "hunter2");
    const client = new Client(SK);

    client.on("ready", async () => {
        login(client);
    });

    client.on("authed", async () => {
        const me = client.users.me();

        for (let i = 0; i < 2; i++) {
            await client.messages.send(me.userID, i.toString());
        }
    });

    let received = 0;
    client.on("message", async (message) => {
        if (!message.decrypted) {
            throw new Error("Message failed to decrypt.");
        }
        if (message.direction === "incoming" && message.decrypted) {
            received++;
            if (received === 2) {
                const history = await client.messages.retrieve(
                    client.users.me().userID
                );
                // check we received everything OK
                expect(history.length === 2).toBe(true);
                await client.close();
            }
        }
    });

    client.on("closed", () => {
        done();
    });

    client.init();
});

test("Server operations", async (done) => {
    const SK = Client.loadKeyFile("test.key", "hunter2");
    const client = new Client(SK);

    client.on("ready", async () => {
        login(client);
    });

    client.on("authed", async () => {
        const server = await client.servers.create("Test Server");
        const serverList = await client.servers.retrieve();

        const [knownServer] = serverList;
        expect(server.serverID === knownServer.serverID).toBe(true);

        const retrieveByIDServer = await client.servers.retrieveByID(
            server.serverID
        );
        expect(server.serverID === retrieveByIDServer?.serverID).toBe(true);

        await client.servers.delete(server.serverID);

        // make another server to be used by channel tests
        await client.servers.create("Channel Test Server");
        await client.close();
    });

    client.on("closed", () => {
        done();
    });

    client.init();
});

test("Channel operations", async (done) => {
    const SK = Client.loadKeyFile("test.key", "hunter2");
    const client = new Client(SK);

    client.on("ready", async () => {
        login(client);
    });

    client.on("authed", async () => {
        const servers = await client.servers.retrieve();
        const [testServer] = servers;

        const channel = await client.channels.create(
            "Test Channel",
            testServer.serverID
        );

        await client.channels.delete(channel.channelID);

        const channels = await client.channels.retrieve(testServer.serverID);
        expect(channels.length).toBe(1);

        const retrievedByIDChannel = await client.channels.retrieveByID(
            channels[0].channelID
        );
        expect(channels[0].channelID === retrievedByIDChannel?.channelID).toBe(
            true
        );

        await client.close();
    });

    client.on("closed", () => {
        done();
    });

    client.init();
});

const login = async (client: Client) => {
    const err = await client.login();
    if (err) {
        await client.close();
        throw new Error(err.message);
    }
};
