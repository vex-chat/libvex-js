import { Client, IClientOptions } from "..";
import fs from "fs";

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
        expect(user!.username === username);
        done();
    });

    client.init();
});

test("Login", async (done) => {
    const SK = Client.loadKeyFile("test.key", "hunter2");
    const client = new Client(SK);

    client.on("ready", async () => {
        const err = await client.login();
        if (err) {
            await client.close();
            throw new Error(err.message);
        }
    });

    client.on("authed", async () => {
        await client.close();
        done();
    });

    client.init();
});

test("Direct messaging", async (done) => {
    const SK = Client.loadKeyFile("test.key", "hunter2");
    const client = new Client(SK);

    client.on("ready", async () => {
        const err = await client.login();
        if (err) {
            await client.close();
            throw new Error(err.message);
        }
    });

    client.on("authed", async () => {
        const me = client.users.me();

        for (let i = 0; i < 5; i++) {
            await client.messages.send(me.userID, i.toString());
        }
    });

    let received = 0;
    client.on("message", async (message) => {
        if (message.direction === "incoming" && message.decrypted) {
            received++;
            if (received === 5) {
                const history = await client.messages.retrieve(
                    client.users.me().userID
                );
                // check we received everything OK
                expect(history.length === 5).toBe(true);

                await client.close();
                done();
            }
        }
        if (!message.decrypted) {
            throw new Error("Message failed to decrypt.");
        }
    });

    client.init();
});

test("cleanup", () => {
    const SK = Client.loadKeyFile("test.key", "hunter2");
    const client = new Client(SK);

    fs.unlinkSync(client.getKeys().public + ".sqlite");
    fs.unlinkSync("test.key");
});
