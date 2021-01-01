import { Client, IClientOptions } from "..";

const options: IClientOptions = {
    inMemoryDb: true,
};

test("Register", async (done) => {
    const client = new Client(undefined, options);

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
    const client = new Client(undefined, options);

    client.on("ready", async () => {
        const username = Client.randomUsername();
        const [user, err] = await client.register(username);
        if (err) {
            throw err;
        }

        const loginErr = await client.login();
        if (loginErr) {
            await client.close();
            throw new Error(loginErr.message);
        }
    });

    client.on("authed", async () => {
        await client.close();
        done();
    });

    client.init();
});

test("Direct messaging", async (done) => {
    const client = new Client(undefined, options);

    client.on("ready", async () => {
        const username = Client.randomUsername();
        const [user, err] = await client.register(username);
        if (err) {
            throw err;
        }

        const loginErr = await client.login();
        if (loginErr) {
            await client.close();
            throw new Error(loginErr.message);
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
