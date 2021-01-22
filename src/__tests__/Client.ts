import { sleep } from "@extrahash/sleep";
// tslint:disable-next-line: no-implicit-dependencies
import fs from "fs";
import _ from "lodash";
import { Client, IChannel, IClientOptions, IMessage, IServer, IUser } from "..";

let clientA: Client | null = null;

beforeAll(async () => {
    const SK = Client.generateSecretKey();

    const clientOptions: IClientOptions = {
        inMemoryDb: true,
        logLevel: "warn",
        dbLogLevel: "warn",
        // host: "localhost:16777",
        // unsafeHttp: true,
    };
    clientA = await Client.create(SK, clientOptions);
    if (!clientA) {
        throw new Error("Couldn't create client.");
    }
});

describe("Perform client tests", () => {
    let createdServer: IServer | null = null;
    let createdChannel: IChannel | null = null;

    const username = Client.randomUsername();
    const password = "hunter2";

    let userDetails: IUser | null = null;
    test("Register", async (done) => {
        const [user, err] = await clientA!.register(username, password);
        if (err) {
            throw err;
        }
        userDetails = user;
        expect(user!.username === username).toBe(true);
        done();
    });

    test("Login", () => {
        return login(clientA!, username, password);
    });

    test("Connect", async (done) => {
        clientA!.on("connected", () => {
            done();
        });

        await clientA!.connect();
    });

    test("Server operations", async (done) => {
        const server = await clientA!.servers.create("Test Server");
        const serverList = await clientA!.servers.retrieve();

        const [knownServer] = serverList;
        expect(server.serverID === knownServer.serverID).toBe(true);

        const retrieveByIDServer = await clientA!.servers.retrieveByID(
            server.serverID
        );
        expect(server.serverID === retrieveByIDServer?.serverID).toBe(true);

        await clientA!.servers.delete(server.serverID);

        // make another server to be used by channel tests
        createdServer = await clientA!.servers.create("Channel Test Server");

        done();
    });

    test("Channel operations", async (done) => {
        const servers = await clientA!.servers.retrieve();
        const [testServer] = servers;

        const channel = await clientA!.channels.create(
            "Test Channel",
            testServer.serverID
        );

        await clientA!.channels.delete(channel.channelID);

        const channels = await clientA!.channels.retrieve(testServer.serverID);
        expect(channels.length).toBe(1);

        createdChannel = channels[0];

        const retrievedByIDChannel = await clientA!.channels.retrieveByID(
            channels[0].channelID
        );
        expect(channels[0].channelID === retrievedByIDChannel?.channelID).toBe(
            true
        );
        done();
    });

    test("Direct messaging", async (done) => {
        const received: string[] = [];

        const receivedAllExpected = () =>
            received.includes("initial") && received.includes("subsequent");

        const onMessage = (message: IMessage) => {
            if (!message.decrypted) {
                throw new Error("Message failed to decrypt.");
            }
            if (
                message.direction === "incoming" &&
                message.decrypted &&
                message.group === null
            ) {
                received.push(message.message);
                if (receivedAllExpected()) {
                    clientA!.off("message", onMessage);
                    done();
                }
            }
        };
        clientA!.on("message", onMessage);

        const me = clientA!.me.user();

        await clientA!.messages.send(me.userID, "initial");
        await sleep(500);
        await clientA!.messages.send(me.userID, "subsequent");
    });

    test("File operations", async (done) => {
        const createdFile = Buffer.alloc(1000);
        createdFile.fill(0);

        const [createdDetails, key] = await clientA!.files.create(createdFile);
        const fetchedFileRes = await clientA!.files.retrieve(
            createdDetails.fileID,
            key
        );
        if (!fetchedFileRes) {
            throw new Error("Error fetching file.");
        }

        const { data, details } = fetchedFileRes;

        expect(_.isEqual(createdFile, data)).toBe(true);
        expect(_.isEqual(createdDetails.nonce, details.nonce)).toBe(true);

        done();
    });

    test("Upload an emoji", async (done) => {
        const buf = fs.readFileSync("./src/__tests__/triggered.png");
        const emoji = await clientA!.emoji.create(buf, "triggered");
        console.log(emoji);
        const list = await clientA?.emoji.retrieveList();
        expect([emoji]).toEqual(list);
        done();
    });

    test("Upload an avatar", async (done) => {
        const buf = fs.readFileSync("./src/__tests__/ghost.png");
        await clientA!.me.setAvatar(buf);
        done();
    });

    test("Create invite", async (done) => {
        if (!createdServer) {
            throw new Error("Server not created, can't do invite test.");
        }

        const invite = await clientA!.invites.create(
            createdServer.serverID,
            "1h"
        );
        await clientA?.invites.redeem(invite.inviteID);

        const serverInviteList = await clientA?.invites.retrieve(
            createdServer.serverID
        );
        done();
    });

    test("Group messaging", async (done) => {
        const received: string[] = [];

        const receivedAllExpected = () =>
            received.includes("initial") && received.includes("subsequent");

        const onGroupMessage = (message: IMessage) => {
            if (!message.decrypted) {
                throw new Error("Message failed to decrypt.");
            }
            if (
                message.direction === "incoming" &&
                message.decrypted &&
                message.group !== null
            ) {
                received.push(message.message);
                if (receivedAllExpected()) {
                    done();
                }
            }
        };

        clientA!.on("message", onGroupMessage);

        await clientA!.messages.group(createdChannel!.channelID, "initial");
        await sleep(500);
        await clientA!.messages.group(createdChannel!.channelID, "subsequent");
    });
});

/**
 * @hidden
 */
const login = async (client: Client, username: string, password: string) => {
    const err = await client.login(username, password);
    if (err) {
        console.error(JSON.stringify(err));
        await client.close();
        throw new Error(err.toString());
    }
};
