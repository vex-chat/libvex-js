import { sleep } from "@extrahash/sleep";
// tslint:disable-next-line: no-implicit-dependencies
import { Spire } from "@vex-chat/spire";
import fs from "fs";
import _ from "lodash";
import {
    Client,
    IChannel,
    IClientOptions,
    IFileProgress,
    IMessage,
    IServer,
} from "..";
import { Storage } from "../Storage";

let spire: Spire | null = null;

beforeAll(() => {
    // spire = new Spire({
    //     dbType: "sqlite3mem",
    //     logLevel: "error",
    // });
});

describe("Perform client tests", () => {
    const SK = Client.generateSecretKey();

    const clientOptions: IClientOptions = {
        inMemoryDb: true,
        logLevel: "info",
        dbLogLevel: "error",
        host: "localhost:16777",
        unsafeHttp: true,
    };

    const storage = new Storage(":memory:", SK, clientOptions);

    const client = new Client(SK, clientOptions, storage);

    let createdServer: IServer | null = null;
    let createdChannel: IChannel | null = null;
    test("Register", async (done) => {
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
        login(client);

        client.on("authed", async () => {
            done();
        });
    });

    test("Server operations", async (done) => {
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
        createdServer = await client.servers.create("Channel Test Server");
        done();
    });

    test("Channel operations", async (done) => {
        const servers = await client.servers.retrieve();
        const [testServer] = servers;

        const channel = await client.channels.create(
            "Test Channel",
            testServer.serverID
        );

        await client.channels.delete(channel.channelID);

        const channels = await client.channels.retrieve(testServer.serverID);
        expect(channels.length).toBe(1);

        createdChannel = channels[0];

        const retrievedByIDChannel = await client.channels.retrieveByID(
            channels[0].channelID
        );
        expect(channels[0].channelID === retrievedByIDChannel?.channelID).toBe(
            true
        );
        done();
    });

    test("Direct messaging", async (done) => {
        let received = 0;

        const onMessage = (message: IMessage) => {
            if (!message.decrypted) {
                throw new Error("Message failed to decrypt.");
            }
            if (
                message.direction === "incoming" &&
                message.decrypted &&
                message.group === null
            ) {
                received++;
                if (received === 2) {
                    client.off("message", onMessage);
                    done();
                }
            }
        };
        client.on("message", onMessage);

        const me = client.users.me();

        await client.messages.send(me.userID, "initial");
        await sleep(500);
        await client.messages.send(me.userID, "subsequent");
    });

    test("File operations", async (done) => {
        const createdFile = Buffer.alloc(5000000);
        createdFile.fill(0);

        const [createdDetails, key] = await client.files.create(createdFile);
        const fetchedFileRes = await client.files.retrieve(
            createdDetails.fileID,
            key
        );
        if (!fetchedFileRes) {
            throw new Error("Error fetching file.");
        }

        const { data, details } = fetchedFileRes;

        expect(_.isEqual(createdFile, data)).toBe(true);
        expect(_.isEqual(createdDetails, details)).toBe(true);

        done();
    });

    test("Group messaging", async (done) => {
        let received = 0;

        const onGroupMessage = (message: IMessage) => {
            if (!message.decrypted) {
                throw new Error("Message failed to decrypt.");
            }
            if (
                message.direction === "incoming" &&
                message.decrypted &&
                message.group !== null
            ) {
                received++;
                if (received === 2) {
                    client.off("message", onGroupMessage);
                    done();
                }
            }
        };

        client.on("message", onGroupMessage);

        const userIDs = [
            "71ab7ca2-ad89-4de4-90d3-455b32c24fbd",
            "acbc01dc-0207-40f8-b7ca-cded77a93bdf",
            "17e059c2-37fc-471e-9f4c-6fb0027263da",
        ];
        for (const userID of userIDs) {
            await client.permissions.create({
                userID,
                resourceType: "server",
                resourceID: createdServer!.serverID,
            });
        }

        await client.messages.group(createdChannel!.channelID, "initial");
        await sleep(500);
        await client.messages.group(createdChannel!.channelID, "subsequent");
    });

    test("Client close", async (done) => {
        await client.close();
        done();
    });
});

afterAll(() => {
    fs.rmdirSync("files", { recursive: true });
    return spire?.close();
});

/**
 * @hidden
 */
const login = async (client: Client) => {
    const err = await client.login();
    if (err) {
        await client.close();
        throw new Error(err.message);
    }
};
