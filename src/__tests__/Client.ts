import { sleep } from "@extrahash/sleep";
// tslint:disable-next-line: no-implicit-dependencies
import { Spire } from "@vex-chat/spire";
import fs from "fs";
import _ from "lodash";
import { Client, IChannel, IClientOptions, IMessage, IServer, IUser } from "..";

let spire: Spire | null = null;

beforeAll(() => {
    // spire = new Spire({
    //     dbType: "sqlite3mem",
    //     logLevel: "warn",
    // });
});

describe("Perform client tests", () => {
    const SK = Client.generateSecretKey();

    const clientOptions: IClientOptions = {
        inMemoryDb: true,
        logLevel: "error",
        dbLogLevel: "error",
        unsafeHttp: true,
        host: "localhost:16777",
    };

    const clientA = new Client(SK, clientOptions);

    let createdServer: IServer | null = null;
    let createdChannel: IChannel | null = null;

    const username = Client.randomUsername();
    const password = "hunter2";

    let userDetails: IUser | null = null;
    test("Register", async (done) => {
        clientA.on("ready", async () => {
            const [user, err] = await clientA.register(username, password);
            if (err) {
                throw err;
            }
            userDetails = user;
            expect(user!.username === username).toBe(true);
            done();
        });

        clientA.init();
    });

    test("Login", async (done) => {
        login(clientA, username, password);

        clientA.on("authed", async () => {
            done();
        });
    });

    test("Multiple devices", async (done) => {
        jest.setTimeout(10000);
        const ASK2 = Client.generateSecretKey();
        const clientA2 = new Client(ASK2, {
            ...clientOptions,
            logLevel: "warn",
        });

        const BSK = Client.generateSecretKey();
        const clientB = new Client(BSK, { ...clientOptions, logLevel: "warn" });

        await new Promise(async (res, rej) => {
            let newReady = false;
            let otherReady = false;

            clientA2.on("ready", async () => {
                await clientA2.registerDevice(username, password);
                await clientA2.login(username);
            });
            clientA2.on("authed", async () => {
                await sleep(500);
                newReady = true;
            });

            clientB.on("ready", async () => {
                const otherUsername = Client.randomUsername();
                await clientB.register(otherUsername, password);
                await clientB.login(otherUsername);
            });
            clientB.on("authed", async () => {
                await sleep(500);
                otherReady = true;
            });

            clientA2.init();
            clientB.init();

            let timeout = 5;
            while (true) {
                if (newReady && otherReady) {
                    res();
                }
                await sleep(Math.log(timeout));
                timeout *= 2;
            }
        });

        await new Promise(async (res, rej) => {
            const receivedA: string[] = [];
            const receivedA2: string[] = [];
            const receivedB: string[] = [];

            const userA = clientA.me.user().userID;
            const userB = clientB.me.user().userID;

            const onAMessage = (message: IMessage) => {
                if (!message.decrypted) {
                    throw new Error("Message failed to decrypt.");
                }
                receivedA.push(message.message);
            };

            const onA2Message = (message: IMessage) => {
                if (!message.decrypted) {
                    throw new Error("Message failed to decrypt.");
                }
                receivedA2.push(message.message);
            };

            const onBMessage = (message: IMessage) => {
                if (!message.decrypted) {
                    throw new Error("Message failed to decrypt.");
                }
                receivedB.push(message.message);
            };

            clientA.on("message", onAMessage);
            clientA2.on("message", onA2Message);
            clientB.on("message", onBMessage);

            (async () => {
                while (true) {
                    clientA.messages.send(userB, "clientA");
                    clientA2.messages.send(userB, "clientA2");
                    clientB.messages.send(userA, "clientB");
                    await sleep(1000);
                }
            })();

            const expectedResults = ["clientA", "clientA2", "clientB"];
            const receivedResults = (results: string[]) => {
                return [...new Set(results)].sort();
            };

            let timeout = 5;
            while (true) {
                const received =
                    receivedA.length + receivedA2.length + receivedB.length;
                // console.log("A", receivedResults(receivedA));
                // console.log("A2", receivedResults(receivedA2));
                // console.log("B", receivedResults(receivedB));

                if (
                    _.isEqual(receivedResults(receivedA), expectedResults) &&
                    _.isEqual(receivedResults(receivedA2), expectedResults) &&
                    _.isEqual(receivedResults(receivedB), expectedResults) &&
                    received > 20
                ) {
                    clientA.off("message", onAMessage);
                    clientA2.off("message", onA2Message);
                    clientB.off("message", onBMessage);
                    done();
                    break;
                }
                await sleep(Math.log(timeout));
                timeout = timeout * 2;
            }
        });
        done();
    });

    test("Server operations", async (done) => {
        const server = await clientA.servers.create("Test Server");
        const serverList = await clientA.servers.retrieve();

        const [knownServer] = serverList;
        expect(server.serverID === knownServer.serverID).toBe(true);

        const retrieveByIDServer = await clientA.servers.retrieveByID(
            server.serverID
        );
        expect(server.serverID === retrieveByIDServer?.serverID).toBe(true);

        await clientA.servers.delete(server.serverID);

        // make another server to be used by channel tests
        createdServer = await clientA.servers.create("Channel Test Server");
        done();
    });

    test("Channel operations", async (done) => {
        const servers = await clientA.servers.retrieve();
        const [testServer] = servers;

        const channel = await clientA.channels.create(
            "Test Channel",
            testServer.serverID
        );

        await clientA.channels.delete(channel.channelID);

        const channels = await clientA.channels.retrieve(testServer.serverID);
        expect(channels.length).toBe(1);

        createdChannel = channels[0];

        const retrievedByIDChannel = await clientA.channels.retrieveByID(
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
                    clientA.off("message", onMessage);
                    done();
                }
            }
        };
        clientA.on("message", onMessage);

        const me = clientA.me.user();

        await clientA.messages.send(me.userID, "initial");
        await clientA.messages.send(me.userID, "subsequent");
    });

    test("File operations", async (done) => {
        const createdFile = Buffer.alloc(1000);
        createdFile.fill(0);

        const [createdDetails, key] = await clientA.files.create(createdFile);
        const fetchedFileRes = await clientA.files.retrieve(
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

    test("Upload an avatar", async (done) => {
        const buf = fs.readFileSync("./src/__tests__/ghost.png");
        await clientA.me.setAvatar(buf);
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

        clientA.on("message", onGroupMessage);

        const userIDs: string[] = [
            /*
            "71ab7ca2-ad89-4de4-90d3-455b32c24fbd",
            "acbc01dc-0207-40f8-b7ca-cded77a93bdf",
            "17e059c2-37fc-471e-9f4c-6fb0027263da",
         */
        ];
        for (const userID of userIDs) {
            await clientA.permissions.create({
                userID,
                resourceType: "server",
                resourceID: createdServer!.serverID,
            });
        }

        await clientA.messages.group(createdChannel!.channelID, "initial");
        await sleep(500);
        await clientA.messages.group(createdChannel!.channelID, "subsequent");
    });
});

afterAll(async (done) => {
    const createdDirs = ["files", "avatars"];
    for (const dir of createdDirs) {
        fs.rmdirSync(dir, { recursive: true });
    }
    try {
        await spire?.close();
        done();
    } catch (err) {
        console.warn(err);
        done();
    }
});

/**
 * @hidden
 */
const login = async (clientA: Client, username: string, password: string) => {
    const err = await clientA.login(username);
    if (err) {
        await clientA.close();
        throw new Error(err.message);
    }
};
