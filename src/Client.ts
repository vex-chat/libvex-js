// tslint:disable: no-empty-interface

import { sleep } from "@extrahash/sleep";
import {
    xConcat,
    xConstants,
    xDH,
    xEncode,
    xHMAC,
    xKDF,
    XKeyConvert,
    xMakeNonce,
    xMnemonic,
    XUtils,
} from "@vex-chat/crypto";
import { XTypes } from "@vex-chat/types";
import ax, { AxiosError } from "axios";
import chalk from "chalk";
import { EventEmitter } from "events";
import nacl from "tweetnacl";
import * as uuid from "uuid";
import winston from "winston";
import WebSocket from "ws";
import { Database } from "./Database";
import { capitalize } from "./utils/capitalize";
import { createLogger } from "./utils/createLogger";
import { uuidToUint8 } from "./utils/uint8uuid";

/**
 * IMessage is a chat message.
 */
export interface IMessage {
    nonce: string;
    mailID: string;
    sender: string;
    recipient: string;
    message: string;
    direction: "incoming" | "outgoing";
    timestamp: Date;
    decrypted: boolean;
    group: string | null;
}

/**
 * IPermission is a permission to a resource.
 */
export interface IPermission extends XTypes.SQL.IPermission {}

/**
 * IKeys are a pair of ed25519 public and private keys,
 * encoded as hex strings.
 */
export interface IKeys {
    public: string;
    private: string;
}

/**
 * IUser is a single user on the vex platform.
 */
export interface IUser extends XTypes.SQL.IUser {}

/**
 * ISession is an end to end encryption session with another peer.
 */
export interface ISession extends XTypes.SQL.ISession {}

/**
 * IChannel is a chat channel on a server.
 */
export interface IChannel extends XTypes.SQL.IChannel {}

/**
 * IServer is a single chat server.
 */
export interface IServer extends XTypes.SQL.IServer {}

/**
 * @ignore
 */
interface IUsers {
    retrieve: (userID: string) => Promise<[IUser | null, AxiosError | null]>;
    me: () => XTypes.SQL.IUser;
    familiars: () => Promise<IUser[]>;
}

/**
 * @ignore
 */
interface IMessages {
    send: (userID: string, message: string) => Promise<void>;
    group: (channelID: string, message: string) => Promise<void[]>;
    retrieve: (userID: string) => Promise<IMessage[]>;
    retrieveGroup: (channelID: string) => Promise<IMessage[]>;
}

/**
 * @ignore
 */
interface IServers {
    retrieve: () => Promise<XTypes.SQL.IServer[]>;
    retrieveByID: (serverID: string) => Promise<XTypes.SQL.IServer | null>;
    create: (name: string) => Promise<XTypes.SQL.IServer>;
    delete: (serverID: string) => Promise<void>;
}

/**
 * @ignore
 */
interface IPermissions {
    retrieve: () => Promise<XTypes.SQL.IPermission[]>;
    create: (params: {
        userID: string;
        resourceType: string;
        resourceID: string;
    }) => Promise<XTypes.SQL.IPermission>;
}

/**
 * @ignore
 */
interface IChannels {
    retrieve: (serverID: string) => Promise<XTypes.SQL.IChannel[]>;
    retrieveByID: (channelID: string) => Promise<XTypes.SQL.IChannel | null>;
    create: (name: string, serverID: string) => Promise<XTypes.SQL.IChannel>;
    delete: (channelID: string) => Promise<void>;
}

/**
 * @ignore
 */
interface ISessions {
    retrieve: () => Promise<XTypes.SQL.ISession[]>;
    verify: (session: XTypes.SQL.ISession) => string;
    markVerified: (fingerprint: string) => Promise<void>;
}

/**
 * @ignore
 */
interface IFiles {
    create: (file: Buffer) => Promise<[XTypes.SQL.IFile, string]>;
    retrieve: (
        fileID: string,
        key: string
    ) => Promise<XTypes.HTTP.IFileResponse | null>;
}

/**
 * IClientOptions are the options you can pass into the client.
 */
export interface IClientOptions {
    logLevel?:
        | "error"
        | "warn"
        | "info"
        | "http"
        | "verbose"
        | "debug"
        | "silly";
    host?: string;
    dbFolder?: string;
    inMemoryDb?: boolean;
}

// tslint:disable-next-line: interface-name
export declare interface Client {
    /**
     * This is emitted whenever the keyring is done initializing after an init()
     * call. You must wait to login or register until after this event.
     *
     * Example:
     *
     * ```ts
     *   client.on("ready", () => {
     *       await client.register()
     *   });
     * ```
     *
     * @event
     */
    on(event: "ready", callback: () => void): this;

    /**
     * This is emitted when you are logged in succesfully. You can now call the rest of the methods in the api.
     *
     * Example:
     *
     * ```ts
     *   client.on("authed", (user) => {
     *       // do something
     *   });
     * ```
     *
     * @event
     */
    // tslint:disable-next-line: unified-signatures
    on(event: "authed", callback: () => void): this;

    /**
     * This is emitted for every sent and received message.
     *
     * Example:
     *
     * ```ts
     *
     *   client.on("message", (msg: IMessage) => {
     *       console.log(message);
     *   });
     * ```
     * @event
     */
    on(event: "message", callback: (message: IMessage) => void): this;

    /**
     * This is emitted when the user is granted a new permission.
     *
     * Example:
     *
     * ```ts
     *
     *   client.on("permission", (perm: IPermission) => {
     *       console.log(perm);
     *   });
     * ```
     * @event
     */
    on(event: "permission", callback: (permission: IPermission) => void): this;

    /**
     * This is emitted for a new encryption session being created with
     * a specific user.
     *
     * Example:
     *
     * ```ts
     *
     *   client.on("session", (session: ISession, user: IUser) => {
     *       console.log(session);
     *       console.log(user);
     *   });
     * ```
     * @event
     */
    on(
        event: "session",
        callback: (session: ISession, user: IUser) => void
    ): this;

    /**
     * This is emitted whenever the connection is closed. You must discard the client
     * and connect again with a fresh one.
     *
     * Example:
     * ```ts
     *
     *   client.on("disconnect", () => {
     *     // do something
     *   });
     * ```
     * @event
     */
    // tslint:disable-next-line: unified-signatures
    on(event: "disconnect", callback: () => void): this;

    /**
     * This is emitted whenever the close() event is called and completed successfully.
     * Note this is not fired for an unintentional disconnect, see the disconnect event.
     *
     * Example:
     *
     * ```ts
     *
     *   client.on("closed", () => {
     *       process.exit(0);
     *   });
     * ```
     *
     * @event
     */
    // tslint:disable-next-line: unified-signatures
    on(event: "closed", callback: () => void): this;
}

/**
 * Client provides an interface for you to use a vex chat server and
 * send end to end encrypted messages to other users.
 *
 * @example
 * ```ts
 * import { Client } from "@vex-chat/libvex";
 *
 * async function main() {
 *     // generate a secret key to use, save this somewhere permanent
 *     const privateKey = Client.generateSecretKey();
 *
 *     const client = new Client(privateKey);
 *
 *     // the ready event is emitted when init() is finished.
 *     // you must wait until this event fires to perform
 *     // registration or login.
 *     client.on("ready", async () => {
 *         // you must register once before you can log in
 *         await client.register(Client.randomUsername());
 *         await client.login();
 *     })
 *
 *     // The authed event fires when login() successfully completes
 *     // and the server indicates you are authorized. You must wait to
 *     // perform any operations besides register() and login() until
 *     // this occurs.
 *     client.on("authed", async () => {
 *         const me = await client.users.me();
 *
 *         // send a message
 *         await client.messages.send(me.userID, "Hello world!");
 *     })
 *
 *     // Outgoing and incoming messages are emitted here.
 *     client.on("message", (message) => {
 *         console.log("message:", message);
 *     })
 *
 *     // you must call init() to initialize the keyring and
 *     // start the client.
 *     client.init();
 * }
 *
 * main();
 * ```
 *
 * @noInheritDoc
 */
export class Client extends EventEmitter {
    public static loadKeyFile = XUtils.loadKeyFile;

    public static saveKeyFile = XUtils.saveKeyFile;
    /**
     * Generates an ed25519 secret key as a hex string.
     *
     * @returns - A secret key to use for the client. Save it permanently somewhere safe.
     */
    public static generateSecretKey(): string {
        return XUtils.encodeHex(nacl.sign.keyPair().secretKey);
    }

    /**
     * Generates a random username using bip39.
     *
     * @returns - The username.
     */
    public static randomUsername() {
        const IKM = XUtils.decodeHex(XUtils.encodeHex(nacl.randomBytes(16)));
        const mnemonic = xMnemonic(IKM).split(" ");
        const addendum = XUtils.uint8ArrToNumber(nacl.randomBytes(1));

        return (
            capitalize(mnemonic[0]) +
            capitalize(mnemonic[1]) +
            addendum.toString()
        );
    }
    private static getMnemonic(session: XTypes.SQL.ISession): string {
        return xMnemonic(xKDF(XUtils.decodeHex(session.fingerprint)));
    }
    private static deserializeExtra(
        type: XTypes.WS.MailType,
        extra: Uint8Array
    ): Uint8Array[] {
        switch (type) {
            case XTypes.WS.MailType.initial:
                /* 32 bytes for signkey, 32 bytes for ephemeral key, 
                 68 bytes for AD, 6 bytes for otk index (empty for no otk) */
                const signKey = extra.slice(0, 32);
                const ephKey = extra.slice(32, 64);
                const ad = extra.slice(96, 164);
                const index = extra.slice(164, 170);
                return [signKey, ephKey, ad, index];
            case XTypes.WS.MailType.subsequent:
                const publicKey = extra;
                return [publicKey];
            default:
                return [];
        }
    }

    /**
     * The IUsers interface contains methods for dealing with users.
     */
    public users: IUsers = {
        /**
         * Retrieves a user's information by a string identifier.
         * @param identifier: A userID, hex string public key, or a username.
         *
         * @returns - The user's IUser object, or null if the user does not exist.
         */
        retrieve: this.retrieveUserDBEntry.bind(this),
        /**
         * Retrieves the currently logged in user's (you) information.
         *
         * @returns - The logged in user's IUser object.
         */
        me: this.getUser.bind(this),
        /**
         * Retrieves the list of users you can currently access, or are already familiar with.
         *
         * @returns - The list of IUser objects.
         */
        familiars: this.getFamiliars.bind(this),
    };

    /**
     * The IMessages interface contains methods for dealing with messages.
     */
    public files: IFiles = {
        /**
         * Uploads an encrypted file and returns the details and the secret key.
         * @param file: The file as a Buffer.
         *
         * @returns Details of the file uploaded and the key to encrypt in the form [details, key].
         */
        create: this.createFile.bind(this),
        retrieve: this.retrieveFile.bind(this),
    };

    /**
     * The IPermissions object contains all methods for dealing with permissions.
     */
    public permissions: IPermissions = {
        retrieve: this.getPermissions.bind(this),
        /**
         * Creates a new permission for the givern resourceID and userID.
         * @param params: The new permission details.
         *
         * @returns - The list of IPermissions objects.
         */
        create: this.createPermission.bind(this),
    };

    /**
     * The IMessages interface contains methods for dealing with messages.
     */
    public messages: IMessages = {
        /**
         * Send a direct message.
         * @param userID: The userID of the user to send a message to.
         * @param message: The message to send.
         */
        send: this.sendMessage.bind(this),
        /**
         * Send a group message to a channel.
         * @param channelID: The channelID of the channel to send a message to.
         * @param message: The message to send.
         */
        group: this.sendGroupMessage.bind(this),
        /**
         * Gets the message history with a specific userID.
         * @param userID: The userID of the user to retrieve message history for.
         *
         * @returns - The list of IMessage objects.
         */
        retrieve: this.getMessageHistory.bind(this),
        /**
         * Gets the group message history with a specific channelID.
         * @param chqnnelID: The channelID of the channel to retrieve message history for.
         *
         * @returns - The list of IMessage objects.
         */
        retrieveGroup: this.getGroupHistory.bind(this),
    };

    /**
     * The ISessions interface contains methods for dealing with encryption sessions.
     */
    public sessions: ISessions = {
        /**
         * Gets all encryption sessions.
         *
         * @returns - The list of ISession encryption sessions.
         */
        retrieve: this.getSessionList.bind(this),

        /**
         * Returns a mnemonic for the session, to verify with the other user.
         * @param session the ISession object to get the mnemonic for.
         *
         * @returns - The mnemonic representation of the session.
         */
        verify: Client.getMnemonic,

        /**
         * Marks a mnemonic verified, implying that the the user has confirmed
         * that the session mnemonic matches with the other user.
         * @param sessionID the sessionID of the session to mark.
         * @param status Optionally, what to mark it as. Defaults to true.
         */
        markVerified: this.markSessionVerified.bind(this),
    };

    public servers: IServers = {
        /**
         * Retrieves all servers the logged in user has access to.
         *
         * @returns - The list of IServer objects.
         */
        retrieve: this.getServerList.bind(this),
        /**
         * Retrieves server details by its unique serverID.
         *
         * @returns - The requested IServer object, or null if the id does not exist.
         */
        retrieveByID: this.getServerByID.bind(this),
        /**
         * Creates a new server.
         * @param name: The server name.
         *
         * @returns - The created IServer object.
         */
        create: this.createServer.bind(this),
        /**
         * Deletes a server.
         * @param serverID: The unique serverID to delete.
         */
        delete: this.deleteServer.bind(this),
    };

    public channels: IChannels = {
        /**
         * Retrieves all channels in a server.
         *
         * @returns - The list of IChannel objects.
         */
        retrieve: this.getChannelList.bind(this),
        /**
         * Retrieves channel details by its unique channelID.
         *
         * @returns - The list of IChannel objects.
         */
        retrieveByID: this.getChannelByID.bind(this),
        /**
         * Creates a new channel in a server.
         * @param name: The channel name.
         * @param serverID: The unique serverID to create the channel in.
         *
         * @returns - The created IChannel object.
         */
        create: this.createChannel.bind(this),
        /**
         * Deletes a channel.
         * @param channelID: The unique channelID to delete.
         */
        delete: this.deleteChannel.bind(this),
    };

    /**
     * This is true if the client has ever been initialized. You can only initialize
     * a client once.
     */
    public hasInit: boolean = false;
    /**
     * This is true if the client has ever logged in before. You can only login a client once.
     */
    public hasLoggedIn: boolean = false;

    private wsOpen = false;

    private database: Database;
    private dbPath: string;
    private conn: WebSocket;
    private host: string;

    // these are created from one set of sign keys
    private signKeys: nacl.SignKeyPair;
    private idKeys: nacl.BoxKeyPair | null;

    private xKeyRing?: XTypes.CRYPTO.IXKeyRing;

    private user?: XTypes.SQL.IUser;
    private isAlive: boolean = true;
    private failCount: number = 0;
    private reading: boolean = false;
    private getting: boolean = false;

    private log: winston.Logger;

    private pingInterval?: NodeJS.Timeout;
    private mailInterval?: NodeJS.Timeout;

    private manuallyClosing: boolean = false;

    constructor(privateKey?: string, options?: IClientOptions) {
        super();

        this.log = createLogger("client", options);

        this.signKeys = privateKey
            ? nacl.sign.keyPair.fromSecretKey(XUtils.decodeHex(privateKey))
            : nacl.sign.keyPair();
        this.idKeys = XKeyConvert.convertKeyPair(this.signKeys);

        if (!this.idKeys) {
            throw new Error("Could not convert key to X25519!");
        }

        this.host = options?.host || "api.vex.chat";

        const dbFileName = options?.inMemoryDb
            ? ":memory:"
            : XUtils.encodeHex(this.signKeys.publicKey) + ".sqlite";
        this.dbPath = options?.dbFolder
            ? options?.dbFolder + "/" + dbFileName
            : dbFileName;

        this.database = new Database(this.dbPath, this.idKeys, options);

        this.database.on("error", (error) => {
            this.log.error(error);
            this.close(true);
            this.emit("disconnect");
        });

        // we want to initialize this later with login()
        this.conn = new WebSocket("ws://localhost:1234");
        // silence the error for connecting to junk ws
        // tslint:disable-next-line: no-empty
        this.conn.onerror = () => {};
    }

    /**
     * Initializes the keyring. This must be called before anything else.
     */
    public async init() {
        if (this.hasInit) {
            return new Error("You should only call init() once.");
        }
        this.hasInit = true;

        await this.populateKeyRing();
        this.on("message", async (message) => {
            if (
                message.direction === "incoming" &&
                message.recipient === message.sender
            ) {
                return;
            }

            await this.database.saveMessage(message);
        });

        this.emit("ready");
    }

    /**
     * Manually closes the client. Emits the closed event on successful shutdown.
     */
    public async close(muteEvent = false): Promise<void> {
        this.manuallyClosing = true;
        this.log.info("Manually closing client.");

        this.conn.close();
        await this.database.close();

        if (this.pingInterval) {
            clearInterval(this.pingInterval);
        }

        if (this.mailInterval) {
            clearInterval(this.mailInterval);
        }
        delete this.xKeyRing;

        if (!muteEvent) {
            this.emit("closed");
        }
        return;
    }

    /**
     * Gets the hex string representations of the public and private keys.
     */
    public getKeys(): IKeys {
        return {
            public: XUtils.encodeHex(this.signKeys.publicKey),
            private: XUtils.encodeHex(this.signKeys.secretKey),
        };
    }

    /**
     * Logs in to the server. You must have registered() before with your current
     * private key.
     */
    public async login(): Promise<Error | null> {
        if (this.hasLoggedIn) {
            return new Error("You should only call login() once.");
        }
        this.hasLoggedIn = true;

        if (!this.user) {
            try {
                const res = await ax.get(
                    "https://" +
                        this.host +
                        "/user/" +
                        XUtils.encodeHex(this.signKeys.publicKey)
                );
                this.user = res.data;
            } catch (err) {
                return new Error(
                    "Error retrieving user info from server: " + err.toString()
                );
            }
        }

        try {
            await this.initSocket();
        } catch (err) {
            return err;
        }

        return null;
    }

    /**
     * Registers a new account on the server.
     * @param username The username to register. Must be unique.
     *
     * @returns The error, or the user object.
     *
     * @example [user, err] = await client.register("MyUsername");
     */
    public async register(
        username: string
    ): Promise<[XTypes.SQL.IUser | null, Error | null]> {
        while (!this.xKeyRing) {
            await sleep(100);
        }
        const regKey = await this.getRegistrationKey();
        if (regKey) {
            const signKey = XUtils.encodeHex(this.signKeys.publicKey);
            const signed = XUtils.encodeHex(
                nacl.sign(
                    Uint8Array.from(uuid.parse(regKey.key)),
                    this.signKeys.secretKey
                )
            );
            const regMsg: XTypes.HTTP.IRegPayload = {
                username,
                signKey,
                signed,
                preKey: XUtils.encodeHex(
                    this.xKeyRing.preKeys.keyPair.publicKey
                ),
                preKeySignature: XUtils.encodeHex(
                    this.xKeyRing.preKeys.signature
                ),
                preKeyIndex: this.xKeyRing.preKeys.index!,
            };
            try {
                const res = await ax.post(
                    "https://" + this.host + "/register/new",
                    regMsg
                );

                this.setUser(res.data);
                return [this.getUser(), null];
            } catch (err) {
                if (err.response) {
                    return [null, new Error(err.response.data.error)];
                } else {
                    return [null, err];
                }
            }
        } else {
            return [null, new Error("Couldn't get regkey from server.")];
        }
    }

    private createPermission(params: {
        userID: string;
        resourceType: string;
        resourceID: string;
    }): Promise<XTypes.SQL.IPermission> {
        return new Promise((res, rej) => {
            const transmissionID = uuid.v4();
            const callback = (packedMsg: Buffer) => {
                const [header, msg] = XUtils.unpackMessage(packedMsg);
                if (msg.transmissionID === transmissionID) {
                    this.conn.off("message", callback);
                    if (msg.type === "success") {
                        res((msg as XTypes.WS.ISucessMsg).data);
                    } else {
                        rej(msg);
                    }
                }
            };
            this.conn.on("message", callback);
            const outMsg: XTypes.WS.IResourceMsg = {
                transmissionID,
                type: "resource",
                resourceType: "permissions",
                action: "CREATE",
                data: params,
            };
            this.send(outMsg);
        });
    }

    /**
     * Gets all permissions for the logged in user.
     *
     * @returns - The list of IPermissions objects.
     */
    private getPermissions(): Promise<XTypes.SQL.IPermission[]> {
        return new Promise((res, rej) => {
            const transmissionID = uuid.v4();
            const callback = (packedMsg: Buffer) => {
                const [header, msg] = XUtils.unpackMessage(packedMsg);
                if (msg.transmissionID === transmissionID) {
                    this.conn.off("message", callback);
                    if (msg.type === "success") {
                        res((msg as XTypes.WS.ISucessMsg).data);
                    } else {
                        rej(msg);
                    }
                }
            };
            this.conn.on("message", callback);
            const outMsg: XTypes.WS.IResourceMsg = {
                transmissionID,
                type: "resource",
                resourceType: "permissions",
                action: "RETRIEVE",
            };
            this.send(outMsg);
        });
    }

    private async retrieveFile(
        fileID: string,
        key: string
    ): Promise<XTypes.HTTP.IFileResponse | null> {
        try {
            const res = await ax.get(
                "https://" + this.host + "/file/" + fileID
            );
            const resp: XTypes.HTTP.IFileResponse = res.data;

            const decrypted = nacl.secretbox.open(
                Uint8Array.from(Buffer.from(resp.data)),
                XUtils.decodeHex(resp.details.nonce),
                XUtils.decodeHex(key)
            );

            if (decrypted) {
                resp.data = Buffer.from(decrypted);
                return resp;
            }
            throw new Error("Decryption failed.");
        } catch (err) {
            console.warn(err);
            return null;
        }
    }

    private async deleteServer(serverID: string): Promise<void> {
        return new Promise((res, rej) => {
            const transmissionID = uuid.v4();
            const callback = (packedMsg: Buffer) => {
                const [header, msg] = XUtils.unpackMessage(packedMsg);
                if (msg.transmissionID === transmissionID) {
                    this.conn.off("message", callback);
                    if (msg.type === "success") {
                        res((msg as XTypes.WS.ISucessMsg).data);
                    } else {
                        rej(msg);
                    }
                }
            };
            this.conn.on("message", callback);
            const outMsg: XTypes.WS.IResourceMsg = {
                transmissionID,
                type: "resource",
                resourceType: "servers",
                action: "DELETE",
                data: serverID,
            };
            this.send(outMsg);
        });
    }

    private async deleteChannel(channelID: string): Promise<void> {
        return new Promise((res, rej) => {
            const transmissionID = uuid.v4();
            const callback = (packedMsg: Buffer) => {
                const [header, msg] = XUtils.unpackMessage(packedMsg);
                if (msg.transmissionID === transmissionID) {
                    this.conn.off("message", callback);
                    if (msg.type === "success") {
                        res((msg as XTypes.WS.ISucessMsg).data);
                    } else {
                        rej(msg);
                    }
                }
            };
            this.conn.on("message", callback);
            const outMsg: XTypes.WS.IResourceMsg = {
                transmissionID,
                type: "resource",
                resourceType: "channels",
                action: "DELETE",
                data: channelID,
            };
            this.send(outMsg);
        });
    }

    // returns the file details and the encryption key
    private async createFile(
        file: Buffer
    ): Promise<[XTypes.SQL.IFile, string]> {
        const nonce = xMakeNonce();
        const key = nacl.box.keyPair();
        const box = nacl.secretbox(Uint8Array.from(file), nonce, key.secretKey);

        const decrypted = nacl.secretbox.open(box, nonce, key.secretKey);
        if (!decrypted) {
            throw new Error("decryption test failed!");
        }

        const signed = nacl.sign(box, this.signKeys.secretKey);

        const payload: XTypes.HTTP.IFilePayload = {
            owner: this.getUser().userID,
            signed: XUtils.encodeHex(signed),
            nonce: XUtils.encodeHex(nonce),
        };

        const res = await ax.post("https://" + this.host + "/file", payload);
        const createdFile: XTypes.SQL.IFile = res.data;

        return [createdFile, XUtils.encodeHex(key.secretKey)];
    }

    private getUserList(channelID: string): Promise<IUser[]> {
        return new Promise((res, rej) => {
            const transmissionID = uuid.v4();
            const callback = (packedMsg: Buffer) => {
                const [header, msg] = XUtils.unpackMessage(packedMsg);
                if (msg.transmissionID === transmissionID) {
                    this.conn.off("message", callback);
                    if (msg.type === "success") {
                        res((msg as XTypes.WS.ISucessMsg).data);
                    } else {
                        rej(msg);
                    }
                }
            };
            this.conn.on("message", callback);
            const outMsg: XTypes.WS.IResourceMsg = {
                transmissionID,
                type: "resource",
                resourceType: "userlist",
                action: "RETRIEVE",
                data: channelID,
            };
            this.send(outMsg);
        });
    }

    private async markSessionVerified(sessionID: string, status = true) {
        return this.database.markSessionVerified(sessionID, status);
    }

    private async getGroupHistory(channelID: string): Promise<IMessage[]> {
        const messages: IMessage[] = await this.database.getGroupHistory(
            channelID
        );

        return messages;
    }

    private async getMessageHistory(userID: string): Promise<IMessage[]> {
        const messages: IMessage[] = await this.database.getMessageHistory(
            userID
        );

        return messages;
    }

    /* A thin wrapper around sendMail for string inputs. */
    private async sendMessage(userID: string, message: string): Promise<void> {
        try {
            await this.sendMail(userID, XUtils.decodeUTF8(message), null);
        } catch (err) {
            this.log.error(
                "Message " + (err.message?.mailID || "") + " threw exception."
            );
            if (err.message?.mailID) {
                await this.database.deleteMessage(err.message.mailID);
            }
            throw err;
        }
    }

    private async sendGroupMessage(
        channelID: string,
        message: string
    ): Promise<void[]> {
        const userList = await this.getUserList(channelID);
        const mailID = uuid.v4();
        const promises: Array<Promise<void>> = [];
        for (const user of userList) {
            promises.push(
                this.sendMail(
                    user.userID,
                    XUtils.decodeUTF8(message),
                    uuidToUint8(channelID),
                    mailID
                )
            );
        }

        return Promise.all(promises).catch(async (err) => {
            this.log.error("Message " + mailID + " threw exception.");
            await this.database.deleteMessage(mailID);
            throw err;
        });
    }

    private async createServer(name: string): Promise<XTypes.SQL.IChannel> {
        return new Promise((res, rej) => {
            const transmissionID = uuid.v4();
            const callback = (packedMsg: Buffer) => {
                const [header, msg] = XUtils.unpackMessage(packedMsg);
                if (msg.transmissionID === transmissionID) {
                    this.conn.off("message", callback);
                    if (msg.type === "success") {
                        res((msg as XTypes.WS.ISucessMsg).data);
                    } else {
                        rej(msg);
                    }
                }
            };
            this.conn.on("message", callback);
            const outMsg: XTypes.WS.IResourceMsg = {
                transmissionID,
                type: "resource",
                resourceType: "servers",
                action: "CREATE",
                data: name,
            };
            this.send(outMsg);
        });
    }

    /* Sends encrypted mail to a user. */
    private async sendMail(
        userID: string,
        msg: Uint8Array,
        group: Uint8Array | null,
        mailID?: string
    ): Promise<void> {
        this.log.info("Sending mail to " + userID);
        const session = await this.database.getSession(userID);
        if (!session) {
            this.log.info("Creating new session for " + userID);
            await this.createSession(userID, msg, group, mailID);
            return;
        }

        const nonce = xMakeNonce();
        const cipher = nacl.secretbox(msg, nonce, session.SK);
        const extra = session.publicKey;

        const mail: XTypes.WS.IMail = {
            mailType: XTypes.WS.MailType.subsequent,
            mailID: mailID || uuid.v4(),
            recipient: userID,
            cipher,
            nonce,
            extra,
            sender: this.user!.userID,
            group,
        };

        const msgb: XTypes.WS.IResourceMsg = {
            transmissionID: uuid.v4(),
            type: "resource",
            resourceType: "mail",
            action: "CREATE",
            data: mail,
        };

        const hmac = xHMAC(mail, session.SK);

        const outMsg: IMessage = {
            mailID: mail.mailID,
            sender: mail.sender,
            recipient: mail.recipient,
            nonce: XUtils.encodeHex(mail.nonce),
            message: XUtils.encodeUTF8(msg),
            direction: "outgoing",
            timestamp: new Date(Date.now()),
            decrypted: true,
            group: mail.group ? uuid.stringify(mail.group) : null,
        };
        this.emit("message", outMsg);

        await new Promise((res, rej) => {
            const callback = async (packedMsg: Buffer) => {
                const [header, receivedMsg] = XUtils.unpackMessage(packedMsg);
                if (receivedMsg.transmissionID === msgb.transmissionID) {
                    this.conn.off("message", callback);
                    if (receivedMsg.type === "success") {
                        res((receivedMsg as XTypes.WS.ISucessMsg).data);
                    } else {
                        rej({
                            error: receivedMsg,
                            message: outMsg,
                        });
                    }
                }
            };
            this.conn.on("message", callback);
            this.send(msgb, hmac);
        });
    }

    private async getSessionList() {
        return this.database.getSessions();
    }

    private async getServerList(): Promise<XTypes.SQL.IServer[]> {
        return new Promise((res, rej) => {
            const transmissionID = uuid.v4();
            const callback = (packedMsg: Buffer) => {
                const [header, msg] = XUtils.unpackMessage(packedMsg);
                if (msg.transmissionID === transmissionID) {
                    this.conn.off("message", callback);
                    if (msg.type === "success") {
                        res((msg as XTypes.WS.ISucessMsg).data);
                    } else {
                        rej(msg);
                    }
                }
            };
            this.conn.on("message", callback);
            const outMsg: XTypes.WS.IResourceMsg = {
                transmissionID,
                type: "resource",
                resourceType: "servers",
                action: "RETRIEVE",
            };
            this.send(outMsg);
        });
    }

    private async createChannel(
        name: string,
        serverID: string
    ): Promise<XTypes.SQL.IChannel> {
        return new Promise((res, rej) => {
            const transmissionID = uuid.v4();
            const callback = (packedMsg: Buffer) => {
                const [header, msg] = XUtils.unpackMessage(packedMsg);
                if (msg.transmissionID === transmissionID) {
                    this.conn.off("message", callback);
                    if (msg.type === "success") {
                        res((msg as XTypes.WS.ISucessMsg).data);
                    } else {
                        rej(msg);
                    }
                }
            };
            this.conn.on("message", callback);
            const outMsg: XTypes.WS.IResourceMsg = {
                transmissionID,
                type: "resource",
                resourceType: "channels",
                action: "CREATE",
                data: { name, serverID },
            };
            this.send(outMsg);
        });
    }

    private async getServerByID(
        serverID: string
    ): Promise<XTypes.SQL.IServer | null> {
        try {
            const res = await ax.get(
                "https://" + this.host + "/server/" + serverID
            );
            return res.data;
        } catch (err) {
            return null;
        }
    }

    private async getChannelByID(
        channelID: string
    ): Promise<XTypes.SQL.IChannel | null> {
        try {
            const res = await ax.get(
                "https://" + this.host + "/channel/" + channelID
            );
            return res.data;
        } catch (err) {
            return null;
        }
    }

    private async getChannelList(
        serverID: string
    ): Promise<XTypes.SQL.IChannel[]> {
        return new Promise((res, rej) => {
            const transmissionID = uuid.v4();
            const callback = (packedMsg: Buffer) => {
                const [header, msg] = XUtils.unpackMessage(packedMsg);
                if (msg.transmissionID === transmissionID) {
                    this.conn.off("message", callback);
                    if (msg.type === "success") {
                        res((msg as XTypes.WS.ISucessMsg).data);
                    } else {
                        rej(msg);
                    }
                }
            };
            this.conn.on("message", callback);
            const outMsg: XTypes.WS.IResourceMsg = {
                transmissionID,
                type: "resource",
                resourceType: "channels",
                action: "RETRIEVE",
                data: serverID,
            };
            this.send(outMsg);
        });
    }

    /* Get the currently logged in user. You cannot call this until 
    after the auth event is emitted. */
    private getUser(): XTypes.SQL.IUser {
        if (!this.user) {
            throw new Error(
                "You must wait until the auth event is emitted before getting user details."
            );
        }
        return this.user;
    }

    private setUser(user: XTypes.SQL.IUser): void {
        this.user = user;
    }

    /* Retrieves the userID with the user identifier.
    user identifier is checked for userID, then signkey,
    and finally falls back to username. */
    private async retrieveUserDBEntry(
        userIdentifier: string
    ): Promise<[XTypes.SQL.IUser | null, AxiosError | null]> {
        try {
            const res = await ax.get(
                "https://" + this.host + "/user/" + userIdentifier
            );
            return [res.data, null];
        } catch (err) {
            return [null, err];
        }
    }

    /* Retrieves the current list of users you have access to. */
    private getFamiliars(): Promise<XTypes.SQL.IUser[]> {
        return new Promise((res, rej) => {
            const transmissionID = uuid.v4();
            const callback = (packedMsg: Buffer) => {
                const [header, msg] = XUtils.unpackMessage(packedMsg);
                if (msg.transmissionID === transmissionID) {
                    this.conn.off("message", callback);
                    if (msg.type === "success") {
                        res((msg as XTypes.WS.ISucessMsg).data);
                    } else {
                        rej(msg);
                    }
                }
            };
            this.conn.on("message", callback);
            const outMsg: XTypes.WS.IResourceMsg = {
                transmissionID,
                type: "resource",
                resourceType: "users",
                action: "RETRIEVE",
            };
            this.send(outMsg);
        });
    }

    private async createSession(
        userID: string,
        message: Uint8Array,
        group: Uint8Array | null,
        /* this is passed through if the first message is 
        part of a group message */
        mailID?: string
    ): Promise<void> {
        let keyBundle: XTypes.WS.IKeyBundle;

        this.log.info("Requesting key bundle.");
        try {
            keyBundle = await this.retrieveKeyBundle(userID);
        } catch (err) {
            this.log.warn("Couldn't get key bundle:", err);
            return;
        }

        // my keys
        const IK_A = this.xKeyRing!.identityKeys.secretKey;
        const IK_AP = this.xKeyRing!.identityKeys.publicKey;
        const EK_A = this.xKeyRing!.ephemeralKeys.secretKey;

        // their keys
        const IK_B = XKeyConvert.convertPublicKey(keyBundle.signKey)!;
        const SPK_B = keyBundle.preKey.publicKey;
        const OPK_B = keyBundle.otk ? keyBundle.otk.publicKey : null;

        // diffie hellman functions
        const DH1 = xDH(IK_A, SPK_B);
        const DH2 = xDH(EK_A, IK_B);
        const DH3 = xDH(EK_A, SPK_B);
        const DH4 = OPK_B ? xDH(EK_A, OPK_B) : null;

        // initial key material
        const IKM = DH4 ? xConcat(DH1, DH2, DH3, DH4) : xConcat(DH1, DH2, DH3);

        // one time key index
        const IDX = keyBundle.otk
            ? XUtils.numberToUint8Arr(keyBundle.otk.index)
            : XUtils.numberToUint8Arr(0);

        // shared secret key
        const SK = xKDF(IKM);
        this.log.info("Obtained SK.");

        const PK = nacl.box.keyPair.fromSecretKey(SK).publicKey;

        const AD = xConcat(
            xEncode(xConstants.CURVE, IK_AP),
            xEncode(xConstants.CURVE, IK_B)
        );

        const nonce = xMakeNonce();
        const cipher = nacl.secretbox(message, nonce, SK);

        this.log.info("Encrypted ciphertext.");

        /* 32 bytes for signkey, 32 bytes for ephemeral key, 
        68 bytes for AD, 6 bytes for otk index (empty for no otk) */
        const extra = xConcat(
            this.signKeys.publicKey,
            this.xKeyRing!.ephemeralKeys.publicKey,
            PK,
            AD,
            IDX
        );

        const mail: XTypes.WS.IMail = {
            mailType: XTypes.WS.MailType.initial,
            mailID: mailID || uuid.v4(),
            recipient: userID,
            cipher,
            nonce,
            extra,
            sender: this.user!.userID,
            group,
        };

        const hmac = xHMAC(mail, SK);
        this.log.info("Generated hmac: " + XUtils.encodeHex(hmac));
        this.log.debug(JSON.stringify(mail, null, 4));

        const msg: XTypes.WS.IResourceMsg = {
            transmissionID: uuid.v4(),
            type: "resource",
            resourceType: "mail",
            action: "CREATE",
            data: mail,
        };

        // discard the ephemeral keys
        this.newEphemeralKeys();

        // save the encryption session
        this.log.info("Saving new session.");
        const sessionEntry: XTypes.SQL.ISession = {
            verified: false,
            sessionID: uuid.v4(),
            userID,
            mode: "initiator",
            SK: XUtils.encodeHex(SK),
            publicKey: XUtils.encodeHex(PK),
            lastUsed: new Date(Date.now()),
            fingerprint: XUtils.encodeHex(AD),
        };

        await this.database.saveSession(sessionEntry);

        let [user, err] = await this.retrieveUserDBEntry(userID);

        if (user) {
            this.emit("session", sessionEntry, user);
        } else {
            let failed = 1;
            // retry a couple times
            while (!user) {
                [user, err] = await this.retrieveUserDBEntry(userID);
                failed++;
                if (failed > 3) {
                    throw new Error(
                        "We saved a session, but we didn't get it back from the db!"
                    );
                }
            }
        }

        // emit the message
        const emitMsg: IMessage = {
            nonce: XUtils.encodeHex(mail.nonce),
            mailID: mail.mailID,
            sender: mail.sender,
            recipient: mail.recipient,
            message: XUtils.encodeUTF8(message),
            direction: "outgoing",
            timestamp: new Date(Date.now()),
            decrypted: true,
            group: mail.group ? uuid.stringify(mail.group) : null,
        };
        this.emit("message", emitMsg);

        // send mail and wait for response
        return new Promise((res, rej) => {
            const callback = (packedMsg: Buffer) => {
                const [header, receivedMsg] = XUtils.unpackMessage(packedMsg);
                if (receivedMsg.transmissionID === msg.transmissionID) {
                    this.conn.off("message", callback);
                    if (receivedMsg.type === "success") {
                        res((receivedMsg as XTypes.WS.ISucessMsg).data);
                    } else {
                        rej({
                            error: receivedMsg,
                            message: emitMsg,
                        });
                    }
                }
            };
            this.conn.on("message", callback);
            this.send(msg, hmac);
            this.log.info("Mail sent.");
        });
    }

    private sendReceipt(nonce: Uint8Array, transmissionID: string) {
        const receipt: XTypes.WS.IReceiptMsg = {
            type: "receipt",
            transmissionID,
            nonce,
        };
        this.send(receipt);
    }

    private async readMail(
        mail: XTypes.WS.IMail,
        header: Uint8Array,
        transmissionID: string
    ) {
        while (this.reading) {
            await sleep(100);
        }
        this.reading = true;
        this.log.info("Received mail from " + mail.sender);
        switch (mail.mailType) {
            case XTypes.WS.MailType.subsequent:
                const [publicKey] = Client.deserializeExtra(
                    mail.mailType,
                    mail.extra
                );
                const session = await this.database.getSessionByPublicKey(
                    publicKey
                );
                if (!session) {
                    this.log.warn(
                        `Invalid session public key ${XUtils.encodeHex(
                            publicKey
                        )} Decryption failed.`
                    );

                    // emit the message
                    const message: IMessage = {
                        nonce: XUtils.encodeHex(mail.nonce),
                        mailID: mail.mailID,
                        sender: mail.sender,
                        recipient: mail.recipient,
                        message: "",
                        direction: "incoming",
                        timestamp: new Date(Date.now()),
                        decrypted: false,
                        group: mail.group ? uuid.stringify(mail.group) : null,
                    };
                    this.emit("message", message);

                    await this.sendReceipt(mail.nonce, transmissionID);
                    return;
                }
                this.log.info("Session found for " + mail.sender);
                this.log.info("Mail nonce " + XUtils.encodeHex(mail.nonce));

                const HMAC = xHMAC(mail, session.SK);

                if (!XUtils.bytesEqual(HMAC, header)) {
                    this.log.warn(
                        "Message authentication failed (HMAC does not match."
                    );
                    this.log.debug(JSON.stringify(mail, null, 4));
                    await this.sendReceipt(mail.nonce, transmissionID);
                    return;
                }

                const decrypted = nacl.secretbox.open(
                    mail.cipher,
                    mail.nonce,
                    session.SK
                );

                if (decrypted) {
                    this.log.info(
                        "Decryption successful: " + XUtils.encodeUTF8(decrypted)
                    );

                    // emit the message
                    const message: IMessage = {
                        nonce: XUtils.encodeHex(mail.nonce),
                        mailID: mail.mailID,
                        sender: mail.sender,
                        recipient: mail.recipient,
                        message: XUtils.encodeUTF8(decrypted),
                        direction: "incoming",
                        timestamp: new Date(Date.now()),
                        decrypted: true,
                        group: mail.group ? uuid.stringify(mail.group) : null,
                    };

                    this.emit("message", message);

                    await this.database.markSessionUsed(session.sessionID);
                    await this.sendReceipt(mail.nonce, transmissionID);
                } else {
                    this.log.info("Decryption failed.");

                    // emit the message
                    const message: IMessage = {
                        nonce: XUtils.encodeHex(mail.nonce),
                        mailID: mail.mailID,
                        sender: mail.sender,
                        recipient: mail.recipient,
                        message: "",
                        direction: "incoming",
                        timestamp: new Date(Date.now()),
                        decrypted: false,
                        group: mail.group ? uuid.stringify(mail.group) : null,
                    };
                    this.emit("message", message);

                    await this.sendReceipt(mail.nonce, transmissionID);
                }
                break;
            case XTypes.WS.MailType.initial:
                this.log.info("Initiating new session.");
                const [
                    signKey,
                    ephKey,
                    assocData,
                    indexBytes,
                ] = Client.deserializeExtra(
                    XTypes.WS.MailType.initial,
                    mail.extra
                );

                const preKeyIndex = XUtils.uint8ArrToNumber(indexBytes);
                const otk = await this.database.getOneTimeKey(preKeyIndex);

                // their public keys
                const IK_A = XKeyConvert.convertPublicKey(signKey)!;
                const EK_A = ephKey;

                // my private keys
                const IK_B = this.xKeyRing!.identityKeys.secretKey;
                const IK_BP = this.xKeyRing!.identityKeys.publicKey;
                const SPK_B = this.xKeyRing!.preKeys.keyPair.secretKey;
                const OPK_B = otk ? otk.keyPair.secretKey : null;

                // diffie hellman functions
                const DH1 = xDH(SPK_B, IK_A);
                const DH2 = xDH(IK_B, EK_A);
                const DH3 = xDH(SPK_B, EK_A);
                const DH4 = OPK_B ? xDH(OPK_B, EK_A) : null;

                // initial key material
                const IKM = DH4
                    ? xConcat(DH1, DH2, DH3, DH4)
                    : xConcat(DH1, DH2, DH3);

                // shared secret key
                const SK = xKDF(IKM);
                this.log.info("Obtained SK.");

                // shared public key
                const PK = nacl.box.keyPair.fromSecretKey(SK).publicKey;

                const hmac = xHMAC(mail, SK);
                this.log.info("Calculated hmac: " + XUtils.encodeHex(hmac));
                this.log.debug(JSON.stringify(mail, null, 4));

                // associated data
                const AD = xConcat(
                    xEncode(xConstants.CURVE, IK_A),
                    xEncode(xConstants.CURVE, IK_BP)
                );

                if (!XUtils.bytesEqual(hmac, header)) {
                    this.log.warn(
                        "Mail authentication failed (HMAC did not match)."
                    );
                    return;
                }
                this.log.info("Mail authenticated successfully.");

                const unsealed = nacl.secretbox.open(
                    mail.cipher,
                    mail.nonce,
                    SK
                );
                if (unsealed) {
                    this.log.info(
                        "Decryption successful " + XUtils.encodeUTF8(unsealed)
                    );

                    // emit the message
                    const message: IMessage = {
                        nonce: XUtils.encodeHex(mail.nonce),
                        mailID: mail.mailID,
                        sender: mail.sender,
                        recipient: mail.recipient,
                        message: XUtils.encodeUTF8(unsealed),
                        direction: "incoming",
                        timestamp: new Date(Date.now()),
                        decrypted: true,
                        group: mail.group ? uuid.stringify(mail.group) : null,
                    };
                    this.emit("message", message);

                    // discard onetimekey
                    await this.database.deleteOneTimeKey(preKeyIndex);

                    // save session
                    const newSession: XTypes.SQL.ISession = {
                        verified: false,
                        sessionID: uuid.v4(),
                        userID: mail.sender,
                        mode: "receiver",
                        SK: XUtils.encodeHex(SK),
                        publicKey: XUtils.encodeHex(PK),
                        lastUsed: new Date(Date.now()),
                        fingerprint: XUtils.encodeHex(AD),
                    };
                    if (newSession.userID !== this.user!.userID) {
                        await this.database.saveSession(newSession);

                        let [user, err] = await this.retrieveUserDBEntry(
                            newSession.userID
                        );

                        if (user) {
                            this.emit("session", newSession, user);
                        } else {
                            let failed = 1;
                            // retry a couple times
                            while (!user) {
                                [user, err] = await this.retrieveUserDBEntry(
                                    newSession.userID
                                );
                                failed++;
                                if (failed > 3) {
                                    throw new Error(
                                        "We saved a session, but we didn't get it back from the db!"
                                    );
                                }
                            }
                        }
                    }
                    await this.sendReceipt(mail.nonce, transmissionID);
                } else {
                    this.log.warn("Mail decryption failed.");
                }
                break;
            default:
                this.log.warn("Unsupported MailType:", mail.mailType);
                break;
        }
        this.reading = false;
    }

    private newEphemeralKeys() {
        this.xKeyRing!.ephemeralKeys = nacl.box.keyPair();
    }

    private createPreKey() {
        const preKeyPair = nacl.box.keyPair();
        const preKeys: XTypes.CRYPTO.IPreKeys = {
            keyPair: preKeyPair,
            signature: nacl.sign(
                xEncode(xConstants.CURVE, preKeyPair.publicKey),
                this.signKeys.secretKey
            ),
        };
        return preKeys;
    }

    private async handleNotify(msg: XTypes.WS.INotifyMsg) {
        switch (msg.event) {
            case "mail":
                this.log.info("Server has informed us of new mail.");
                this.getMail();
                break;
            case "permission":
                this.emit("permission", msg.data as IPermission);
                break;
            default:
                this.log.info("Unsupported notification event " + msg.event);
                break;
        }
    }

    private async populateKeyRing() {
        // we've checked in the constructor that these exist
        const identityKeys = this.idKeys!;

        let preKeys = await this.database.getPreKeys();
        if (!preKeys) {
            preKeys = this.createPreKey();
            await this.database.savePreKeys(preKeys, false);
        }

        const ephemeralKeys = nacl.box.keyPair();

        this.xKeyRing = {
            identityKeys,
            preKeys,
            ephemeralKeys,
        };

        this.log.info(
            "Keyring populated, public key: " +
                XUtils.encodeHex(this.signKeys.publicKey)
        );
    }

    private initSocket() {
        try {
            this.conn = new WebSocket("wss://" + this.host + "/socket");
            this.conn.on("open", () => {
                this.log.info("Connection opened.");
                this.pingInterval = setInterval(this.ping.bind(this), 5000);
                this.wsOpen = true;
            });

            this.conn.on("close", () => {
                this.log.info("Connection closed.");
                if (!this.manuallyClosing) {
                    this.emit("disconnect");
                }
            });

            this.conn.on("error", (error) => {
                throw error;
            });

            this.conn.on("message", async (message: Buffer) => {
                const [header, msg] = XUtils.unpackMessage(message);

                this.log.debug(
                    chalk.red.bold("INH ") + XUtils.encodeHex(header)
                );
                this.log.debug(
                    chalk.red.bold("IN ") + JSON.stringify(msg, null, 4)
                );

                switch (msg.type) {
                    case "ping":
                        this.pong(msg.transmissionID);
                        break;
                    case "pong":
                        this.setAlive(true);
                        break;
                    case "challenge":
                        this.log.info("Received challenge from server.");
                        this.respond(msg as XTypes.WS.IChallMsg);
                        break;
                    case "authorized":
                        this.log.info(
                            "Authenticated with userID " + this.user!.userID
                        );
                        this.emit("authed");
                        this.postAuth();
                        break;
                    case "success":
                        break;
                    case "error":
                        this.log.warn(JSON.stringify(msg));
                        break;
                    case "notify":
                        this.handleNotify(msg as XTypes.WS.INotifyMsg);
                        break;
                    default:
                        this.log.info("Unsupported message " + msg.type);
                        break;
                }
            });
        } catch (err) {
            throw new Error(
                "Error initiating websocket connection " + err.toString()
            );
        }
    }

    private setAlive(status: boolean) {
        this.isAlive = status;
    }

    private async postAuth() {
        try {
            await this.negotiateOTK();
        } catch (err) {
            this.log.warn("error negotiating OTKs:", err.toString());
        }

        try {
            await this.getMail();
        } catch (err) {
            this.log.warn("Problem getting mail", err.toString());
        }

        this.mailInterval = setInterval(this.getMail.bind(this), 5000);
    }

    private async getMail(): Promise<void> {
        while (this.getting) {
            await sleep(100);
        }
        this.getting = true;
        return new Promise((res, rej) => {
            const transmissionID = uuid.v4();
            const callback = (packedMsg: Buffer) => {
                const [header, msg] = XUtils.unpackMessage(packedMsg);
                if (msg.transmissionID === transmissionID) {
                    if (msg.type === "success") {
                        if (!(msg as XTypes.WS.ISucessMsg).data) {
                            this.conn.off("message", callback);
                            this.getting = false;
                            res();
                            return;
                        }
                        try {
                            this.readMail(
                                (msg as XTypes.WS.ISucessMsg).data,
                                header,
                                transmissionID
                            );
                        } catch (err) {
                            this.log.warn(
                                "error reading mail:",
                                err.toString()
                            );
                        }
                    } else {
                        rej(msg);
                    }
                }
            };
            this.conn.on("message", callback);
            const outMsg: XTypes.WS.IResourceMsg = {
                transmissionID,
                type: "resource",
                resourceType: "mail",
                action: "RETRIEVE",
            };
            this.send(outMsg);
        });
    }

    /* header is 32 bytes and is either empty
    or contains an HMAC of the message with
    a derived SK */
    private async send(msg: any, header?: Uint8Array) {
        let i = 0;
        while (!this.wsOpen) {
            await sleep(i);
            i *= 2;

            if (i > 500) {
                this.close(true);
                this.emit("disconnect");
            }
        }

        this.log.debug(
            chalk.red.bold("OUTH ") +
                XUtils.encodeHex(header || XUtils.emptyHeader())
        );
        this.log.debug(chalk.red.bold("OUT ") + JSON.stringify(msg, null, 4));

        this.conn.send(XUtils.packMessage(msg, header));
    }

    private async retrieveKeyBundle(
        userID: string
    ): Promise<XTypes.WS.IKeyBundle> {
        return new Promise((res, rej) => {
            const transmissionID = uuid.v4();
            const callback = (packedMsg: Buffer) => {
                const [header, msg] = XUtils.unpackMessage(packedMsg);
                if (msg.transmissionID === transmissionID) {
                    this.conn.off("message", callback);
                    if (msg.type === "success") {
                        res((msg as XTypes.WS.ISucessMsg).data);
                    } else {
                        rej(msg);
                    }
                }
            };
            this.conn.on("message", callback);
            const outMsg: XTypes.WS.IResourceMsg = {
                transmissionID,
                type: "resource",
                resourceType: "keyBundle",
                action: "RETRIEVE",
                data: userID,
            };
            this.send(outMsg);
        });
    }

    private async getOTKCount(): Promise<number> {
        return new Promise((res, rej) => {
            const transmissionID = uuid.v4();
            const callback = (packedMsg: Buffer) => {
                const [header, msg] = XUtils.unpackMessage(packedMsg);
                if (msg.transmissionID === transmissionID) {
                    this.conn.off("message", callback);
                    if (msg.type === "success") {
                        res((msg as XTypes.WS.ISucessMsg).data);
                    } else {
                        rej(msg);
                    }
                }
            };
            this.conn.on("message", callback);
            this.send({
                transmissionID,
                type: "resource",
                resourceType: "otk",
                action: "RETRIEVE",
            });
        });
    }

    private async submitOTK(): Promise<void> {
        return new Promise(async (res, rej) => {
            const transmissionID = uuid.v4();
            const callback = (packedMessage: Buffer) => {
                const [header, msg] = XUtils.unpackMessage(packedMessage);
                if (msg.transmissionID === transmissionID) {
                    this.conn.off("message", callback);
                    if (msg.type === "success") {
                        res((msg as XTypes.WS.ISucessMsg).data);
                    } else {
                        rej(msg);
                    }
                }
            };

            this.conn.on("message", callback);

            const oneTimeKey: XTypes.CRYPTO.IPreKeys = this.createPreKey();
            const preKeyIndex: number = await this.database.savePreKeys(
                oneTimeKey,
                true
            );
            oneTimeKey.index = preKeyIndex;

            this.send({
                transmissionID,
                type: "resource",
                resourceType: "otk",
                action: "CREATE",
                data: this.censorPreKey(oneTimeKey),
            });
        });
    }

    private async negotiateOTK() {
        let otkCount = await this.getOTKCount();
        this.log.info("Server reported OTK: " + otkCount.toString());
        const needs = xConstants.MIN_OTK_SUPPLY - otkCount;
        if (needs > 0) {
            this.log.info("Filling server OTK supply.");
        }

        for (let i = 0; i < needs; i++) {
            await this.submitOTK();
            otkCount++;
        }
        this.log.info("Server OTK supply is full.");
    }

    private respond(msg: XTypes.WS.IChallMsg) {
        const response: XTypes.WS.IRespMsg = {
            transmissionID: msg.transmissionID,
            type: "response",
            signed: nacl.sign(msg.challenge, this.signKeys.secretKey),
            userID: this.user!.userID,
        };

        this.send(response);
    }

    private async getRegistrationKey(): Promise<XTypes.HTTP.IRegKey | null> {
        try {
            const res = await ax.post("https://" + this.host + "/register/key");
            return res.data;
        } catch (err) {
            this.log.warn("error getting regkey:", err.toString());
            return null;
        }
    }

    private censorPreKey(preKey: XTypes.CRYPTO.IPreKeys): XTypes.WS.IPreKeys {
        if (!preKey.index) {
            throw new Error("Key index is required.");
        }
        return {
            publicKey: preKey.keyPair.publicKey,
            signature: preKey.signature,
            index: preKey.index,
        };
    }

    private pong(transmissionID: string) {
        this.send({ transmissionID, type: "pong" });
    }

    private async ping() {
        if (!this.isAlive) {
            this.log.warn("Ping failed.");
            this.failCount++;
            if (this.failCount === 2) {
                await this.close(true);
                this.emit("disconnect");
            }
        }
        this.setAlive(false);
        this.send({ transmissionID: uuid.v4(), type: "ping" });
    }
}
