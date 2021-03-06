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
import { isBrowser, isNode } from "browser-or-node";
import btoa from "btoa";
import chalk from "chalk";
import { EventEmitter } from "events";
import { first } from "lodash";
import msgpack from "msgpack-lite";
import objectHash from "object-hash";
import os from "os";
import { performance } from "perf_hooks";
import nacl from "tweetnacl";
import * as uuid from "uuid";
import winston from "winston";
import WebSocket from "ws";
import { IStorage } from "./IStorage";
import { Storage } from "./Storage";
import { capitalize } from "./utils/capitalize";
import { createLogger } from "./utils/createLogger";
import { formatBytes } from "./utils/formatBytes";
import { sqlSessionToCrypto } from "./utils/sqlSessionToCrypto";
import { uuidToUint8 } from "./utils/uint8uuid";

ax.defaults.withCredentials = true;
ax.defaults.responseType = "arraybuffer";

const protocolMsgRegex = /��\w+:\w+��/g;

interface ICensoredUser {
    lastSeen: number;
    userID: string;
    username: string;
}

// tslint:disable-next-line: no-var-requires

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
    forward: boolean;
    authorID: string;
    readerID: string;
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

export interface IDevice extends XTypes.SQL.IDevice {}

/**
 * IUser is a single user on the vex platform.
 */
export interface IUser extends ICensoredUser {}

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
 * Ifile is an uploaded encrypted file.
 */
export interface IFile extends XTypes.SQL.IFile {}

/**
 * IFileRes is a server response to a file retrieval request.
 */
export interface IFileRes extends XTypes.HTTP.IFileResponse {}

/**
 * @ignore
 */
interface IMe {
    user: () => ICensoredUser;
    device: () => XTypes.SQL.IDevice;
    setAvatar: (avatar: Buffer) => Promise<void>;
}

/**
 * @ignore
 */
interface IUsers {
    retrieve: (userID: string) => Promise<[IUser | null, AxiosError | null]>;
    familiars: () => Promise<IUser[]>;
}

/**
 * @ignore
 */
interface IMessages {
    send: (userID: string, message: string) => Promise<void>;
    group: (channelID: string, message: string) => Promise<void>;
    retrieve: (userID: string) => Promise<IMessage[]>;
    retrieveGroup: (channelID: string) => Promise<IMessage[]>;
    delete: (userOrChannelID: string, duration?: string) => Promise<void>;
    purge: () => Promise<void>;
}

/**
 * @ignore
 */
interface IServers {
    retrieve: () => Promise<XTypes.SQL.IServer[]>;
    retrieveByID: (serverID: string) => Promise<XTypes.SQL.IServer | null>;
    create: (name: string) => Promise<XTypes.SQL.IServer>;
    delete: (serverID: string) => Promise<void>;
    leave: (serverID: string) => Promise<void>;
}

/**
 * @ignore
 */
interface IModeration {
    kick: (userID: string, serverID: string) => Promise<void>;
    fetchPermissionList: (
        serverID: string
    ) => Promise<XTypes.SQL.IPermission[]>;
}

/**
 * @ignore
 */
interface IPermissions {
    retrieve: () => Promise<XTypes.SQL.IPermission[]>;
    delete: (permissionID: string) => Promise<void>;
}

/**
 * @ignore
 */
interface IInvites {
    redeem: (inviteID: string) => Promise<XTypes.SQL.IPermission>;
    create: (serverID: string, duration: string) => Promise<XTypes.SQL.IInvite>;
    retrieve: (serverID: string) => Promise<XTypes.SQL.IInvite[]>;
}

/**
 * @ignore
 */
interface IChannels {
    retrieve: (serverID: string) => Promise<XTypes.SQL.IChannel[]>;
    retrieveByID: (channelID: string) => Promise<XTypes.SQL.IChannel | null>;
    create: (name: string, serverID: string) => Promise<XTypes.SQL.IChannel>;
    delete: (channelID: string) => Promise<void>;
    userList: (channelID: string) => Promise<IUser[]>;
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
interface IDevices {
    retrieve: (deviceIdentifier: string) => Promise<XTypes.SQL.IDevice | null>;
    register: () => Promise<XTypes.SQL.IDevice | null>;
    delete: (deviceID: string) => Promise<void>;
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
 * @ignore
 */
interface IEmoji {
    create: (
        emoji: Buffer,
        name: string,
        serverID: string
    ) => Promise<XTypes.SQL.IEmoji | null>;
    retrieveList: (serverID: string) => Promise<XTypes.SQL.IEmoji[]>;
    retrieve: (emojiID: string) => Promise<XTypes.SQL.IEmoji | null>;
}

export interface IFileProgress {
    token: string;
    direction: "upload" | "download";
    progress: number;
    loaded: number;
    total: number;
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
    dbLogLevel?:
        | "error"
        | "warn"
        | "info"
        | "http"
        | "verbose"
        | "debug"
        | "silly";
    unsafeHttp?: boolean;
    saveHistory?: boolean;
}

// tslint:disable-next-line: interface-name
export declare interface Client {
    /**
     * This is emitted for file progress events.
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
    on(
        event: "fileProgress",
        callback: (progress: IFileProgress) => void
    ): this;

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

    // tslint:disable-next-line: unified-signatures
    on(event: "decryptingMail", callback: () => void): this;

    /**
     * This is emitted when you are connected to the chat.
     *
     * Example:
     *
     * ```ts
     *   client.on("connected", (user) => {
     *       // do something
     *   });
     * ```
     *
     * @event
     */
    // tslint:disable-next-line: unified-signatures
    on(event: "connected", callback: () => void): this;

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

    public static create = async (
        privateKey?: string,
        options?: IClientOptions,
        storage?: IStorage
    ): Promise<Client> => {
        const client = new Client(privateKey, options, storage);
        await client.init();
        return client;
    };

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
         * Retrieves the list of users you can currently access, or are already familiar with.
         *
         * @returns - The list of IUser objects.
         */
        familiars: this.getFamiliars.bind(this),
    };

    public emoji: IEmoji = {
        create: this.uploadEmoji.bind(this),
        retrieveList: this.retrieveEmojiList.bind(this),
        retrieve: this.retrieveEmojiByID.bind(this),
    };

    public me: IMe = {
        /**
         * Retrieves your user information
         *
         * @returns - The logged in user's IUser object.
         */
        user: this.getUser.bind(this),
        /**
         * Retrieves current device details
         *
         * @returns - The logged in device's IDevice object.
         */
        device: this.getDevice.bind(this),
        /**
         * Changes your avatar.
         */
        setAvatar: this.uploadAvatar.bind(this),
    };

    public devices: IDevices = {
        retrieve: this.getDeviceByID.bind(this),
        register: this.registerDevice.bind(this),
        delete: this.deleteDevice.bind(this),
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
        delete: this.deletePermission.bind(this),
    };

    /**
     * The IModeration object contains all methods for dealing with permissions.
     */
    public moderation: IModeration = {
        kick: this.kickUser.bind(this),
        fetchPermissionList: this.fetchPermissionList.bind(this),
    };

    /**
     * The IInvites interface contains methods for dealing with invites.
     */
    public invites: IInvites = {
        create: this.createInvite.bind(this),
        redeem: this.redeemInvite.bind(this),
        retrieve: this.retrieveInvites.bind(this),
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
        delete: this.deleteHistory.bind(this),
        purge: this.purgeHistory.bind(this),
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
        leave: this.leaveServer.bind(this),
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
        /**
         * Retrieves a channel's userlist.
         * @param channelID: The channelID to retrieve userlist for.
         */
        userList: this.getUserList.bind(this),
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

    public sending: Record<string, IDevice> = {};

    private database: IStorage;
    private dbPath: string;
    private conn: WebSocket;
    private host: string;

    private firstMailFetch = true;

    // these are created from one set of sign keys
    private signKeys: nacl.SignKeyPair;
    private idKeys: nacl.BoxKeyPair | null;

    private xKeyRing?: XTypes.CRYPTO.IXKeyRing;

    private user?: ICensoredUser;
    private device?: XTypes.SQL.IDevice;

    private userRecords: Record<string, IUser> = {};
    private deviceRecords: Record<string, IDevice> = {};
    private sessionRecords: Record<string, XTypes.CRYPTO.ISession> = {};

    private isAlive: boolean = true;
    private reading: boolean = false;
    private fetchingMail: boolean = false;

    private cookies: string[] = [];

    private log: winston.Logger;

    private pingInterval: ReturnType<typeof setTimeout> | null = null;
    private mailInterval?: NodeJS.Timeout;

    private manuallyClosing: boolean = false;

    private token: string | null = null;

    private forwarded: string[] = [];

    private prefixes:
        | { HTTP: "http://"; WS: "ws://" }
        | { HTTP: "https://"; WS: "wss://" };

    private constructor(
        privateKey?: string,
        options?: IClientOptions,
        storage?: IStorage
    ) {
        super();

        this.log = createLogger("client", options?.logLevel);

        this.prefixes = options?.unsafeHttp
            ? { HTTP: "http://", WS: "ws://" }
            : { HTTP: "https://", WS: "wss://" };

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

        this.database = storage
            ? storage
            : new Storage(
                  this.dbPath,
                  XUtils.encodeHex(this.signKeys.secretKey),
                  options
              );

        this.database.on("error", (error) => {
            this.log.error(error.toString());
            this.close(true);
        });

        // we want to initialize this later with login()
        this.conn = new WebSocket("ws://localhost:1234");
        // silence the error for connecting to junk ws
        // tslint:disable-next-line: no-empty
        this.conn.onerror = () => {};

        this.log.info(
            "Client debug information: " +
                JSON.stringify(
                    {
                        publicKey: this.getKeys().public,
                        host: this.getHost(),
                        dbPath: this.dbPath,
                        environment: {
                            isBrowser,
                            isNode,
                        },
                        options,
                    },
                    null,
                    4
                )
        );
    }

    public getHost() {
        return this.prefixes.HTTP + this.host;
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

    public async login(
        username: string,
        password: string
    ): Promise<Error | null> {
        try {
            const res = await ax.post(
                this.getHost() + "/auth",
                msgpack.encode({
                    username,
                    password,
                }),
                {
                    headers: { "Content-Type": "application/msgpack" },
                }
            );
            const {
                user,
                token,
            }: { user: ICensoredUser; token: string } = msgpack.decode(
                Buffer.from(res.data)
            );

            const cookies = res.headers["set-cookie"];
            if (cookies) {
                for (const cookie of cookies) {
                    if (cookie.includes("auth")) {
                        this.addCookie(cookie);
                    }
                }
            }

            this.setUser(user);
            this.token = token;
        } catch (err) {
            console.error(err.toString());
            return err;
        }
        return null;
    }

    /**
     * Returns the authorization cookie details. Throws if you don't have a
     * valid authorization cookie.
     */
    public async whoami(): Promise<{
        user: ICensoredUser;
        exp: number;
        token: string;
    }> {
        const res = await ax.post(this.getHost() + "/whoami", null, {
            withCredentials: true,
            responseType: "arraybuffer",
        });

        const whoami: {
            user: ICensoredUser;
            exp: number;
            token: string;
        } = msgpack.decode(Buffer.from(res.data));
        return whoami;
    }

    public async logout(): Promise<void> {
        await ax.post(this.getHost() + "/goodbye");
    }

    /**
     * Connects your device to the chat. You must have an valid authorization cookie.
     * You can check whoami() to see before calling connect().
     */
    public async connect(): Promise<void> {
        const { user, token } = await this.whoami();
        this.token = token;

        if (!user || !token) {
            throw new Error("Auth cookie missing or expired. Log in again.");
        }
        this.setUser(user);

        this.device = await this.retrieveOrCreateDevice();

        const connectToken = await this.getToken("connect");
        if (!connectToken) {
            throw new Error("Couldn't get connect token.");
        }
        const signed = nacl.sign(
            Uint8Array.from(uuid.parse(connectToken.key)),
            this.signKeys.secretKey
        );

        const res = await ax.post(
            this.getHost() + "/device/" + this.device.deviceID + "/connect",
            msgpack.encode({ signed }),
            { headers: { "Content-Type": "application/msgpack" } }
        );
        const cookies = res.headers["set-cookie"];
        if (cookies) {
            for (const cookie of cookies) {
                if (cookie.includes("device")) {
                    this.addCookie(cookie);
                }
            }
        }

        this.log.info("Starting websocket.");
        this.initSocket();
        await this.negotiateOTK();
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
        username: string,
        password: string
    ): Promise<[ICensoredUser | null, Error | null]> {
        while (!this.xKeyRing) {
            await sleep(100);
        }
        const regKey = await this.getToken("register");
        if (regKey) {
            const signKey = XUtils.encodeHex(this.signKeys.publicKey);
            const signed = XUtils.encodeHex(
                nacl.sign(
                    Uint8Array.from(uuid.parse(regKey.key)),
                    this.signKeys.secretKey
                )
            );
            const regMsg: XTypes.HTTP.IRegistrationPayload = {
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
                password,
                deviceName: `${os.platform()}`,
            };
            try {
                const res = await ax.post(
                    this.getHost() + "/register",
                    msgpack.encode(regMsg),
                    { headers: { "Content-Type": "application/msgpack" } }
                );
                this.setUser(msgpack.decode(Buffer.from(res.data)));
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

    public toString(): string {
        return this.user?.username + "<" + this.device?.deviceID + ">";
    }

    private async redeemInvite(
        inviteID: string
    ): Promise<XTypes.SQL.IPermission> {
        const res = await ax.patch(this.getHost() + "/invite/" + inviteID);
        return msgpack.decode(Buffer.from(res.data));
    }

    private async retrieveInvites(
        serverID: string
    ): Promise<XTypes.SQL.IInvite[]> {
        const res = await ax.get(
            this.getHost() + "/server/" + serverID + "/invites"
        );
        return msgpack.decode(Buffer.from(res.data));
    }

    private async createInvite(serverID: string, duration: string) {
        const payload = {
            serverID,
            duration,
        };

        const res = await ax.post(
            this.getHost() + "/server/" + serverID + "/invites",
            payload
        );

        return msgpack.decode(Buffer.from(res.data));
    }

    private async retrieveEmojiList(
        serverID: string
    ): Promise<XTypes.SQL.IEmoji[]> {
        const res = await ax.get(
            this.getHost() + "/server/" + serverID + "/emoji"
        );
        return msgpack.decode(Buffer.from(res.data));
    }

    private async retrieveEmojiByID(
        emojiID: string
    ): Promise<XTypes.SQL.IEmoji | null> {
        const res = await ax.get(
            this.getHost() + "/emoji/" + emojiID + "/details"
        );
        // this is actually empty string
        if (!res.data) {
            return null;
        }
        return msgpack.decode(Buffer.from(res.data));
    }

    private async leaveServer(serverID: string): Promise<void> {
        const permissionList = await this.permissions.retrieve();
        for (const permission of permissionList) {
            if (permission.resourceID === serverID) {
                await this.deletePermission(permission.permissionID);
            }
        }
    }

    private async kickUser(userID: string, serverID: string): Promise<void> {
        const permissionList = await this.fetchPermissionList(serverID);
        for (const permission of permissionList) {
            if (userID === permission.userID) {
                await this.deletePermission(permission.permissionID);
                return;
            }
        }
        throw new Error("Couldn't kick user.");
    }

    private addCookie(cookie: string) {
        if (!this.cookies.includes(cookie)) {
            this.cookies.push(cookie);
            this.log.info("cookies changed", this.getCookies());
            if (isNode) {
                ax.defaults.headers.cookie = this.cookies.join(";");
            }
        }
    }

    private getCookies() {
        return this.cookies.join(";");
    }

    private async uploadEmoji(
        emoji: Buffer,
        name: string,
        serverID: string
    ): Promise<XTypes.SQL.IEmoji | null> {
        if (typeof FormData !== "undefined") {
            const fpayload = new FormData();
            fpayload.set("emoji", new Blob([emoji]));
            fpayload.set("name", name);

            try {
                const res = await ax.post(
                    this.getHost() + "/emoji/" + serverID,
                    fpayload,
                    {
                        headers: { "Content-Type": "multipart/form-data" },
                        onUploadProgress: (progressEvent) => {
                            const percentCompleted = Math.round(
                                (progressEvent.loaded * 100) /
                                    progressEvent.total
                            );
                            const { loaded, total } = progressEvent;
                            const progress: IFileProgress = {
                                direction: "upload",
                                token: name,
                                progress: percentCompleted,
                                loaded,
                                total,
                            };
                            this.emit("fileProgress", progress);
                        },
                    }
                );
                return msgpack.decode(Buffer.from(res.data));
            } catch (err) {
                return null;
            }
        }

        const payload: { file: string; name: string } = {
            file: XUtils.encodeBase64(emoji),
            name,
        };
        try {
            const res = await ax.post(
                this.getHost() + "/emoji/" + serverID + "/json",
                msgpack.encode(payload),
                { headers: { "Content-Type": "application/msgpack" } }
            );
            return msgpack.decode(Buffer.from(res.data));
        } catch (err) {
            return null;
        }
    }

    private async retrieveOrCreateDevice(): Promise<XTypes.SQL.IDevice> {
        let device: XTypes.SQL.IDevice;
        try {
            const res = await ax.get(
                this.prefixes.HTTP +
                    this.host +
                    "/device/" +
                    XUtils.encodeHex(this.signKeys.publicKey)
            );
            device = msgpack.decode(Buffer.from(res.data));
        } catch (err) {
            this.log.error(err.toString());
            if (err.response?.status === 404) {
                // just in case
                await this.database.purgeKeyData();
                await this.populateKeyRing();

                this.log.info("Attempting to register device.");

                const newDevice = await this.registerDevice();
                if (newDevice) {
                    device = newDevice;
                } else {
                    throw new Error("Error registering device.");
                }
            } else {
                throw err;
            }
        }
        this.log.info("Got device " + JSON.stringify(device, null, 4));
        return device;
    }

    private async registerDevice(): Promise<XTypes.SQL.IDevice | null> {
        while (!this.xKeyRing) {
            await sleep(100);
        }

        const token = await this.getToken("device");

        const [userDetails, err] = await this.retrieveUserDBEntry(
            this.user!.username
        );
        if (!userDetails) {
            throw new Error("Username not found " + this.user!.username);
        }
        if (err) {
            throw err;
        }
        if (!token) {
            throw new Error("Couldn't fetch token.");
        }

        const signKey = this.getKeys().public;
        const signed = XUtils.encodeHex(
            nacl.sign(
                Uint8Array.from(uuid.parse(token.key)),
                this.signKeys.secretKey
            )
        );

        const devMsg: XTypes.HTTP.IDevicePayload = {
            username: userDetails.username,
            signKey,
            signed,
            preKey: XUtils.encodeHex(this.xKeyRing.preKeys.keyPair.publicKey),
            preKeySignature: XUtils.encodeHex(this.xKeyRing.preKeys.signature),
            preKeyIndex: this.xKeyRing.preKeys.index!,
            deviceName: `${os.platform()}`,
        };

        try {
            const res = await ax.post(
                this.prefixes.HTTP +
                    this.host +
                    "/user/" +
                    userDetails.userID +
                    "/devices",
                msgpack.encode(devMsg),
                { headers: { "Content-Type": "application/msgpack" } }
            );
            return msgpack.decode(Buffer.from(res.data));
        } catch (err) {
            throw err;
        }
    }

    private async getToken(
        type:
            | "register"
            | "file"
            | "avatar"
            | "device"
            | "invite"
            | "emoji"
            | "connect"
    ): Promise<XTypes.HTTP.IActionToken | null> {
        try {
            const res = await ax.get(this.getHost() + "/token/" + type, {
                responseType: "arraybuffer",
            });
            return msgpack.decode(Buffer.from(res.data));
        } catch (err) {
            this.log.warn(err.toString());
            return null;
        }
    }

    private async uploadAvatar(avatar: Buffer): Promise<void> {
        if (typeof FormData !== "undefined") {
            const fpayload = new FormData();
            fpayload.set("avatar", new Blob([avatar]));

            await ax.post(
                this.prefixes.HTTP +
                    this.host +
                    "/avatar/" +
                    this.me.user().userID,
                fpayload,
                {
                    headers: { "Content-Type": "multipart/form-data" },
                    onUploadProgress: (progressEvent) => {
                        const percentCompleted = Math.round(
                            (progressEvent.loaded * 100) / progressEvent.total
                        );
                        const { loaded, total } = progressEvent;
                        const progress: IFileProgress = {
                            direction: "upload",
                            token: this.getUser().userID,
                            progress: percentCompleted,
                            loaded,
                            total,
                        };
                        this.emit("fileProgress", progress);
                    },
                }
            );
            return;
        }

        const payload: { file: string } = {
            file: XUtils.encodeBase64(avatar),
        };
        await ax.post(
            this.prefixes.HTTP +
                this.host +
                "/avatar/" +
                this.me.user().userID +
                "/json",
            msgpack.encode(payload),
            { headers: { "Content-Type": "application/msgpack" } }
        );
    }

    /**
     * Gets a list of permissions for a server.
     *
     * @returns - The list of IPermissions objects.
     */
    private async fetchPermissionList(
        serverID: string
    ): Promise<XTypes.SQL.IPermission[]> {
        const res = await ax.get(
            this.prefixes.HTTP +
                this.host +
                "/server/" +
                serverID +
                "/permissions"
        );
        return msgpack.decode(Buffer.from(res.data));
    }

    /**
     * Gets all permissions for the logged in user.
     *
     * @returns - The list of IPermissions objects.
     */
    private async getPermissions(): Promise<XTypes.SQL.IPermission[]> {
        const res = await ax.get(
            this.getHost() + "/user/" + this.getUser().userID + "/permissions"
        );
        return msgpack.decode(Buffer.from(res.data));
    }

    private async deletePermission(permissionID: string): Promise<void> {
        await ax.delete(this.getHost() + "/permission/" + permissionID);
    }

    private async retrieveFile(
        fileID: string,
        key: string
    ): Promise<XTypes.HTTP.IFileResponse | null> {
        try {
            const detailsRes = await ax.get(
                this.getHost() + "/file/" + fileID + "/details"
            );
            const details = msgpack.decode(Buffer.from(detailsRes.data));

            const res = await ax.get(this.getHost() + "/file/" + fileID, {
                onDownloadProgress: (progressEvent) => {
                    const percentCompleted = Math.round(
                        (progressEvent.loaded * 100) / progressEvent.total
                    );
                    const { loaded, total } = progressEvent;
                    const progress: IFileProgress = {
                        direction: "download",
                        token: fileID,
                        progress: percentCompleted,
                        loaded,
                        total,
                    };
                    this.emit("fileProgress", progress);
                },
            });
            const fileData = res.data;

            const decrypted = nacl.secretbox.open(
                Uint8Array.from(Buffer.from(fileData)),
                XUtils.decodeHex(details.nonce),
                XUtils.decodeHex(key)
            );

            if (decrypted) {
                const resp: XTypes.HTTP.IFileResponse = {
                    details,
                    data: Buffer.from(decrypted),
                };
                return resp;
            }
            throw new Error("Decryption failed.");
        } catch (err) {
            throw err;
        }
    }

    private async deleteServer(serverID: string): Promise<void> {
        await ax.delete(this.getHost() + "/server/" + serverID);
    }

    /**
     * Initializes the keyring. This must be called before anything else.
     */
    private async init() {
        if (this.hasInit) {
            return new Error("You should only call init() once.");
        }
        this.hasInit = true;

        await this.populateKeyRing();
        this.on("message", async (message) => {
            if (message.direction === "outgoing" && !message.forward) {
                this.forward(message);
            }

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

    private async deleteChannel(channelID: string): Promise<void> {
        await ax.delete(this.getHost() + "/channel/" + channelID);
    }

    // returns the file details and the encryption key
    private async createFile(
        file: Buffer
    ): Promise<[XTypes.SQL.IFile, string]> {
        this.log.info(
            "Creating file, size: " + formatBytes(Buffer.byteLength(file))
        );

        const nonce = xMakeNonce();
        const key = nacl.box.keyPair();
        const box = nacl.secretbox(Uint8Array.from(file), nonce, key.secretKey);

        this.log.info("Encrypted size: " + formatBytes(Buffer.byteLength(box)));

        if (typeof FormData !== "undefined") {
            const fpayload = new FormData();
            fpayload.set("owner", this.getDevice().deviceID);
            fpayload.set("nonce", XUtils.encodeHex(nonce));
            fpayload.set("file", new Blob([box]));

            const fres = await ax.post(this.getHost() + "/file", fpayload, {
                headers: { "Content-Type": "multipart/form-data" },
                onUploadProgress: (progressEvent) => {
                    const percentCompleted = Math.round(
                        (progressEvent.loaded * 100) / progressEvent.total
                    );
                    const { loaded, total } = progressEvent;
                    const progress: IFileProgress = {
                        direction: "upload",
                        token: XUtils.encodeHex(nonce),
                        progress: percentCompleted,
                        loaded,
                        total,
                    };
                    this.emit("fileProgress", progress);
                },
            });
            const fcreatedFile: XTypes.SQL.IFile = msgpack.decode(
                Buffer.from(fres.data)
            );

            return [fcreatedFile, XUtils.encodeHex(key.secretKey)];
        }

        const payload: {
            owner: string;
            nonce: string;
            file: string;
        } = {
            owner: this.getDevice().deviceID,
            nonce: XUtils.encodeHex(nonce),
            file: XUtils.encodeBase64(box),
        };
        const res = await ax.post(
            this.getHost() + "/file/json",
            msgpack.encode(payload),
            { headers: { "Content-Type": "application/msgpack" } }
        );
        const createdFile: XTypes.SQL.IFile = msgpack.decode(
            Buffer.from(res.data)
        );

        return [createdFile, XUtils.encodeHex(key.secretKey)];
    }

    private async getUserList(channelID: string): Promise<IUser[]> {
        const res = await ax.post(this.getHost() + "/userList/" + channelID);
        return msgpack.decode(Buffer.from(res.data));
    }

    private async markSessionVerified(sessionID: string) {
        return this.database.markSessionVerified(sessionID);
    }

    private async getGroupHistory(channelID: string): Promise<IMessage[]> {
        const messages: IMessage[] = await this.database.getGroupHistory(
            channelID
        );

        return messages;
    }

    private async deleteHistory(
        channelOrUserID: string,
        olderThan?: string
    ): Promise<void> {
        await this.database.deleteHistory(channelOrUserID, olderThan);
    }

    private async purgeHistory(): Promise<void> {
        await this.database.purgeHistory();
    }

    private async getMessageHistory(userID: string): Promise<IMessage[]> {
        const messages: IMessage[] = await this.database.getMessageHistory(
            userID
        );

        return messages;
    }

    private async sendMessage(userID: string, message: string): Promise<void> {
        try {
            const [userEntry, err] = await this.retrieveUserDBEntry(userID);
            if (err) {
                throw err;
            }
            if (!userEntry) {
                throw new Error("Couldn't get user entry.");
            }

            let deviceList = await this.getUserDeviceList(userID);
            if (!deviceList) {
                let retries = 0;
                while (!deviceList) {
                    deviceList = await this.getUserDeviceList(userID);
                    retries++;
                    if (retries > 3) {
                        throw new Error("Couldn't get device list.");
                    }
                }
            }
            const mailID = uuid.v4();
            const promises: Array<Promise<any>> = [];
            for (const device of deviceList) {
                promises.push(
                    this.sendMail(
                        device,
                        userEntry,
                        XUtils.decodeUTF8(message),
                        null,
                        mailID,
                        false
                    )
                );
            }
            Promise.allSettled(promises).then((results) => {
                for (const result of results) {
                    const { status } = result;
                    if (status === "rejected") {
                        this.log.warn("Message failed.");
                        this.log.warn(result);
                    }
                }
            });
        } catch (err) {
            this.log.error(
                "Message " + (err.message?.mailID || "") + " threw exception."
            );
            this.log.error(err.toString());
            if (err.message?.mailID) {
                await this.database.deleteMessage(err.message.mailID);
            }
            throw err;
        }
    }

    private async sendGroupMessage(
        channelID: string,
        message: string
    ): Promise<void> {
        const userList = await this.getUserList(channelID);
        for (const user of userList) {
            this.userRecords[user.userID] = user;
        }

        this.log.info(
            "Sending to userlist:\n" + JSON.stringify(userList, null, 4)
        );

        const mailID = uuid.v4();
        const promises: Array<Promise<void>> = [];

        const userIDs = [...new Set(userList.map((user) => user.userID))];
        const devices = await this.getMultiUserDeviceList(userIDs);

        this.log.info(
            "Retrieved devicelist:\n" + JSON.stringify(devices, null, 4)
        );

        for (const device of devices) {
            promises.push(
                this.sendMail(
                    device,
                    this.userRecords[device.owner],
                    XUtils.decodeUTF8(message),
                    uuidToUint8(channelID),
                    mailID,
                    false
                )
            );
        }
        Promise.allSettled(promises).then((results) => {
            for (const result of results) {
                const { status } = result;
                if (status === "rejected") {
                    this.log.warn("Message failed.");
                    this.log.warn(result);
                }
            }
        });
    }

    private async createServer(name: string): Promise<XTypes.SQL.IServer> {
        const res = await ax.post(this.getHost() + "/server/" + btoa(name));
        return msgpack.decode(Buffer.from(res.data));
    }

    private async forward(message: IMessage) {
        const copy = { ...message };

        if (this.forwarded.includes(copy.mailID)) {
            return;
        }
        this.forwarded.push(copy.mailID);
        if (this.forwarded.length > 1000) {
            this.forwarded.shift();
        }

        const msgBytes = Uint8Array.from(msgpack.encode(copy));

        const devices = await this.getUserDeviceList(this.getUser().userID);
        this.log.info(
            "Forwarding to my other devices, deviceList length is " +
                devices?.length
        );

        if (!devices) {
            throw new Error("Couldn't get own devices.");
        }
        const promises = [];
        for (const device of devices) {
            if (device.deviceID !== this.getDevice().deviceID) {
                promises.push(
                    this.sendMail(
                        device,
                        this.getUser(),
                        msgBytes,
                        null,
                        copy.mailID,
                        true
                    )
                );
            }
        }
        Promise.allSettled(promises).then((results) => {
            for (const result of results) {
                const { status } = result;
                if (status === "rejected") {
                    this.log.warn("Message failed.");
                    this.log.warn(result);
                }
            }
        });
    }

    /* Sends encrypted mail to a user. */
    private async sendMail(
        device: IDevice,
        user: IUser,
        msg: Uint8Array,
        group: Uint8Array | null,
        mailID: string | null,
        forward: boolean,
        retry = false
    ): Promise<void> {
        while (this.sending[device.deviceID] !== undefined) {
            this.log.warn(
                "Sending in progress to device ID " +
                    device.deviceID +
                    ", waiting."
            );
            await sleep(100);
        }
        this.log.info(
            "Sending mail to user: \n" + JSON.stringify(user, null, 4)
        );
        this.log.info(
            "Sending mail to device:\n " +
                JSON.stringify(device.deviceID, null, 4)
        );
        this.sending[device.deviceID] = device;

        const session = await this.database.getSessionByDeviceID(
            device.deviceID
        );

        if (!session || retry) {
            this.log.info("Creating new session for " + device.deviceID);
            await this.createSession(device, user, msg, group, mailID, forward);
            return;
        } else {
            this.log.info("Found existing session for " + device.deviceID);
        }

        const nonce = xMakeNonce();
        const cipher = nacl.secretbox(msg, nonce, session.SK);
        const extra = session.publicKey;

        const mail: XTypes.WS.IMail = {
            mailType: XTypes.WS.MailType.subsequent,
            mailID: mailID || uuid.v4(),
            recipient: device.deviceID,
            cipher,
            nonce,
            extra,
            sender: this.getDevice().deviceID,
            group,
            forward,
            authorID: this.getUser().userID,
            readerID: session.userID,
        };

        const msgb: XTypes.WS.IResourceMsg = {
            transmissionID: uuid.v4(),
            type: "resource",
            resourceType: "mail",
            action: "CREATE",
            data: mail,
        };

        const hmac = xHMAC(mail, session.SK);
        this.log.info("Mail hash: " + objectHash(mail));
        this.log.info("Calculated hmac: " + XUtils.encodeHex(hmac));

        const outMsg: IMessage = forward
            ? { ...msgpack.decode(msg), forward: true }
            : {
                  mailID: mail.mailID,
                  sender: mail.sender,
                  recipient: mail.recipient,
                  nonce: XUtils.encodeHex(mail.nonce),
                  message: XUtils.encodeUTF8(msg),
                  direction: "outgoing",
                  timestamp: new Date(Date.now()),
                  decrypted: true,
                  group: mail.group ? uuid.stringify(mail.group) : null,
                  forward: mail.forward,
                  authorID: mail.authorID,
                  readerID: mail.readerID,
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
        delete this.sending[device.deviceID];
    }

    private async getSessionList() {
        return this.database.getAllSessions();
    }

    private async getServerList(): Promise<XTypes.SQL.IServer[]> {
        const res = await ax.get(
            this.getHost() + "/user/" + this.getUser().userID + "/servers"
        );
        return msgpack.decode(Buffer.from(res.data));
    }

    private async createChannel(
        name: string,
        serverID: string
    ): Promise<XTypes.SQL.IChannel> {
        const body = { name };
        const res = await ax.post(
            this.getHost() + "/server/" + serverID + "/channels",
            msgpack.encode(body),
            { headers: { "Content-Type": "application/msgpack" } }
        );
        return msgpack.decode(Buffer.from(res.data));
    }

    private async getDeviceByID(
        deviceID: string
    ): Promise<XTypes.SQL.IDevice | null> {
        if (this.deviceRecords[deviceID]) {
            this.log.info("Found device in local cache.");
            return this.deviceRecords[deviceID];
        }

        const device = await this.database.getDevice(deviceID);
        if (device) {
            this.log.info("Found device in local db.");
            this.deviceRecords[deviceID] = device;
            return device;
        }
        try {
            const res = await ax.get(this.getHost() + "/device/" + deviceID);
            this.log.info("Retrieved device from server.");
            const fetchedDevice = msgpack.decode(Buffer.from(res.data));
            this.deviceRecords[deviceID] = fetchedDevice;
            await this.database.saveDevice(fetchedDevice);
            return fetchedDevice;
        } catch (err) {
            return null;
        }
    }

    private async deleteDevice(deviceID: string): Promise<void> {
        if (deviceID === this.getDevice().deviceID) {
            throw new Error("You can't delete the device you're logged in to.");
        }
        await ax.delete(
            this.prefixes.HTTP +
                this.host +
                "/user/" +
                this.getUser().userID +
                "/devices/" +
                deviceID
        );
    }

    private async getMultiUserDeviceList(
        userIDs: string[]
    ): Promise<XTypes.SQL.IDevice[]> {
        try {
            const res = await ax.post(
                this.getHost() + "/deviceList",
                msgpack.encode(userIDs),
                { headers: { "Content-Type": "application/msgpack" } }
            );
            const devices: XTypes.SQL.IDevice[] = msgpack.decode(
                Buffer.from(res.data)
            );
            for (const device of devices) {
                this.deviceRecords[device.deviceID] = device;
            }

            return devices;
        } catch (err) {
            return [];
        }
    }

    private async getUserDeviceList(
        userID: string
    ): Promise<XTypes.SQL.IDevice[] | null> {
        try {
            const res = await ax.get(
                this.getHost() + "/user/" + userID + "/devices"
            );
            const devices: XTypes.SQL.IDevice[] = msgpack.decode(
                Buffer.from(res.data)
            );
            for (const device of devices) {
                this.deviceRecords[device.deviceID] = device;
            }

            return devices;
        } catch (err) {
            return null;
        }
    }

    private async getServerByID(
        serverID: string
    ): Promise<XTypes.SQL.IServer | null> {
        try {
            const res = await ax.get(this.getHost() + "/server/" + serverID);
            return msgpack.decode(Buffer.from(res.data));
        } catch (err) {
            return null;
        }
    }

    private async getChannelByID(
        channelID: string
    ): Promise<XTypes.SQL.IChannel | null> {
        try {
            const res = await ax.get(this.getHost() + "/channel/" + channelID);
            return msgpack.decode(Buffer.from(res.data));
        } catch (err) {
            return null;
        }
    }

    private async getChannelList(
        serverID: string
    ): Promise<XTypes.SQL.IChannel[]> {
        const res = await ax.get(
            this.getHost() + "/server/" + serverID + "/channels"
        );
        return msgpack.decode(Buffer.from(res.data));
    }

    /* Get the currently logged in user. You cannot call this until 
    after the auth event is emitted. */
    private getUser(): ICensoredUser {
        if (!this.user) {
            throw new Error(
                "You must wait until the auth event is emitted before fetching user details."
            );
        }
        return this.user;
    }

    private getDevice(): XTypes.SQL.IDevice {
        if (!this.device) {
            throw new Error(
                "You must wait until the auth event is emitted before fetching device details."
            );
        }
        return this.device;
    }

    private setUser(user: ICensoredUser): void {
        this.user = user;
    }

    /* Retrieves the userID with the user identifier.
    user identifier is checked for userID, then signkey,
    and finally falls back to username. */
    private async retrieveUserDBEntry(
        userIdentifier: string
    ): Promise<[ICensoredUser | null, AxiosError | null]> {
        if (this.userRecords[userIdentifier]) {
            return [this.userRecords[userIdentifier], null];
        }

        try {
            const res = await ax.get(
                this.getHost() + "/user/" + userIdentifier
            );
            const userRecord = msgpack.decode(Buffer.from(res.data));
            this.userRecords[userIdentifier] = userRecord;
            return [userRecord, null];
        } catch (err) {
            return [null, err];
        }
    }

    /* Retrieves the current list of users you have sessions with. */
    private async getFamiliars(): Promise<IUser[]> {
        const sessions = await this.database.getAllSessions();
        const familiars: IUser[] = [];

        for (const session of sessions) {
            const [user, err] = await this.retrieveUserDBEntry(session.userID);
            if (user) {
                familiars.push(user);
            }
        }

        return familiars;
    }

    private async createSession(
        device: IDevice,
        user: IUser,
        message: Uint8Array,
        group: Uint8Array | null,
        /* this is passed through if the first message is 
        part of a group message */
        mailID: string | null,
        forward: boolean
    ): Promise<void> {
        let keyBundle: XTypes.WS.IKeyBundle;

        this.log.info(
            "Requesting key bundle for device: " +
                JSON.stringify(device, null, 4)
        );
        try {
            keyBundle = await this.retrieveKeyBundle(device.deviceID);
        } catch (err) {
            this.log.warn("Couldn't get key bundle:", err);
            return;
        }

        this.log.warn(
            this.toString() +
                " retrieved keybundle #" +
                keyBundle.otk?.index.toString() +
                " for " +
                device.deviceID
        );

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
        this.log.info("Obtained SK, " + XUtils.encodeHex(SK));

        const PK = nacl.box.keyPair.fromSecretKey(SK).publicKey;
        this.log.info(
            this.toString() +
                " Obtained PK for " +
                device.deviceID +
                " " +
                XUtils.encodeHex(PK)
        );

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
            recipient: device.deviceID,
            cipher,
            nonce,
            extra,
            sender: this.getDevice().deviceID,
            group,
            forward,
            authorID: this.getUser().userID,
            readerID: user.userID,
        };

        const hmac = xHMAC(mail, SK);
        this.log.info("Mail hash: " + objectHash(mail));
        this.log.info("Generated hmac: " + XUtils.encodeHex(hmac));

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
            userID: user.userID,
            mode: "initiator",
            SK: XUtils.encodeHex(SK),
            publicKey: XUtils.encodeHex(PK),
            lastUsed: new Date(Date.now()),
            fingerprint: XUtils.encodeHex(AD),
            deviceID: device.deviceID,
        };

        await this.database.saveSession(sessionEntry);

        this.emit("session", sessionEntry, user);

        // emit the message
        const emitMsg: IMessage = forward
            ? { ...msgpack.decode(message), forward: true }
            : {
                  nonce: XUtils.encodeHex(mail.nonce),
                  mailID: mail.mailID,
                  sender: mail.sender,
                  recipient: mail.recipient,
                  message: XUtils.encodeUTF8(message),
                  direction: "outgoing",
                  timestamp: new Date(Date.now()),
                  decrypted: true,
                  group: mail.group ? uuid.stringify(mail.group) : null,
                  forward: mail.forward,
                  authorID: mail.authorID,
                  readerID: mail.readerID,
              };
        this.emit("message", emitMsg);

        // send mail and wait for response
        await new Promise((res, rej) => {
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
        delete this.sending[device.deviceID];
    }

    private sendReceipt(nonce: Uint8Array) {
        const receipt: XTypes.WS.IReceiptMsg = {
            type: "receipt",
            transmissionID: uuid.v4(),
            nonce,
        };
        this.send(receipt);
    }

    private async getSessionByPubkey(publicKey: Uint8Array) {
        const strPubKey = XUtils.encodeHex(publicKey);
        if (this.sessionRecords[strPubKey]) {
            return this.sessionRecords[strPubKey];
        }
        const session = await this.database.getSessionByPublicKey(publicKey);
        if (session) {
            this.sessionRecords[strPubKey] = session;
        }
        return session;
    }

    private async readMail(
        header: Uint8Array,
        mail: XTypes.WS.IMail,
        timestamp: string
    ) {
        this.sendReceipt(mail.nonce);
        let timeout = 1;
        while (this.reading) {
            await sleep(timeout);
            timeout *= 2;
        }
        this.reading = true;

        const healSession = async () => {
            this.log.info("Requesting retry of " + mail.mailID);
            const deviceEntry = await this.getDeviceByID(mail.sender);
            const [user, err] = await this.retrieveUserDBEntry(mail.authorID);
            if (deviceEntry && user) {
                this.createSession(
                    deviceEntry,
                    user,
                    XUtils.decodeUTF8(`��RETRY_REQUEST:${mail.mailID}��`),
                    mail.group,
                    uuid.v4(),
                    false
                );
            }
        };

        this.log.info("Received mail from " + mail.sender);
        switch (mail.mailType) {
            case XTypes.WS.MailType.subsequent:
                const [publicKey] = Client.deserializeExtra(
                    mail.mailType,
                    mail.extra
                );
                let session = await this.getSessionByPubkey(publicKey);
                let retries = 0;
                while (!session) {
                    if (retries > 3) {
                        break;
                    }

                    session = await this.getSessionByPubkey(publicKey);
                    retries++;
                    return;
                }

                if (!session) {
                    this.log.warn(
                        "Couldn't find session public key " +
                            XUtils.encodeHex(publicKey)
                    );
                    healSession();
                    return;
                }
                this.log.info("Session found for " + mail.sender);
                this.log.info("Mail nonce " + XUtils.encodeHex(mail.nonce));

                const HMAC = xHMAC(mail, session.SK);
                this.log.info("Mail hash: " + objectHash(mail));
                this.log.info("Calculated hmac: " + XUtils.encodeHex(HMAC));

                if (!XUtils.bytesEqual(HMAC, header)) {
                    this.log.warn(
                        "Message authentication failed (HMAC does not match)."
                    );
                    healSession();
                    return;
                }

                const decrypted = nacl.secretbox.open(
                    mail.cipher,
                    mail.nonce,
                    session.SK
                );

                if (decrypted) {
                    this.log.info("Decryption successful.");
                    let plaintext = "";
                    if (!mail.forward) {
                        plaintext = XUtils.encodeUTF8(decrypted);
                    }
                    // emit the message
                    const message: IMessage = mail.forward
                        ? {
                              ...msgpack.decode(decrypted),
                              forward: true,
                          }
                        : {
                              nonce: XUtils.encodeHex(mail.nonce),
                              mailID: mail.mailID,
                              sender: mail.sender,
                              recipient: mail.recipient,
                              message: XUtils.encodeUTF8(decrypted),
                              direction: "incoming",
                              timestamp: new Date(timestamp),
                              decrypted: true,
                              group: mail.group
                                  ? uuid.stringify(mail.group)
                                  : null,
                              forward: mail.forward,
                              authorID: mail.authorID,
                              readerID: mail.readerID,
                          };
                    this.emit("message", message);

                    this.database.markSessionUsed(session.sessionID);
                } else {
                    this.log.info("Decryption failed.");
                    healSession();

                    // emit the message
                    const message: IMessage = {
                        nonce: XUtils.encodeHex(mail.nonce),
                        mailID: mail.mailID,
                        sender: mail.sender,
                        recipient: mail.recipient,
                        message: "",
                        direction: "incoming",
                        timestamp: new Date(timestamp),
                        decrypted: false,
                        group: mail.group ? uuid.stringify(mail.group) : null,
                        forward: mail.forward,
                        authorID: mail.authorID,
                        readerID: mail.readerID,
                    };
                    this.emit("message", message);
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

                this.log.info(
                    this.toString() + " otk #" + preKeyIndex + " indicated"
                );

                const otk =
                    preKeyIndex === 0
                        ? null
                        : await this.database.getOneTimeKey(preKeyIndex);

                if (otk) {
                    this.log.info(
                        "otk #" +
                            JSON.stringify(otk?.index) +
                            " retrieved from database."
                    );
                }

                this.log.info("signKey: " + XUtils.encodeHex(signKey));
                this.log.info("preKey: " + XUtils.encodeHex(ephKey));
                if (otk) {
                    this.log.info(
                        "OTK: " + XUtils.encodeHex(otk.keyPair.publicKey)
                    );
                }

                if (otk?.index !== preKeyIndex && preKeyIndex !== 0) {
                    this.log.warn(
                        "OTK index mismatch, received " +
                            JSON.stringify(otk?.index) +
                            ", expected " +
                            preKeyIndex.toString()
                    );
                    return;
                }

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
                this.log.info(
                    "Obtained SK for " +
                        mail.sender +
                        ", " +
                        XUtils.encodeHex(SK)
                );

                // shared public key
                const PK = nacl.box.keyPair.fromSecretKey(SK).publicKey;
                this.log.info(
                    this.toString() +
                        "Obtained PK for " +
                        mail.sender +
                        " " +
                        XUtils.encodeHex(PK)
                );

                const hmac = xHMAC(mail, SK);
                this.log.info("Mail hash: " + objectHash(mail));
                this.log.info("Calculated hmac: " + XUtils.encodeHex(hmac));

                // associated data
                const AD = xConcat(
                    xEncode(xConstants.CURVE, IK_A),
                    xEncode(xConstants.CURVE, IK_BP)
                );

                if (!XUtils.bytesEqual(hmac, header)) {
                    console.warn(
                        "Mail authentication failed (HMAC did not match)."
                    );
                    console.warn(mail);
                    return;
                }
                this.log.info("Mail authenticated successfully.");

                const unsealed = nacl.secretbox.open(
                    mail.cipher,
                    mail.nonce,
                    SK
                );
                if (unsealed) {
                    this.log.info("Decryption successful.");

                    let plaintext = "";
                    if (!mail.forward) {
                        plaintext = XUtils.encodeUTF8(unsealed);
                    }

                    // emit the message
                    const message: IMessage = mail.forward
                        ? { ...msgpack.decode(unsealed), forward: true }
                        : {
                              nonce: XUtils.encodeHex(mail.nonce),
                              mailID: mail.mailID,
                              sender: mail.sender,
                              recipient: mail.recipient,
                              message: plaintext,
                              direction: "incoming",
                              timestamp: new Date(timestamp),
                              decrypted: true,
                              group: mail.group
                                  ? uuid.stringify(mail.group)
                                  : null,
                              forward: mail.forward,
                              authorID: mail.authorID,
                              readerID: mail.readerID,
                          };

                    this.emit("message", message);

                    // discard onetimekey
                    await this.database.deleteOneTimeKey(preKeyIndex);

                    const deviceEntry = await this.getDeviceByID(mail.sender);
                    if (!deviceEntry) {
                        throw new Error("Couldn't get device entry.");
                    }
                    const [userEntry, userErr] = await this.retrieveUserDBEntry(
                        deviceEntry.owner
                    );
                    if (!userEntry) {
                        throw new Error("Couldn't get user entry.");
                    }

                    this.userRecords[userEntry.userID] = userEntry;
                    this.deviceRecords[deviceEntry.deviceID] = deviceEntry;

                    // save session
                    const newSession: XTypes.SQL.ISession = {
                        verified: false,
                        sessionID: uuid.v4(),
                        userID: userEntry.userID,
                        mode: "receiver",
                        SK: XUtils.encodeHex(SK),
                        publicKey: XUtils.encodeHex(PK),
                        lastUsed: new Date(Date.now()),
                        fingerprint: XUtils.encodeHex(AD),
                        deviceID: mail.sender,
                    };
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
                                this.log.warn("Couldn't retrieve user entry.");
                                break;
                            }
                        }
                    }
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
                await this.getMail();
                this.fetchingMail = false;
                break;
            case "permission":
                this.emit("permission", msg.data as IPermission);
                break;
            case "retryRequest":
                const messageID = msg.data;

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
            this.log.warn("No prekeys found in database, creating a new one.");
            preKeys = this.createPreKey();
            await this.database.savePreKeys([preKeys], false);
        }

        const sessions = await this.database.getAllSessions();
        for (const session of sessions) {
            this.sessionRecords[session.publicKey] = sqlSessionToCrypto(
                session
            );
        }

        const ephemeralKeys = nacl.box.keyPair();

        this.xKeyRing = {
            identityKeys,
            preKeys,
            ephemeralKeys,
        };

        this.log.info(
            "Keyring populated:\n" +
                JSON.stringify(
                    {
                        signKey: XUtils.encodeHex(this.signKeys.publicKey),
                        preKey: XUtils.encodeHex(preKeys.keyPair.publicKey),
                        ephemeralKey: XUtils.encodeHex(ephemeralKeys.publicKey),
                    },
                    null,
                    4
                )
        );
    }

    private initSocket() {
        try {
            if (!this.token) {
                throw new Error("No token found, did you call login()?");
            }

            this.conn = new WebSocket(
                this.prefixes.WS + this.host + "/socket",
                { headers: { Cookie: "auth=" + this.token } }
            );
            this.conn.on("open", () => {
                this.log.info("Connection opened.");
                this.pingInterval = setInterval(this.ping.bind(this), 15000);
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
                    case "unauthorized":
                        throw new Error(
                            "Received unauthorized message from server."
                        );
                    case "authorized":
                        this.log.info(
                            "Authenticated with userID " + this.user!.userID
                        );
                        this.emit("connected");
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
        let count = 0;
        while (true) {
            try {
                await this.getMail();
                count++;
                this.fetchingMail = false;

                if (count > 10) {
                    this.negotiateOTK();
                    count = 0;
                }
            } catch (err) {
                this.log.warn("Problem fetching mail" + err.toString());
            }
            await sleep(1000 * 60);
        }
    }

    private async getMail(): Promise<void> {
        while (this.fetchingMail) {
            await sleep(500);
        }
        this.fetchingMail = true;
        let firstFetch = false;
        if (this.firstMailFetch) {
            firstFetch = true;
            this.firstMailFetch = false;
        }

        if (firstFetch) {
            this.emit("decryptingMail");
        }

        this.log.info("fetching mail for device " + this.getDevice().deviceID);
        try {
            const res = await ax.post(
                this.getHost() +
                    "/device/" +
                    this.getDevice().deviceID +
                    "/mail"
            );
            const inbox: Array<[
                Uint8Array,
                XTypes.WS.IMail,
                Date
            ]> = msgpack
                .decode(Buffer.from(res.data))
                .sort(
                    (
                        a: [Uint8Array, XTypes.WS.IMail, Date],
                        b: [Uint8Array, XTypes.WS.IMail, Date]
                    ) => b[2].getTime() - a[2].getTime()
                );

            for (const mailDetails of inbox) {
                const [mailHeader, mailBody, timestamp] = mailDetails;
                try {
                    await this.readMail(
                        mailHeader,
                        mailBody,
                        timestamp.toString()
                    );
                } catch (err) {
                    console.warn(err.toString());
                }
            }
        } catch (err) {
            console.warn(err.toString());
        }
        this.fetchingMail = false;
    }

    /* header is 32 bytes and is either empty
    or contains an HMAC of the message with
    a derived SK */
    private async send(msg: any, header?: Uint8Array) {
        let i = 0;
        while (this.conn.readyState !== 1) {
            await sleep(i);
            i *= 2;
        }

        this.log.debug(
            chalk.red.bold("OUTH ") +
                XUtils.encodeHex(header || XUtils.emptyHeader())
        );
        this.log.debug(chalk.red.bold("OUT ") + JSON.stringify(msg, null, 4));

        this.conn.send(XUtils.packMessage(msg, header));
    }

    private async retrieveKeyBundle(
        deviceID: string
    ): Promise<XTypes.WS.IKeyBundle> {
        const res = await ax.post(
            this.getHost() + "/device/" + deviceID + "/keyBundle"
        );
        return msgpack.decode(Buffer.from(res.data));
    }

    private async getOTKCount(): Promise<number> {
        const res = await ax.get(
            this.getHost() +
                "/device/" +
                this.getDevice().deviceID +
                "/otk/count"
        );
        return msgpack.decode(Buffer.from(res.data)).count;
    }

    private async submitOTK(amount: number) {
        const otks: XTypes.CRYPTO.IPreKeys[] = [];

        const t0 = performance.now();
        for (let i = 0; i < amount; i++) {
            otks[i] = this.createPreKey();
        }
        const t1 = performance.now();

        this.log.info(
            "Generated " + amount + " one time keys in " + (t1 - t0) + " ms."
        );

        const savedKeys = await this.database.savePreKeys(otks, true);

        await ax.post(
            this.getHost() + "/device/" + this.getDevice().deviceID + "/otk",
            msgpack.encode(savedKeys.map((key) => this.censorPreKey(key))),
            {
                headers: { "Content-Type": "application/msgpack" },
            }
        );
    }

    private async negotiateOTK() {
        const otkCount = await this.getOTKCount();
        this.log.info("Server reported OTK: " + otkCount.toString());
        const needs = xConstants.MIN_OTK_SUPPLY - otkCount;
        if (needs === 0) {
            this.log.info("Server otk supply full.");
            return;
        }

        await this.submitOTK(needs);
    }

    private respond(msg: XTypes.WS.IChallMsg) {
        const response: XTypes.WS.IRespMsg = {
            transmissionID: msg.transmissionID,
            type: "response",
            signed: nacl.sign(msg.challenge, this.signKeys.secretKey),
        };
        this.send(response);
    }

    private pong(transmissionID: string) {
        this.send({ transmissionID, type: "pong" });
    }

    private async ping() {
        if (!this.isAlive) {
            this.log.warn("Ping failed.");
        }
        this.setAlive(false);
        this.send({ transmissionID: uuid.v4(), type: "ping" });
    }

    private censorPreKey(preKey: XTypes.SQL.IPreKeys): XTypes.WS.IPreKeys {
        if (!preKey.index) {
            throw new Error("Key index is required.");
        }
        return {
            publicKey: XUtils.decodeHex(preKey.publicKey),
            signature: XUtils.decodeHex(preKey.signature),
            index: preKey.index,
            deviceID: this.getDevice().deviceID,
        };
    }
}
