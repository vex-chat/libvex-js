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
} from "@vex-chat/crypto-js";
import { XTypes } from "@vex-chat/types-js";
import ax from "axios";
import chalk from "chalk";
import { EventEmitter } from "events";
import nacl from "tweetnacl";
import { parse as uuidParse, v4 as uuidv4 } from "uuid";
import winston from "winston";
import WebSocket from "ws";
import { Database } from "./Database";
import { capitalize } from "./utils/capitalize";

/**
 * IMessage is a chat message.
 */
export interface IMessage {
    nonce: string;
    sender: string;
    recipient: string;
    message: string;
    direction: "incoming" | "outgoing";
    timestamp: Date;
    decrypted: boolean;
}

/**
 * IKeys are a pair of ed25519 public and private keys,
 * encoded as hex strings.
 */
export interface IKeys {
    public: string;
    private: string;
}

/**
 * IKeys are a pair of ed25519 public and private keys,
 * encoded as hex strings.
 */
export interface IUser extends XTypes.SQL.IUser {}

/**
 * ISession is an end to end encryption session with another peer.
 */
export interface ISession extends XTypes.SQL.ISession {}

/**
 * @ignore
 */
interface IUsers {
    retrieve: (userID: string) => Promise<IUser | null>;
    me: () => XTypes.SQL.IUser;
    familiars: () => Promise<IUser[]>;
}

/**
 * @ignore
 */
interface IMessages {
    send: (userID: string, message: string) => Promise<void>;
    retrieve: (userID: string) => Promise<IMessage[]>;
}

/**
 * @ignore
 */
interface ISessions {
    retrieve: () => Promise<XTypes.SQL.ISession[]>;
    verify: (session: XTypes.SQL.ISession) => string;
    markVerified: (fingerprint: string) => void;
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
     * This is emitted for a new encryption session being created with
     * a specific user.
     *
     * Example:
     *
     * ```ts
     *
     *   client.on("message", (msg: IMessage, user: IUser) => {
     *       console.log(message);
     *       console.log(user);
     *   });
     * ```
     * @event
     */
    on(
        event: "session",
        callback: (message: IMessage, user: IUser) => void
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
 * Quickstart:
 * ```ts
 *    export function initClient(): void {
 *        const PK = Client.generateSecretKey();
 *        const client = new Client(PK, {
 *            dbFolder: progFolder,
 *            logLevel: "info",
 *        });
 *        client.on("ready", async () => {
 *            // you can retrieve users before you login
 *            const registeredUser = await client.users.retrieve(
 *                client.getKeys().public
 *            );
 *            if (registeredUser) {
 *                await client.login();
 *            } else {
 *                await client.register("MyUsername");
 *                await client.login();
 *            }
 *        });
 *        client.on("authed", async () => {
 *            const familiars = await client.users.familiars();
 *            for (const user of familiars) {
 *                client.messages.send(user.userID, "Hello world!");
 *            }
 *        });
 *        client.init();
 *    }
 *
 *    initClient();
 * ```
 *
 *
 * @noInheritDoc
 */
export class Client extends EventEmitter {
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
    public messages: IMessages = {
        /**
         * Send a chat message.
         * @param userID: The userID of the user to send a message to.
         * @param message: The message to send.
         */
        send: this.sendMessage.bind(this),
        /**
         * Gets the message history with a specific userID.
         * @param userID: The userID of the user to retrieve message history for.
         *
         * @returns - The list of IMessage objects.
         */
        retrieve: this.getMessageHistory.bind(this),
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

    /**
     * This is true if the client has ever been initialized. You can only initialize
     * a client once.
     */
    public hasInit: boolean = false;
    /**
     * This is true if the client has ever logged in before. You can only login a client once.
     */
    public hasLoggedIn: boolean = false;

    private database: Database;
    private dbPath: string;
    private conn: WebSocket;
    private host: string;
    private signKeys: nacl.SignKeyPair;
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

        this.log = winston.createLogger({
            level: options?.logLevel || "error",
            format: winston.format.combine(
                winston.format.timestamp({
                    format: "YYYY-MM-DD HH:mm:ss",
                }),
                winston.format.errors({ stack: true }),
                winston.format.splat(),
                winston.format.json()
            ),
            defaultMeta: { service: "vex-js" },
            transports: [
                //
                // - Write all logs with level `error` and below to `error.log`
                // - Write all logs with level `info` and below to `combined.log`
                //
                new winston.transports.File({
                    filename: "error.log",
                    level: "error",
                }),
                new winston.transports.File({ filename: "combined.log" }),
            ],
        });

        this.signKeys = privateKey
            ? nacl.sign.keyPair.fromSecretKey(XUtils.decodeHex(privateKey))
            : nacl.sign.keyPair();

        this.host = options?.host || "api.vex.chat";

        const dbFileName =
            XUtils.encodeHex(this.signKeys.publicKey) + ".sqlite";
        this.dbPath = options?.dbFolder
            ? options?.dbFolder + "/" + dbFileName
            : dbFileName;

        this.database = new Database(this.dbPath);

        // we want to initialize this later with login()
        this.conn = new WebSocket("ws://localhost:1234");
        // silence the error for connecting to junk ws
        // tslint:disable-next-line: no-empty
        this.conn.onerror = () => {};

        //
        // If we're not in production then log to the `console` with the format:
        // `${info.level}: ${info.message} JSON.stringify({ ...rest }) `
        //
        if (process.env.NODE_ENV !== "production") {
            this.log.add(
                new winston.transports.Console({
                    format: winston.format.combine(
                        winston.format.colorize(),
                        winston.format.simple()
                    ),
                })
            );
        }
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
    public async close(): Promise<void> {
        this.manuallyClosing = true;
        this.log.info("Manually closing client.");

        if (this.pingInterval) {
            clearInterval(this.pingInterval);
        }

        if (this.mailInterval) {
            clearInterval(this.mailInterval);
        }
        this.conn.close();
        await this.database.close();
        delete this.xKeyRing;

        this.emit("closed");
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
                    Uint8Array.from(uuidParse(regKey.key)),
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

    private async markSessionVerified(sessionID: string, status = true) {
        return this.database.markSessionVerified(sessionID, status);
    }

    private async getMessageHistory(userID: string): Promise<IMessage[]> {
        const messages: IMessage[] = await this.database.getMessageHistory(
            userID
        );

        return messages.map((row) => {
            row.decrypted = Boolean(row.decrypted);
            return row;
        });
    }

    /* A thin wrapper around sendMail for string inputs. */
    private async sendMessage(userID: string, message: string) {
        await this.sendMail(userID, XUtils.decodeUTF8(message));
    }

    /* Sends encrypted mail to a user. */
    private async sendMail(userID: string, msg: Uint8Array): Promise<void> {
        this.log.info("Sending mail to " + userID);
        const session = await this.database.getSession(userID);
        if (!session) {
            this.log.info("Creating new session for " + userID);
            await this.createSession(userID, msg);
        } else {
            const nonce = xMakeNonce();
            const cipher = nacl.secretbox(msg, nonce, session.SK);
            const extra = session.publicKey;

            const mail: XTypes.WS.IMail = {
                mailType: XTypes.WS.MailType.subsequent,
                recipient: userID,
                cipher,
                nonce,
                extra,
                sender: this.user!.userID,
            };

            const msgb: XTypes.WS.IResourceMsg = {
                transmissionID: uuidv4(),
                type: "resource",
                resourceType: "mail",
                action: "CREATE",
                data: mail,
            };

            const hmac = xHMAC(mail, session.SK);

            this.send(msgb, hmac);

            const message: IMessage = {
                sender: mail.sender,
                recipient: mail.recipient,
                nonce: XUtils.encodeHex(mail.nonce),
                message: XUtils.encodeUTF8(msg),
                direction: "outgoing",
                timestamp: new Date(Date.now()),
                decrypted: true,
            };
            this.emit("message", message);
        }
    }

    private async getSessionList() {
        return this.database.getSessions();
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
    ): Promise<XTypes.SQL.IUser | null> {
        try {
            const res = await ax.get(
                "https://" + this.host + "/user/" + userIdentifier
            );
            return res.data;
        } catch (err) {
            console.error("Error retrieving user from server:", err.toString());
            return null;
        }
    }

    /* Retrieves the current list of users you have access to. */
    private getFamiliars(): Promise<XTypes.SQL.IUser[]> {
        return new Promise((res, rej) => {
            const transmissionID = uuidv4();
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

    private async createSession(userID: string, message: Uint8Array) {
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
            recipient: userID,
            cipher,
            nonce,
            extra,
            sender: this.user!.userID,
        };

        const hmac = xHMAC(mail, SK);
        this.log.info("Generated hmac: " + XUtils.encodeHex(hmac));

        const msg: XTypes.WS.IResourceMsg = {
            transmissionID: uuidv4(),
            type: "resource",
            resourceType: "mail",
            action: "CREATE",
            data: mail,
        };

        // emit the message
        const emitMsg: IMessage = {
            nonce: XUtils.encodeHex(mail.nonce),
            sender: mail.sender,
            recipient: mail.recipient,
            message: XUtils.encodeUTF8(message),
            direction: "outgoing",
            timestamp: new Date(Date.now()),
            decrypted: true,
        };
        this.emit("message", emitMsg);

        // discard the ephemeral keys
        this.newEphemeralKeys();

        // send the message
        this.send(msg, hmac);
        this.log.info("Mail sent.");

        // save the encryption session
        this.log.info("Saving new session.");
        const sessionEntry: XTypes.SQL.ISession = {
            verified: false,
            sessionID: uuidv4(),
            userID,
            mode: "initiator",
            SK: XUtils.encodeHex(SK),
            publicKey: XUtils.encodeHex(PK),
            lastUsed: new Date(Date.now()),
            fingerprint: XUtils.encodeHex(AD),
        };

        await this.database.saveSession(sessionEntry);

        let user = await this.retrieveUserDBEntry(userID);

        if (user) {
            this.emit("session", sessionEntry, user);
        } else {
            let failed = 1;
            // retry a couple times
            while (!user) {
                user = await this.retrieveUserDBEntry(userID);
                failed++;
                if (failed > 3) {
                    throw new Error(
                        "We saved a session, but we didn't get it back from the db!"
                    );
                }
            }
        }
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
                        sender: mail.sender,
                        recipient: mail.recipient,
                        message: "",
                        direction: "incoming",
                        timestamp: new Date(Date.now()),
                        decrypted: false,
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
                        sender: mail.sender,
                        recipient: mail.recipient,
                        message: XUtils.encodeUTF8(decrypted),
                        direction: "incoming",
                        timestamp: new Date(Date.now()),
                        decrypted: true,
                    };
                    this.emit("message", message);

                    await this.database.markSessionUsed(session.sessionID);
                    await this.sendReceipt(mail.nonce, transmissionID);
                } else {
                    this.log.info("Decryption failed.");

                    // emit the message
                    const message: IMessage = {
                        nonce: XUtils.encodeHex(mail.nonce),
                        sender: mail.sender,
                        recipient: mail.recipient,
                        message: "",
                        direction: "incoming",
                        timestamp: new Date(Date.now()),
                        decrypted: false,
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
                        sender: mail.sender,
                        recipient: mail.recipient,
                        message: XUtils.encodeUTF8(unsealed),
                        direction: "incoming",
                        timestamp: new Date(Date.now()),
                        decrypted: true,
                    };
                    this.emit("message", message);

                    // discard onetimekey
                    await this.database.deleteOneTimeKey(preKeyIndex);

                    // save session
                    const newSession: XTypes.SQL.ISession = {
                        verified: false,
                        sessionID: uuidv4(),
                        userID: mail.sender,
                        mode: "receiver",
                        SK: XUtils.encodeHex(SK),
                        publicKey: XUtils.encodeHex(PK),
                        lastUsed: new Date(Date.now()),
                        fingerprint: XUtils.encodeHex(AD),
                    };
                    // for testing so i can create messages with myself
                    if (newSession.userID !== this.user!.userID) {
                        await this.database.saveSession(newSession);

                        const user = await this.retrieveUserDBEntry(
                            newSession.userID
                        );

                        if (user) {
                            this.emit("session", newSession, user);
                        } else {
                            throw new Error(
                                "Saved session but got nothing back from db!"
                            );
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
            default:
                this.log.info("Unsupported notification event " + msg.event);
                break;
        }
    }

    private async populateKeyRing() {
        let identityKeys = await this.database.getIdentityKeys();

        const providedKeys = XKeyConvert.convertKeyPair(this.signKeys);
        if (!providedKeys) {
            throw new Error("Could not convert ed25519 key to X25519!");
        }

        if (!identityKeys) {
            await this.database.saveIdentityKeys(providedKeys!);
            identityKeys = providedKeys;
        } else {
            if (
                !XUtils.bytesEqual(
                    identityKeys.secretKey,
                    providedKeys.secretKey
                )
            ) {
                throw new Error(
                    "Private key changed. Please delete or move the database file."
                );
            }
        }

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
            const transmissionID = uuidv4();
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
            const transmissionID = uuidv4();
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
            const transmissionID = uuidv4();
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
            const transmissionID = uuidv4();
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

    private ping() {
        if (!this.isAlive) {
            this.log.warn("Ping failed.");
            this.failCount++;
            if (this.failCount === 2) {
                this.conn.close();
            }
        }
        this.setAlive(false);
        this.send({ transmissionID: uuidv4(), type: "ping" });
    }
}
