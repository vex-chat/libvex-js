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
import log from "electron-log";
import { EventEmitter } from "events";
import nacl from "tweetnacl";
import { parse as uuidParse, v4 as uuidv4 } from "uuid";
import WebSocket from "ws";
import { Database } from "./Database";

export interface IMessage {
    nonce: string;
    sender: string;
    recipient: string;
    message: string;
    direction: "incoming" | "outgoing";
    timestamp: Date;
}

export interface IKeys {
    public: string;
    private: string;
}

// tslint:disable-next-line: no-empty-interface
export interface IUser extends XTypes.SQL.IUser {}

// tslint:disable-next-line: no-empty-interface
export interface ISession extends XTypes.SQL.ISession {}

const capitalize = (s: string): string => {
    return s.charAt(0).toUpperCase() + s.slice(1);
};

interface IUsers {
    retrieve: (userID: string) => Promise<IUser | null>;
    me: () => XTypes.SQL.IUser;
}

interface IFamiliars {
    retrieve: () => Promise<IUser[]>;
}

interface IConversations {
    retrieve: () => Promise<Record<string, XTypes.SQL.ISession[]>>;
}

interface IMessages {
    send: (userID: string, message: string) => Promise<void>;
    retrieve: (userID: string) => Promise<IMessage[]>;
}

interface ISessions {
    retrieve: () => Promise<XTypes.SQL.ISession[]>;
    verify: (session: XTypes.SQL.ISession) => string;
    markVerified: (fingerprint: string) => void;
}

export interface IClientOptions {
    logLevel?: "error" | "warn" | "info" | "debug";
    host?: string;
    dbFolder?: string;
}

export class Client extends EventEmitter {
    // Generates an ed25519 private key, formatted as a hex string.
    public static generateSecretKey(): string {
        return XUtils.encodeHex(nacl.sign.keyPair().secretKey);
    }
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

    public users: IUsers = {
        retrieve: this.retrieveUserDBEntry.bind(this),
        me: this.getUser.bind(this),
    };

    public familiars: IFamiliars = {
        retrieve: this.getFamiliars.bind(this),
    };

    public messages: IMessages = {
        send: this.sendMessage.bind(this),
        retrieve: this.getMessageHistory.bind(this),
    };

    public sessions: ISessions = {
        retrieve: this.getSessionList.bind(this),
        verify: Client.getMnemonic,
        markVerified: this.markSessionVerified.bind(this),
    };

    public conversations: IConversations = {
        retrieve: this.getFingerprints.bind(this),
    };

    private database: Database;
    private dbPath: string;
    private conn: WebSocket;
    private host: string;
    private signKeys: nacl.SignKeyPair;
    private xKeyRing?: XTypes.CRYPTO.IXKeyRing;

    private user?: XTypes.SQL.IUser;
    private isAlive: boolean = true;
    private reading: boolean = false;
    private getting: boolean = false;

    private hasInit: boolean = false;
    private hasLoggedIn: boolean = false;

    private pingInterval?: NodeJS.Timeout;
    private mailInterval?: NodeJS.Timeout;

    constructor(privateKey?: string, options?: IClientOptions) {
        super();
        this.setLogLevel(options?.logLevel || "error");

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
    }

    /* initialize the client. run this first and listen for
    the ready event. */
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

    public async close(): Promise<void> {
        log.info("Manually closing client.");

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

    /* sets the log level. */
    public setLogLevel(logLevel: "error" | "warn" | "info" | "debug") {
        log.transports.console.level = logLevel;
    }

    /* gets the public and private keys. */
    public getKeys(): IKeys {
        return {
            public: XUtils.encodeHex(this.signKeys.publicKey),
            private: XUtils.encodeHex(this.signKeys.secretKey),
        };
    }

    /* logs in to the server. you must have already registered. */
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

    /* Registers a new account on the server. */
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

    private async markSessionVerified(fingerprint: string) {
        return this.database.markSessionVerified(fingerprint);
    }

    private async getFingerprints() {
        return this.database.getFingerprints();
    }

    private async getMessageHistory(userID: string): Promise<IMessage[]> {
        const messages: IMessage[] = await this.database.getMessageHistory(
            userID
        );

        return messages;
    }

    /* A thin wrapper around sendMail for string inputs. */
    private async sendMessage(userID: string, message: string) {
        await this.sendMail(userID, XUtils.decodeUTF8(message));
    }

    /* Sends encrypted mail to a user. */
    private async sendMail(userID: string, msg: Uint8Array): Promise<void> {
        log.info("Sending mail to", userID);
        const session = await this.database.getSession(userID);
        if (!session) {
            log.info("Creating new session for", userID);
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

        log.info("Requesting key bundle.");
        try {
            keyBundle = await this.retrieveKeyBundle(userID);
        } catch (err) {
            log.warn("Couldn't get key bundle:", err);
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
        log.info("Obtained SK.");

        const PK = nacl.box.keyPair.fromSecretKey(SK).publicKey;

        const AD = xConcat(
            xEncode(xConstants.CURVE, IK_AP),
            xEncode(xConstants.CURVE, IK_B)
        );

        const nonce = xMakeNonce();
        const cipher = nacl.secretbox(message, nonce, SK);

        log.info("Encrypted ciphertext.");

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
        log.info("Generated hmac:", XUtils.encodeHex(hmac));

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
        };
        this.emit("message", emitMsg);

        // discard the ephemeral keys
        this.newEphemeralKeys();

        // send the message
        this.send(msg, hmac);
        log.info("Mail sent.");

        // save the encryption session
        log.info("Saving new session.");
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

        const user = await this.retrieveUserDBEntry(userID);

        if (user) {
            this.emit("conversation", sessionEntry, user);
        } else {
            throw new Error(
                "We saved a session, but we didn't get it back from the db!"
            );
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
        log.info("Received mail from " + mail.sender);
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
                    log.warn(
                        `Invalid session public key ${XUtils.encodeHex(
                            publicKey
                        )} Decryption failed.`
                    );
                    await this.sendReceipt(mail.nonce, transmissionID);
                    return;
                }
                log.info("Session found for", mail.sender);
                log.info("Mail nonce", XUtils.encodeHex(mail.nonce));

                const HMAC = xHMAC(mail, session.SK);

                if (!XUtils.bytesEqual(HMAC, header)) {
                    log.warn(
                        "Message authentication failed (HMAC does not match."
                    );
                }

                const decrypted = nacl.secretbox.open(
                    mail.cipher,
                    mail.nonce,
                    session.SK
                );

                if (decrypted) {
                    log.info(
                        "Decryption successful:",
                        XUtils.encodeUTF8(decrypted)
                    );

                    // emit the message
                    const message: IMessage = {
                        nonce: XUtils.encodeHex(mail.nonce),
                        sender: mail.sender,
                        recipient: this.getUser().userID,
                        message: XUtils.encodeUTF8(decrypted),
                        direction: "incoming",
                        timestamp: new Date(Date.now()),
                    };
                    this.emit("message", message);

                    await this.database.markSessionUsed(session.sessionID);
                    await this.sendReceipt(mail.nonce, transmissionID);
                } else {
                    log.info("Decryption failed.");
                    await this.sendReceipt(mail.nonce, transmissionID);
                }
                break;
            case XTypes.WS.MailType.initial:
                log.info("Initiating new session.");
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
                log.info("Obtained SK.");

                // shared public key
                const PK = nacl.box.keyPair.fromSecretKey(SK).publicKey;

                const hmac = xHMAC(mail, SK);
                log.info("Calculated hmac:", XUtils.encodeHex(hmac));

                // associated data
                const AD = xConcat(
                    xEncode(xConstants.CURVE, IK_A),
                    xEncode(xConstants.CURVE, IK_BP)
                );

                if (!XUtils.bytesEqual(hmac, header)) {
                    log.warn(
                        "Mail authentication failed (HMAC did not match)."
                    );
                    return;
                }
                log.info("Mail authenticated successfully.");

                const unsealed = nacl.secretbox.open(
                    mail.cipher,
                    mail.nonce,
                    SK
                );
                if (unsealed) {
                    log.info(
                        "Decryption successful:",
                        XUtils.encodeUTF8(unsealed)
                    );

                    // emit the message
                    const message: IMessage = {
                        nonce: XUtils.encodeHex(mail.nonce),
                        sender: mail.sender,
                        recipient: this.getUser().userID,
                        message: XUtils.encodeUTF8(unsealed),
                        direction: "incoming",
                        timestamp: new Date(Date.now()),
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
                            this.emit("conversation", newSession, user);
                        } else {
                            throw new Error(
                                "Saved session but got nothing back from db!"
                            );
                        }
                    }
                    await this.sendReceipt(mail.nonce, transmissionID);
                } else {
                    log.warn("Mail decryption failed.");
                }
                break;
            default:
                log.warn("Unsupported MailType:", mail.mailType);
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
                log.info("Server has informed us of new mail.");
                this.getMail();
                break;
            default:
                log.info("Unsupported notification event", msg.event);
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

        log.info(
            "Keyring populated, public key:",
            XUtils.encodeHex(this.signKeys.publicKey)
        );
    }

    private initSocket() {
        try {
            this.conn = new WebSocket("wss://" + this.host + "/socket");
            this.conn.on("open", () => {
                log.info("Connection opened.");
                this.pingInterval = setInterval(this.ping.bind(this), 5000);
            });

            this.conn.on("close", () => {
                log.info("Connection closed.");
            });

            this.conn.on("error", (error) => {
                throw error;
            });

            this.conn.on("message", async (message: Buffer) => {
                const [header, msg] = XUtils.unpackMessage(message);

                log.debug(chalk.red.bold("INH"), header.toString());
                log.debug(chalk.red.bold("IN"), msg);

                switch (msg.type) {
                    case "ping":
                        this.pong(msg.transmissionID);
                        break;
                    case "pong":
                        this.setAlive(true);
                        break;
                    case "challenge":
                        log.info("Received challenge from server.");
                        this.respond(msg as XTypes.WS.IChallMsg);
                        break;
                    case "authorized":
                        log.info(
                            "Authenticated with userID",
                            this.user!.userID
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
                        log.info("Unsupported message", msg.type);
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
            log.warn("error negotiating OTKs:", err.toString());
        }

        try {
            await this.getMail();
        } catch (err) {
            log.warn("Problem getting mail", err.toString());
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
                            log.warn("error reading mail:", err.toString());
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
        log.debug(
            chalk.red.bold("OUTH"),
            header?.toString() || XUtils.emptyHeader().toString()
        );
        log.debug(chalk.red.bold("OUT"), msg);

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
        log.info("Server reported OTK: ", otkCount);
        const needs = xConstants.MIN_OTK_SUPPLY - otkCount;
        if (needs > 0) {
            log.info("Filling server OTK supply.");
        }

        for (let i = 0; i < needs; i++) {
            await this.submitOTK();
            otkCount++;
        }
        log.info("Server OTK supply is full.");
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
            log.warn("error getting regkey:", err.toString());
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
            log.warn("Connection might be down.");
        }
        this.setAlive(false);
        this.send({ transmissionID: uuidv4(), type: "ping" });
    }
}
