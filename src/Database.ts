import { sleep } from "@extrahash/sleep";
import { XUtils } from "@vex-chat/crypto";
import { XTypes } from "@vex-chat/types";
import { EventEmitter } from "events";
import { connect, Model, Trilogy } from "trilogy";
import nacl from "tweetnacl";
import winston from "winston";
import { IClientOptions, IMessage, ISession } from ".";
import { createLogger } from "./utils/createLogger";

// tslint:disable-next-line: class-name
export class Database extends EventEmitter {
    public ready: boolean = false;
    private dbPath: string;
    private db: Trilogy;
    private log: winston.Logger;
    private idKeys: nacl.BoxKeyPair;
    private closing: boolean = false;

    private messages: Model<Record<string, ReturnType<any>>> | null;
    private sessions: Model<Record<string, ReturnType<any>>> | null;
    private preKeys: Model<Record<string, ReturnType<any>>> | null;
    private oneTimeKeys: Model<Record<string, ReturnType<any>>> | null;

    constructor(
        dbPath: string,
        idKeys: nacl.BoxKeyPair,
        options?: IClientOptions
    ) {
        super();
        this.log = createLogger("db", options?.dbLogLevel || options?.logLevel);

        this.idKeys = idKeys;
        this.dbPath = dbPath;

        this.log.info("Opening database file at " + this.dbPath);
        this.db = connect(this.dbPath, { client: "sql.js" });

        this.messages = null;
        this.sessions = null;
        this.preKeys = null;
        this.oneTimeKeys = null;

        this.init();
    }

    public async close() {
        this.closing = true;
        this.log.debug("Closing database.");

        // give it a second to finish any pending writes
        // hack, TODO: fix
        return new Promise(async (res, rej) => {
            await sleep(1000);
            await this.db.close();
            res({ closed: true });
        });
    }

    public async saveMessage(message: IMessage): Promise<void> {
        if (this.closing) {
            this.log.warn("Database closing, saveMessage() will not complete.");
            return;
        }

        const copy = { ...message };

        // encrypt plaintext with our idkey before it gets saved to disk
        copy.message = XUtils.encodeHex(
            nacl.secretbox(
                XUtils.decodeUTF8(message.message),
                XUtils.decodeHex(message.nonce),
                this.idKeys.secretKey
            )
        );

        await this.messages?.create(copy);
    }

    public async deleteMessage(mailID: string): Promise<void> {
        if (this.closing) {
            this.log.warn(
                "Database closing, deleteMessage() will not complete."
            );
            return;
        }
        await this.messages?.remove({ mailID });
    }

    public async markSessionVerified(
        sessionID: string,
        status = true
    ): Promise<void> {
        if (this.closing) {
            this.log.warn(
                "Database closing, markSessionVerified() will not complete."
            );
        }
        await this.sessions?.update({ sessionID }, { verified: true });
    }

    // TODO: Update this to trilogy api instead of using knex
    public async getGroupHistory(channelID: string): Promise<IMessage[]> {
        if (this.closing) {
            this.log.warn(
                "Database closing, getGroupHistory() will not complete."
            );
            this.log.debug(
                "getGroupHistory() => " + JSON.stringify([], null, 4)
            );
            return [];
        }
        const history = (await this.messages!.find(
            { group: channelID },
            { order: ["timestamp", "desc"], limit: 100 }
        )) as IMessage[];

        if (!history) {
            this.log.debug(
                "getGroupHistory() => " + JSON.stringify([], null, 4)
            );
            return [];
        }

        const fixedHistory = history.reverse().map((message) => {
            // some cleanup because of how knex serializes the data
            message.timestamp = new Date(message.timestamp);
            // decrypt
            message.decrypted = Boolean(message.decrypted);

            const decrypted = nacl.secretbox.open(
                XUtils.decodeHex(message.message),
                XUtils.decodeHex(message.nonce),
                this.idKeys!.secretKey
            );

            if (decrypted) {
                message.message = XUtils.encodeUTF8(decrypted);
            } else {
                throw new Error("Couldn't decrypt messages on disk!");
            }

            return message;
        });

        this.log.debug(
            "getGroupHistory() => " + JSON.stringify(fixedHistory, null, 4)
        );
        return fixedHistory;
    }

    public async getMessageHistory(userID: string): Promise<IMessage[]> {
        if (this.closing) {
            this.log.warn(
                "Database closing, getMessageHistory() will not complete"
            );
            this.log.debug(
                "getMessageHistory() => " + JSON.stringify([], null, 4)
            );
            return [];
        }
        const messages = (await this.messages?.find(
            { sender: userID, group: null },
            { limit: 100, order: ["timestamp", "desc"] }
        )) as IMessage[];

        if (!messages) {
            this.log.debug(
                "getMessageHistory() => " + JSON.stringify([], null, 4)
            );
            return [];
        }
        const fixedHistory = messages.reverse().map((message) => {
            // some cleanup because of how knex serializes the data
            message.timestamp = new Date(message.timestamp);
            // decrypt
            message.decrypted = Boolean(message.decrypted);

            const decrypted = nacl.secretbox.open(
                XUtils.decodeHex(message.message),
                XUtils.decodeHex(message.nonce),
                this.idKeys!.secretKey
            );

            if (decrypted) {
                message.message = XUtils.encodeUTF8(decrypted);
            } else {
                throw new Error("Couldn't decrypt messages on disk!");
            }

            return message;
        });
        this.log.debug(
            "getMessageHistory() => " + JSON.stringify(fixedHistory, null, 4)
        );
        return fixedHistory;
    }

    public async savePreKeys(
        preKeys: XTypes.CRYPTO.IPreKeys,
        oneTime: boolean
    ): Promise<number> {
        await this.untilReady();
        if (this.closing) {
            this.log.warn("Database closing, savePreKeys() will not complete.");
            this.log.debug("savePreKeys() => -1");
            return -1;
        }

        const model = oneTime ? this.oneTimeKeys : this.preKeys;

        const preKey = (await model?.create({
            privateKey: XUtils.encodeHex(preKeys.keyPair.secretKey),
            publicKey: XUtils.encodeHex(preKeys.keyPair.publicKey),
            signature: XUtils.encodeHex(preKeys.signature),
        })) as XTypes.WS.IPreKeys;

        this.log.debug("savePreKeys() => " + preKey.index.toString());

        return preKey.index;
    }

    public async getSessionByPublicKey(
        publicKey: Uint8Array
    ): Promise<XTypes.CRYPTO.ISession | null> {
        if (this.closing) {
            this.log.warn(
                "Database closing, getSessionByPublicKey() will not complete."
            );
            this.log.debug(
                "getSessionByPublicKey() => " + JSON.stringify(null, null, 4)
            );
            return null;
        }

        const str = XUtils.encodeHex(publicKey);

        const rows = (await this.sessions?.find(
            { publicKey: str },
            { limit: 1 }
        )) as ISession[];

        if (!rows || rows.length === 0) {
            this.log.debug(
                "getSessionByPublicKey() => " + JSON.stringify(null, null, 4)
            );
            return null;
        }

        const [session] = rows;

        const wsSession: XTypes.CRYPTO.ISession = {
            sessionID: session.sessionID,
            userID: session.userID,
            mode: session.mode,
            SK: XUtils.decodeHex(session.SK),
            publicKey: XUtils.decodeHex(session.publicKey),
            lastUsed: session.lastUsed,
            fingerprint: XUtils.decodeHex(session.fingerprint),
        };

        this.log.debug(
            "getSessionByPublicKey() => " + JSON.stringify(wsSession, null, 4)
        );
        return wsSession;
    }

    public async markSessionUsed(sessionID: string) {
        if (this.closing) {
            this.log.warn(
                "Database closing, markSessionUsed() will not complete."
            );
            return null;
        }

        await this.sessions?.update(
            { lastUsed: new Date(Date.now()) },
            { sessionID }
        );
    }

    public async getSessions(): Promise<XTypes.SQL.ISession[]> {
        if (this.closing) {
            this.log.warn("Database closing, getSessions() will not complete.");
            this.log.debug("getSessions() => " + JSON.stringify([], null, 4));
            return [];
        }

        const rows = (await this.sessions?.find(undefined, {
            order: ["lastUsed", "desc"],
        })) as XTypes.SQL.ISession[];

        if (!rows || rows.length === 0) {
            this.log.debug("getSessions() => " + JSON.stringify([], null, 4));
            return [];
        }

        const fixedRows = rows.map((session) => {
            session.verified = Boolean(session.verified);
            return session;
        });

        this.log.debug(
            "getSessions() => " + JSON.stringify(fixedRows, null, 4)
        );
        return fixedRows;
    }

    public async getSession(
        userID: string
    ): Promise<XTypes.CRYPTO.ISession | null> {
        if (this.closing) {
            this.log.warn("Database closing, getSession() will not complete.");
            this.log.debug("getSession() => " + JSON.stringify(null, null, 4));
            return null;
        }

        const rows = (await this.sessions?.find(
            { userID },
            { order: ["lastUsed", "desc"] }
        )) as ISession[];

        if (!rows || rows.length === 0) {
            this.log.debug("getSession() => " + JSON.stringify(null, null, 4));
            return null;
        }

        const [session] = rows;

        const wsSession: XTypes.CRYPTO.ISession = {
            sessionID: session.sessionID,
            userID: session.userID,
            mode: session.mode,
            SK: XUtils.decodeHex(session.SK),
            publicKey: XUtils.decodeHex(session.publicKey),
            lastUsed: session.lastUsed,
            fingerprint: XUtils.decodeHex(session.fingerprint),
        };

        this.log.debug("getSession() => " + JSON.stringify(wsSession, null, 4));
        return wsSession;
    }

    public async getPreKeys(): Promise<XTypes.CRYPTO.IPreKeys | null> {
        await this.untilReady();
        if (this.closing) {
            this.log.warn("Database closing, getPreKeys() will not complete.");
            this.log.debug("getPreKeys() => " + JSON.stringify(null, null, 4));
            return null;
        }

        const rows = (await this.preKeys?.find()) as XTypes.SQL.IPreKeys[];

        if (!rows || rows.length === 0) {
            this.log.debug("getPreKeys() => " + JSON.stringify(null, null, 4));
            return null;
        }

        const [preKeyInfo] = rows;
        const preKeys: XTypes.CRYPTO.IPreKeys = {
            keyPair: nacl.box.keyPair.fromSecretKey(
                XUtils.decodeHex(preKeyInfo.privateKey!)
            ),
            signature: XUtils.decodeHex(preKeyInfo.signature),
        };
        this.log.debug("getPreKeys() => " + JSON.stringify(preKeys, null, 4));
        return preKeys;
    }

    public async getOneTimeKey(
        index: number
    ): Promise<XTypes.CRYPTO.IPreKeys | null> {
        await this.untilReady();
        if (this.closing) {
            this.log.debug(
                "getOneTimeKey() => " + JSON.stringify(null, null, 4)
            );
            return null;
        }

        const rows = (await this.oneTimeKeys?.find({
            index,
        })) as XTypes.SQL.IPreKeys[];

        if (!rows || rows.length === 0) {
            this.log.debug(
                "getOneTimeKey() => " + JSON.stringify(null, null, 4)
            );
            return null;
        }

        const [otkInfo] = rows;
        const otk: XTypes.CRYPTO.IPreKeys = {
            keyPair: nacl.box.keyPair.fromSecretKey(
                XUtils.decodeHex(otkInfo.privateKey!)
            ),
            signature: XUtils.decodeHex(otkInfo.signature),
            index: otkInfo.index,
        };
        this.log.debug("getOneTimeKey() => " + JSON.stringify(otk, null, 4));
        return otk;
    }

    public async deleteOneTimeKey(index: number) {
        // delete the otk
        if (this.closing) {
            this.log.warn(
                "Database closing, deleteOneTimeKey() will not complete."
            );
            return;
        }

        await this.oneTimeKeys?.remove({ index });
    }

    public async saveSession(session: XTypes.SQL.ISession) {
        if (this.closing) {
            this.log.warn("Database closing, saveSession() will not complete.");
            return null;
        }
        await this.sessions?.create(session);
    }

    private async untilReady() {
        let timeout = 1;
        while (!this.ready) {
            await sleep(timeout);
            timeout *= 2;
        }
    }

    private async init() {
        this.log.debug("Initializing database tables.");

        try {
            this.messages = await this.db.model("messages", {
                nonce: { type: String, primary: true },
                sender: { type: String, index: "sender" },
                recipient: { type: String, index: "recipient" },
                group: { type: String, index: "group" },
                mailID: String,
                message: String,
                direction: String,
                timestamp: Date,
                decrypted: Boolean,
            });

            this.sessions = await this.db.model("sessions", {
                sessionID: { type: String, primary: true },
                userID: String,
                SK: { type: String, unique: true },
                publicKey: String,
                fingerprint: String,
                mode: String,
                lastUsed: Date,
                verified: Boolean,
            });

            this.preKeys = await this.db.model("preKeys", {
                index: "increments",
                keyID: { type: String, unique: true },
                userID: String,
                privateKey: String,
                publicKey: String,
                signature: String,
            });

            this.oneTimeKeys = await this.db.model("oneTimeKeys", {
                index: "increments",
                keyID: { type: String, unique: true },
                userID: String,
                privateKey: String,
                publicKey: String,
                signature: String,
            });

            this.ready = true;
            this.emit("ready");
        } catch (err) {
            this.log.error(err);
            this.emit("error", err);
        }
    }
}
