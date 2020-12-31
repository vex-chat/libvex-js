import { sleep } from "@extrahash/sleep";
import { XUtils } from "@vex-chat/crypto";
import { XTypes } from "@vex-chat/types";
import { EventEmitter } from "events";
import { connect, Model, Trilogy } from "trilogy";
import nacl from "tweetnacl";
import { stringify } from "uuid";
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
        this.log = createLogger("db", options);

        this.idKeys = idKeys;
        this.dbPath = dbPath;

        this.log.info("Opening database file at " + this.dbPath);
        this.db = connect(this.dbPath, { client: "sql.js" });
        // this.db = knex({
        //     client: "sqlite3",
        //     connection: {
        //         filename: this.dbPath,
        //     },
        //     useNullAsDefault: true,
        // });

        this.messages = null;
        this.sessions = null;
        this.preKeys = null;
        this.oneTimeKeys = null;

        this.init();
    }

    public async close() {
        this.log.debug("Closing database.");
        await this.db.close();
    }

    public async saveMessage(message: IMessage): Promise<void> {
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
        this.log.debug("deleteMessage(): deleting mailid " + mailID);
        await this.messages?.remove({ mailID });
    }

    public async markSessionVerified(
        sessionID: string,
        status = true
    ): Promise<void> {
        this.log.debug(
            "markSessionVerified(): marking sessionID " +
                sessionID +
                " " +
                status
        );
        await this.sessions?.update({ sessionID }, { verified: true });
    }

    // TODO: Update this to trilogy api instead of using knex
    public async getGroupHistory(channelID: string): Promise<IMessage[]> {
        this.log.debug("getGroupHistory(): retrieving history " + channelID);

        const history = (await this.messages!.find(
            { group: channelID },
            { order: ["timestamp", "desc"], limit: 100 }
        )) as IMessage[];

        if (!history) {
            return [];
        }

        return history.reverse().map((message) => {
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
    }

    public async getMessageHistory(userID: string): Promise<IMessage[]> {
        this.log.debug("getMessageHistory(): retrieving history " + userID);

        const messages = (await this.messages?.find(
            { sender: userID, group: null },
            { limit: 100, order: ["timestamp", "desc"] }
        )) as IMessage[];

        if (!messages) {
            return [];
        }
        return messages.reverse().map((message) => {
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
    }

    public async savePreKeys(
        preKeys: XTypes.CRYPTO.IPreKeys,
        oneTime: boolean
    ): Promise<number> {
        await this.untilReady();
        this.log.debug("savePreKeys(): called");

        const model = oneTime ? this.oneTimeKeys : this.preKeys;

        const preKey = (await model?.create({
            privateKey: XUtils.encodeHex(preKeys.keyPair.secretKey),
            publicKey: XUtils.encodeHex(preKeys.keyPair.publicKey),
            signature: XUtils.encodeHex(preKeys.signature),
        })) as XTypes.WS.IPreKeys;

        return preKey.index;
    }

    public async getSessionByPublicKey(publicKey: Uint8Array) {
        this.log.debug("getSessionByPublicKey(): called");

        const str = XUtils.encodeHex(publicKey);

        const rows = (await this.sessions?.find(
            { publicKey: str },
            { limit: 1 }
        )) as ISession[];

        if (!rows || rows.length === 0) {
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

        return wsSession;
    }

    public async markSessionUsed(sessionID: string) {
        this.log.debug("markSessionUsed(): called " + sessionID);

        await this.sessions?.update(
            { lastUsed: new Date(Date.now()) },
            { sessionID }
        );
    }

    public async getSessions(): Promise<XTypes.SQL.ISession[]> {
        this.log.debug("getSessions(): called");

        const rows = (await this.sessions?.find(undefined, {
            order: ["lastUsed", "desc"],
        })) as XTypes.SQL.ISession[];

        if (!rows || rows.length === 0) {
            return [];
        }

        const fixedRows = rows.map((session) => {
            session.verified = Boolean(session.verified);
            return session;
        });

        return fixedRows;
    }

    public async getSession(
        userID: string
    ): Promise<XTypes.CRYPTO.ISession | null> {
        this.log.debug("getSession(): called " + userID);

        const rows = (await this.sessions?.find(
            { userID },
            { order: ["lastUsed", "desc"] }
        )) as ISession[];

        if (!rows || rows.length === 0) {
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

        return wsSession;
    }

    public async getPreKeys(): Promise<XTypes.CRYPTO.IPreKeys | null> {
        await this.untilReady();
        this.log.debug("getPreKeys(): called");

        const rows = (await this.preKeys?.find()) as XTypes.SQL.IPreKeys[];

        if (!rows || rows.length === 0) {
            return null;
        }

        const [preKeyInfo] = rows;
        const preKeys: XTypes.CRYPTO.IPreKeys = {
            keyPair: nacl.box.keyPair.fromSecretKey(
                XUtils.decodeHex(preKeyInfo.privateKey!)
            ),
            signature: XUtils.decodeHex(preKeyInfo.signature),
        };
        return preKeys;
    }

    public async getOneTimeKey(
        index: number
    ): Promise<XTypes.CRYPTO.IPreKeys | null> {
        await this.untilReady();
        this.log.debug("getOneTimeKey(): called");

        const rows = (await this.oneTimeKeys?.find({
            index,
        })) as XTypes.SQL.IPreKeys[];

        if (!rows || rows.length === 0) {
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
        return otk;
    }

    public async deleteOneTimeKey(index: number) {
        // delete the otk
        this.log.debug("deleteOneTimeKey(): called");
        await this.oneTimeKeys?.remove({ index });
    }

    public async saveSession(session: XTypes.SQL.ISession) {
        this.log.debug("saveSession(): called");
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
        this.log.debug("init(): called");
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
