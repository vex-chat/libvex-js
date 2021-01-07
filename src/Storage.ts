import { sleep } from "@extrahash/sleep";
import { XKeyConvert, XUtils } from "@vex-chat/crypto";
import { XTypes } from "@vex-chat/types";
import { EventEmitter } from "events";
import knex from "knex";
import nacl from "tweetnacl";
import winston from "winston";
import { IClientOptions, IMessage } from ".";
import { IStorage } from "./IStorage";
import { createLogger } from "./utils/createLogger";

/**
 * The default IStorage() implementation, using knex and sqlite3 driver
 *
 * @hidden
 */
export class Storage extends EventEmitter implements IStorage {
    public ready: boolean = false;
    private closing: boolean = false;
    private dbPath: string;
    private db: knex<any, unknown[]>;
    private log: winston.Logger;
    private idKeys: nacl.BoxKeyPair;

    constructor(dbPath: string, SK: string, options?: IClientOptions) {
        super();
        this.log = createLogger("db", options?.dbLogLevel || options?.logLevel);

        const idKeys = XKeyConvert.convertKeyPair(
            nacl.sign.keyPair.fromSecretKey(XUtils.decodeHex(SK))
        );
        if (!idKeys) {
            throw new Error("Can't convert SK!");
        }

        this.idKeys = idKeys;
        this.dbPath = dbPath;

        this.log.info("Opening database file at " + this.dbPath);
        this.db = knex({
            client: "sqlite3",
            connection: {
                filename: this.dbPath,
            },
            useNullAsDefault: true,
        });

        this.init();
    }

    public async close(): Promise<void> {
        this.closing = true;
        this.log.info("Closing database.");
        await this.db.destroy();
    }

    public async saveMessage(message: IMessage): Promise<void> {
        if (this.closing) {
            this.log.warn(
                "Database is closing, saveMessage() will not complete."
            );
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

        try {
            await this.db("messages").insert(copy);
        } catch (err) {
            if (err.errno !== 19) {
                throw err;
            }
            this.log.warn(
                "Attempted to insert duplicate nonce into message table."
            );
        }
    }

    public async deleteMessage(mailID: string) {
        if (this.closing) {
            this.log.warn(
                "Database is closing, saveMessage() will not complete."
            );
            return;
        }
        await this.db
            .from("messages")
            .where({ mailID })
            .del();
    }

    public async markSessionVerified(sessionID: string, status = true) {
        if (this.closing) {
            this.log.warn(
                "Database is closing, markSessionVerified() will not complete."
            );
            return;
        }
        await this.db("sessions")
            .where({ sessionID })
            .update({ verified: status });
    }

    public async getMessageHistory(userID: string): Promise<IMessage[]> {
        if (this.closing) {
            this.log.warn(
                "Database is closing, getMessageHistory() will not complete."
            );
            return [];
        }
        const messages = await this.db("messages")
            .select()
            .where({ direction: "incoming", sender: userID, group: null })
            .orWhere({ direction: "outgoing", recipient: userID, group: null })
            .orderBy("timestamp", "desc");

        const fixedMessages = messages.reverse().map((message: IMessage) => {
            // some cleanup because of how knex serializes the data
            message.timestamp = new Date(message.timestamp);
            // decrypt
            message.decrypted = Boolean(message.decrypted);

            if (message.decrypted) {
                const localDecrypt = nacl.secretbox.open(
                    XUtils.decodeHex(message.message),
                    XUtils.decodeHex(message.nonce),
                    this.idKeys!.secretKey
                );
                if (localDecrypt) {
                    message.message = XUtils.encodeUTF8(localDecrypt);
                } else {
                    throw new Error("Couldn't decrypt messages on disk!");
                }
            }
            return message;
        });
        this.log.debug(
            "getMessageHistory() => " + JSON.stringify(fixedMessages, null, 4)
        );
        return fixedMessages;
    }

    public async getGroupHistory(channelID: string): Promise<IMessage[]> {
        if (this.closing) {
            this.log.warn(
                "Database is closing, getGroupHistory() will not complete."
            );
            return [];
        }
        const messages: IMessage[] = await this.db("messages")
            .select()
            .where({ group: channelID })
            .orderBy("timestamp", "desc");

        const fixedMessages = messages.reverse().map((message) => {
            // some cleanup because of how knex serializes the data
            message.timestamp = new Date(message.timestamp);
            // decrypt
            message.decrypted = Boolean(message.decrypted);

            if (message.decrypted) {
                const localDecrypt = nacl.secretbox.open(
                    XUtils.decodeHex(message.message),
                    XUtils.decodeHex(message.nonce),
                    this.idKeys!.secretKey
                );
                if (localDecrypt) {
                    message.message = XUtils.encodeUTF8(localDecrypt);
                } else {
                    throw new Error("Couldn't decrypt messages on disk!");
                }
            }
            return message;
        });
        this.log.debug(
            "getGroupHistory() => " + JSON.stringify(fixedMessages, null, 4)
        );
        return fixedMessages;
    }

    public async savePreKeys(
        preKeys: XTypes.CRYPTO.IPreKeys,
        oneTime: boolean
    ): Promise<number> {
        await this.untilReady();
        if (this.closing) {
            this.log.warn(
                "Database is closing, getGroupHistory() will not complete."
            );
            return -1;
        }
        const index = await this.db(oneTime ? "oneTimeKeys" : "preKeys").insert(
            {
                privateKey: XUtils.encodeHex(preKeys.keyPair.secretKey),
                publicKey: XUtils.encodeHex(preKeys.keyPair.publicKey),
                signature: XUtils.encodeHex(preKeys.signature),
            }
        );
        this.log.silly("savePreKeys() => " + JSON.stringify(index[0], null, 4));

        return index[0];
    }

    public async getSessionByPublicKey(
        publicKey: Uint8Array
    ): Promise<XTypes.CRYPTO.ISession | null> {
        if (this.closing) {
            this.log.warn(
                "Database is closing, getGroupHistory() will not complete."
            );
            return null;
        }
        const str = XUtils.encodeHex(publicKey);

        const rows: XTypes.SQL.ISession[] = await this.db
            .from("sessions")
            .select()
            .where({ publicKey: str })
            .limit(1);
        if (rows.length === 0) {
            this.log.warn(
                `getSessionByPublicKey(${XUtils.encodeHex(publicKey)}) => ` +
                    JSON.stringify(null, null, 4)
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

    public async markSessionUsed(sessionID: string): Promise<void> {
        if (this.closing) {
            this.log.warn(
                "Database is closing, markSessionUsed() will not complete."
            );
            return;
        }
        await this.db
            .from("sessions")
            .update({ lastUsed: new Date(Date.now()) })
            .where({ sessionID });
    }

    public async getAllSessions(): Promise<XTypes.SQL.ISession[]> {
        if (this.closing) {
            this.log.warn(
                "Database is closing, getAllSessions() will not complete."
            );
            return [];
        }
        const rows: XTypes.SQL.ISession[] = await this.db
            .from("sessions")
            .select()
            .orderBy("lastUsed", "desc");

        const fixedRows = rows.map((session) => {
            session.verified = Boolean(session.verified);
            return session;
        });
        this.log.debug(
            "getAllSessions() => " + JSON.stringify(fixedRows, null, 4)
        );
        return fixedRows;
    }

    public async getSessionByDeviceID(
        deviceID: string
    ): Promise<XTypes.CRYPTO.ISession | null> {
        if (this.closing) {
            this.log.warn(
                "Database is closing, getSessionByUserID() will not complete."
            );
            return null;
        }
        const rows: XTypes.SQL.ISession[] = await this.db
            .from("sessions")
            .select()
            .where({ deviceID })
            .limit(1)
            .orderBy("lastUsed", "desc");
        if (rows.length === 0) {
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
            this.log.warn(
                "Database is closing, getPreKeys() will not complete."
            );
            return null;
        }
        const rows: XTypes.SQL.IPreKeys[] = await this.db
            .from("preKeys")
            .select();
        if (rows.length === 0) {
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
            this.log.warn(
                "Database is closing, getOneTimeKey() will not complete."
            );
            return null;
        }
        const rows: XTypes.SQL.IPreKeys[] = await this.db
            .from("oneTimeKeys")
            .select()
            .where({ index });
        if (rows.length === 0) {
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
        if (this.closing) {
            this.log.warn(
                "Database is closing, deleteOneTimeKey() will not complete."
            );
            return;
        }
        // delete the otk
        await this.db
            .from("oneTimeKeys")
            .delete()
            .where({ index });
    }

    public async saveSession(session: XTypes.SQL.ISession) {
        if (this.closing) {
            this.log.warn(
                "Database is closing, deleteOneTimeKey() will not complete."
            );
            return;
        }
        await this.db("sessions").insert(session);
    }

    public async init() {
        this.log.info("Initializing database tables.");
        try {
            if (!(await this.db.schema.hasTable("messages"))) {
                await this.db.schema.createTable("messages", (table) => {
                    table.string("nonce").primary();
                    table.string("sender").index();
                    table.string("recipient").index();
                    table.string("group").index();
                    table.string("mailID");
                    table.string("message");
                    table.string("direction");
                    table.date("timestamp");
                    table.boolean("decrypted");
                    table.boolean("forward");
                });
            }
            if (!(await this.db.schema.hasTable("sessions"))) {
                await this.db.schema.createTable("sessions", (table) => {
                    table.string("sessionID").primary();
                    table.string("userID");
                    table.string("deviceID");
                    table.string("SK").unique();
                    table.string("publicKey");
                    table.string("fingerprint");
                    table.string("mode");
                    table.date("lastUsed");
                    table.boolean("verified");
                });
            }
            if (!(await this.db.schema.hasTable("preKeys"))) {
                await this.db.schema.createTable("preKeys", (table) => {
                    table.increments("index");
                    table.string("keyID").unique();
                    table.string("userID");
                    table.string("deviceID");
                    table.string("privateKey");
                    table.string("publicKey");
                    table.string("signature");
                });
            }
            if (!(await this.db.schema.hasTable("oneTimeKeys"))) {
                await this.db.schema.createTable("oneTimeKeys", (table) => {
                    table.increments("index");
                    table.string("keyID").unique();
                    table.string("userID");
                    table.string("deviceID");
                    table.string("privateKey");
                    table.string("publicKey");
                    table.string("signature");
                });
            }

            // make test read
            await this.db.from("preKeys").select();

            this.ready = true;
            this.emit("ready");
        } catch (err) {
            this.emit("error", err);
        }
    }

    private async untilReady() {
        let timeout = 1;
        while (!this.ready) {
            await sleep(timeout);
            timeout *= 2;
        }
    }
}
