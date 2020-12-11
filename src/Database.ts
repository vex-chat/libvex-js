import { sleep } from "@extrahash/sleep";
import { XUtils } from "@vex-chat/crypto-js";
import { XTypes } from "@vex-chat/types-js";
import log from "electron-log";
import knex from "knex";
import nacl from "tweetnacl";
import { IMessage } from ".";

export class Database {
    public ready: boolean = false;
    private dbPath: string;
    private db: knex<any, unknown[]>;

    constructor(dbPath: string) {
        this.dbPath = dbPath;
        this.db = knex({
            client: "sqlite3",
            connection: {
                filename: this.dbPath,
            },
            useNullAsDefault: true,
        });
        this.init();
    }

    public async close() {
        await this.db.destroy();
    }

    public async saveMessage(message: IMessage) {
        await this.db("messages").insert(message);
    }

    public async markSessionVerified(sessionID: string, status = true) {
        await this.db("sessions")
            .where({ sessionID })
            .update({ verified: status });
    }

    public async getMessageHistory(userID: string): Promise<IMessage[]> {
        const messages = await this.db("messages")
            .select()
            .where({ sender: userID })
            .orWhere({ recipient: userID })
            .orderBy("timestamp", "asc")
            .limit(100);

        // i'm not sure why i have to do this, these are
        // coming through as strings
        return messages.map((row) => {
            row.timestamp = new Date(row.timestamp);
            return row;
        });
    }

    public async getIdentityKeys(): Promise<nacl.BoxKeyPair | null> {
        await this.untilReady();
        const rows = await this.db.from("identityKeys").select();
        if (rows.length === 0) {
            return null;
        }
        const [keys] = rows;
        return nacl.box.keyPair.fromSecretKey(
            XUtils.decodeHex(keys.privateKey)
        );
    }

    public async saveIdentityKeys(idKeys: nacl.BoxKeyPair) {
        await this.untilReady();
        await this.db("identityKeys").insert({
            privateKey: XUtils.encodeHex(idKeys.secretKey),
            publicKey: XUtils.encodeHex(idKeys.publicKey),
        });
    }

    public async savePreKeys(
        preKeys: XTypes.CRYPTO.IPreKeys,
        oneTime: boolean
    ): Promise<number> {
        await this.untilReady();
        const index = await this.db(oneTime ? "oneTimeKeys" : "preKeys").insert(
            {
                privateKey: XUtils.encodeHex(preKeys.keyPair.secretKey),
                publicKey: XUtils.encodeHex(preKeys.keyPair.publicKey),
                signature: XUtils.encodeHex(preKeys.signature),
            }
        );
        return index[0];
    }

    public async getSessionByPublicKey(publicKey: Uint8Array) {
        const str = XUtils.encodeHex(publicKey);

        const rows: XTypes.SQL.ISession[] = await this.db
            .from("sessions")
            .select()
            .where({ publicKey: str })
            .limit(1);
        if (rows.length === 0) {
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
        await this.db
            .from("sessions")
            .update({ lastUsed: new Date(Date.now()) })
            .where({ sessionID });
    }

    public async getFingerprints(): Promise<
        Record<string, XTypes.SQL.ISession[]>
    > {
        const rows: XTypes.SQL.ISession[] = await this.db
            .from("sessions")
            .select();

        const sessionsObj: Record<string, XTypes.SQL.ISession[]> = {};

        for (const sess of rows) {
            if (sessionsObj[sess.userID] === undefined) {
                sessionsObj[sess.userID] = [];
            }
            sessionsObj[sess.userID].push(sess);
        }
        return sessionsObj;
    }

    public async getSessions(): Promise<XTypes.SQL.ISession[]> {
        const rows: XTypes.SQL.ISession[] = await this.db
            .from("sessions")
            .select()
            .orderBy("lastUsed", "desc");

        return rows;
    }

    public async getSession(
        userID: string
    ): Promise<XTypes.CRYPTO.ISession | null> {
        const rows: XTypes.SQL.ISession[] = await this.db
            .from("sessions")
            .select()
            .where({ userID })
            .limit(1)
            .orderBy("lastUsed", "desc");
        if (rows.length === 0) {
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
        const rows: XTypes.SQL.IPreKeys[] = await this.db
            .from("preKeys")
            .select();
        if (rows.length === 0) {
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

        const rows: XTypes.SQL.IPreKeys[] = await this.db
            .from("oneTimeKeys")
            .select()
            .where({ index });
        if (rows.length === 0) {
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
        await this.db
            .from("oneTimeKeys")
            .delete()
            .where({ index });
    }

    public async saveSession(session: XTypes.SQL.ISession) {
        await this.db("sessions").insert(session);
    }

    public async retrieveMessageHistory(userID: string) {
        return this.db("messages")
            .select()
            .where({});
    }

    private async untilReady() {
        let timeout = 1;
        while (!this.ready) {
            await sleep(timeout);
            timeout *= 2;
        }
    }

    private async init() {
        if (!(await this.db.schema.hasTable("messages"))) {
            await this.db.schema.createTable("messages", (table) => {
                table.string("nonce").primary();
                table.string("sender").index();
                table.string("recipient").index();
                table.string("message");
                table.string("direction");
                table.date("timestamp");
            });
        }

        if (!(await this.db.schema.hasTable("identityKeys"))) {
            await this.db.schema.createTable("identityKeys", (table) => {
                table.string("privateKey").primary();
                table.string("publicKey");
            });
        }
        if (!(await this.db.schema.hasTable("sessions"))) {
            await this.db.schema.createTable("sessions", (table) => {
                table.string("sessionID").primary();
                table.string("userID");
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
                table.string("privateKey");
                table.string("publicKey");
                table.string("signature");
            });
        }
        this.ready = true;
    }
}
