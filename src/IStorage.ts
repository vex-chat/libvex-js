import * as XTypes from "@vex-chat/types";
import { EventEmitter } from "events";
import { IMessage, ISession } from ".";

/**
 * This is the class you must implement to store and retrieve
 * important data for the key exchange and messaging processes if you want to
 * replace the Database class, for example, if you wanted to port
 * this library to mobile or browser or another platform that doesn't support
 * knex.js
 */
export interface IStorage extends EventEmitter {
    /**
     * Set this to "true" when init has complete.
     */
    ready: boolean;
    /**
     * Closes the database. You must close any open connections
     * so the sqlite database is available to be opened again.
     */
    close: () => Promise<void>;
    /**
     * Saves a single message to a database.
     *
     * @param message The message to save.
     */
    saveMessage: (message: IMessage) => Promise<void>;
    /**
     * Deletes a message. Remove it entirely.
     *
     * @param message The message to delete.
     */
    deleteMessage: (mailID: string) => Promise<void>;
    /**
     * Marks a session as "verified" which means the
     * user has compared the mnemonic fingerprint with
     * the other user and indicated it matches.
     *
     * @param sessionID the sessionID to mark verified.
     */
    markSessionVerified: (sessionID: string) => Promise<void>;
    /**
     * Updates the "lastUsed" timestamp key of a session
     * to the current time. This will be called each time the
     * session is used to encrypt or decrypt a message.
     *
     * @param sessionID the sessionID to mark used.
     */
    markSessionUsed: (sessionID: string) => Promise<void>;
    /**
     * Gets the direct message history of a user by their userID, in
     * descending temporal order.
     *
     * @param userID the userID to retrieve history for.
     */
    getMessageHistory: (userID: string) => Promise<IMessage[]>;
    /**
     * Gets the group message history of a channel by its channelID, in
     * descending temporal order.
     *
     * @param channelID the channelID to retrieve history for.
     */
    getGroupHistory: (channelID: string) => Promise<IMessage[]>;
    /**
     * Deletes the history for a userID or channelID older than a
     * specified duration, if duration is not included, all history
     * is deleted.
     *
     * @param channelOrUserID the channelID to delete history for.
     * @param duration the duration as a string eg. 1h or 7d or 30m
     */
    deleteHistory: (
        channelOrUserID: string,
        olderThan?: string
    ) => Promise<void>;
    /**
     * Deletes all history.
     */
    purgeHistory: () => Promise<void>;
    /**
     * Deletes all sessions, one time keys, and prekeys.
     */
    purgeKeyData: () => Promise<void>;
    /**
     * Saves a main set of prekeys or a onetime set of prekeys,
     * as indicated by the oneTime parameter.
     */
    savePreKeys: (
        preKeys: XTypes.IPreKeysCrypto[],
        oneTime: boolean
    ) => Promise<XTypes.IPreKeysSQL[]>;
    /**
     * Gets your set of main prekeys. You only have one at a time.
     * Returns null if the prekeys have not been saved yet.
     *
     * @param preKeys the set of prekeys to save.
     * @param oneTime whether or not the set of prekeys is a one time set.
     */
    getPreKeys: () => Promise<XTypes.IPreKeysCrypto | null>;
    /**
     * Gets a set of one time keys by index number.
     *
     * @param index The index number of the prekey to fetch.
     */
    getOneTimeKey: (index: number) => Promise<XTypes.IPreKeysCrypto | null>;
    /**
     * Deletes a set of one time keys by index number.
     *
     * @param index The index number of the prekey to delete.
     */
    deleteOneTimeKey: (index: number) => Promise<void>;
    /**
     * Gets an encryption session by its public key.
     *
     * @param publicKey the public key of the session to fetch.
     */
    getSessionByPublicKey: (
        publicKey: Uint8Array
    ) => Promise<XTypes.ISessionCrypto | null>;
    /**
     * Gets all encryption sessions.
     */
    getAllSessions: () => Promise<ISession[]>;
    /**
     * Gets the most recently used (active) session (by lastUsed key) by userID.
     *
     * @param userID The userID to retrieve the active session for.
     */
    getSessionByDeviceID: (
        deviceID: string
    ) => Promise<XTypes.ISessionCrypto | null>;
    /**
     * Saves an encryption session.
     *
     * @param session The ISession object to save.
     */
    saveSession: (session: ISession) => Promise<void>;
    /**
     * Any initializing you may need to do before the class is used.
     * For example, you could initialize the database schema here.
     */

    init: () => Promise<void>;
    getDevice: (deviceID: string) => Promise<XTypes.IDevice | null>;
    saveDevice: (device: XTypes.IDevice) => Promise<void>;

    /**
     * Emit this event when init has complete.
     *
     * @event
     */
    on(event: "ready", callback: () => void): this;
    /**
     * Emit this event if there is an error in opening the database.
     *
     * @event
     */
    on(event: "error", callback: (error: Error) => void): this;
}
