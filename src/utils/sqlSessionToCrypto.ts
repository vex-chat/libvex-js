import { XUtils } from "@vex-chat/crypto";
// import { XTypes } from "@vex-chat/types";
import * as XTypes from "@vex-chat/types";

export function sqlSessionToCrypto(
    session: XTypes.ISessionSQL
): XTypes.ISessionCrypto {
    return {
        sessionID: session.sessionID,
        userID: session.userID,
        mode: session.mode,
        SK: XUtils.decodeHex(session.SK),
        publicKey: XUtils.decodeHex(session.publicKey),
        lastUsed: session.lastUsed,
        fingerprint: XUtils.decodeHex(session.fingerprint),
    };
}
