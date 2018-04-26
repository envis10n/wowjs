module.exports.AuthCMD = {
    CMD_AUTH_LOGON_CHALLENGE: Buffer.from([0x0])[0],
    CMD_AUTH_LOGON_PROOF: Buffer.from([0x1])[0],
    CMD_AUTH_RECONNECT_CHALLENGE: Buffer.from([0x2])[0],
    CMD_AUTH_RECONNECT_PROOF: Buffer.from([0x3])[0],
    CMD_AUTH_REALMLIST: Buffer.from([0x10])[0],
    CMD_XFER_INITIATE: Buffer.from([0x30])[0],
    CMD_XFER_DATA: Buffer.from([0x31])[0],
    CMD_XFER_ACCEPT: Buffer.from([0x32])[0],
    CMD_XFER_RESUME: Buffer.from([0x33])[0],
    CMD_XFER_CANCEL: Buffer.from([0x34])[0]
};

module.exports.AuthResult = {
    WOW_SUCCESS: Buffer.from([0x0])[0],
    WOW_FAIL_BANNED: Buffer.from([0x3])[0],
    WOW_FAIL_UNKNOWN_ACCOUNT: Buffer.from([0x4])[0],
    WOW_FAIL_INCORRECT_PASSWORD: Buffer.from([0x5])[0],
    WOW_FAIL_ALREADY_ONLINE: Buffer.from([0x6])[0],
    WOW_FAIL_NO_TIME: Buffer.from([0x7])[0],
    WOW_FAIL_DB_BUSY: Buffer.from([0x8])[0],
    WOW_FAIL_VERSION_INVALID: Buffer.from([0x9])[0],
    WOW_FAIL_VERSION_UPDATE: Buffer.from([0xA])[0],
    WOW_FAIL_INVALID_SERVER: Buffer.from([0xB])[0],
    WOW_FAIL_SUSPENDED: Buffer.from([0xC])[0],
    WOW_FAIL_FAIL_NOACCESS: Buffer.from([0xD])[0],
    WOW_SUCCESS_SURVEY: Buffer.from([0xE])[0],
    WOW_FAIL_PARENTCONTROL: Buffer.from([0xF])[0],
    WOW_FAIL_LOCKED_ENFORCED: Buffer.from([0x10])[0],
    WOW_FAIL_TRIAL_ENDED: Buffer.from([0x11])[0],
    WOW_FAIL_ANTI_INDULGENCE: Buffer.from([0x13])[0],
    WOW_FAIL_EXPIRED: Buffer.from([0x14])[0],
    WOW_FAIL_NO_GAME_ACCOUNT: Buffer.from([0x15])[0],
    WOW_FAIL_CHARGEBACK: Buffer.from([0x16])[0],
    WOW_FAIL_GAME_ACCOUNT_LOCKED: Buffer.from([0x18])[0],
    WOW_FAIL_UNLOCKABLE_LOCK: Buffer.from([0x19])[0],
    WOW_FAIL_CONVERSION_REQUIRED: Buffer.from([0x20])[0],
    WOW_FAIL_DISCONNECTED: Buffer.from([0xFF])[0]
}

module.exports.AccountState = {
    LOGIN_OK: Buffer.from([0x0])[0],
    LOGIN_FAILED: Buffer.from([0x1])[0],          
    LOGIN_BANNED: Buffer.from([0x3])[0],          
    LOGIN_UNKNOWN_ACCOUNT: Buffer.from([0x4])[0], 
    LOGIN_BAD_PASS: Buffer.from([0x5])[0],        
    LOGIN_ALREADYONLINE: Buffer.from([0x6])[0],   
    LOGIN_NOTIME: Buffer.from([0x7])[0],          
    LOGIN_DBBUSY: Buffer.from([0x8])[0],          
    LOGIN_BADVERSION: Buffer.from([0x9])[0],      
    LOGIN_DOWNLOADFILE: Buffer.from([0xA])[0],
    LOGIN_SUSPENDED: Buffer.from([0xC])[0],
    LOGIN_PARENTALCONTROL: Buffer.from([0xF])[0]
}

module.exports.LoginResponse = {
    LOGIN_OK: Buffer.from([0xC])[0],
    LOGIN_VERSION_MISMATCH: Buffer.from([0x14])[0],
    LOGIN_UNKNOWN_ACCOUNT: Buffer.from([0x15])[0],
    LOGIN_WAIT_QUEUE: Buffer.from([0x1B])[0]
}