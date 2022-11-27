const msgtype = {
    NONE: 0,
    ERR: 1,
    STATUS: 2,
    PRIV_MSG: 3,
    PUB_MSG: 4,
    WHO: 5,
    LOGIN: 6,
    REG: 7,
    EXIT: 8
}

const MAX_MSG_LEN = 160;
const MAX_USER_LEN = 10;

const timestampSize = 8; 

// Adapted from https://stackoverflow.com/questions/11177153/null-padding-a-string-in-javascript
function nullpad( str, len ) {
    if( str.length >= len ) {
        return str.substring(0, len-1);
    }

    return str + Array( len-str.length + 1).join("\x00");
}

// Functions to format binary that represents api_msg, it was this or to parse JSON in C, so this felt like the lesser evil
function getPrivMsg(timestamp, msg, to){
    // Length constraints
    msg = nullpad(str, MAX_MSG_LEN);
    from = nullpad("", MAX_USER_LEN);
    to = nullpad(str, MAX_USER_LEN);

    const b = new Blob([
        new Uint32Array([msgtype.PRIV_MSG]),         // Type
        new Uint8Array([0]),                 // Errcode
        new Uint8Array(timestampSize),
        new String(msg),                      // msg
        new String(from),
        new String(to)
    ]);

    return b;
}

function getPubMsg(timestamp, msg){
    msg = nullpad(str, MAX_MSG_LEN);

    const b = new Blob([
        new Uint32Array([msgtype.PUB_MSG]),         // Type
        new Uint8Array([0]),                 // Errcode
        new Uint8Array(timestampSize),
        new String(msg)                      // msg
    ]);

    return b;
}

function getWho(req){
    const b = new Blob([new Uint32Array([msgtype.WHO])]);

    return b;
}

function getLogin(username, password){
    username = nullpad(username, MAX_USER_LEN);
    password = nullpad(password, MAX_USER_LEN);
    
    // TODO: hashing
    const b = new Blob([
        new Uint32Array([msgtype.LOGIN]),
        new Uint8Array([0]),
        new String(username),
        new String(password)
    ]);

    return b;
}

function getReg(username, password){
    username = nullpad(username, MAX_USER_LEN);
    password = nullpad(password, MAX_USER_LEN);

    const b = new Blob([
        new Uint32Array([msgtype.REG]),
        new Uint8Array([0]),
        new String(username),
        new String(password)
    ]);

    return b;
}