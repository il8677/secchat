/*
    This is probably terrible javacscript code, and the html is probably also terrible. 
    But the goal is to be secure, and I don't usually program in javacsript so I don't 
    know best practices outside of general programming best practices (which I also don't really follow here)
*/

// Globals

// Events that other scripts can use to listen for events
const e_loggedIn = new Event("loggedIn");

const msgqueue = new Map();
const keys = new Map();

var cacert = 0; // Note: retrieved from the server, read README -> #Bonus -> ##Notes
var privkey = 0;
var pubkey = 0;

var api_password = "";
var api_username = "";

const msgtype = {
    NONE: 0,
    ERR: 1,
    STATUS: 2,
    PRIV_MSG: 3,
    PUB_MSG: 4,
    WHO: 5,
    LOGIN: 6,
    REG: 7,
    LOGINACK: 8,
    EXIT: 9,
    KEY: 10
}

const MAX_MSG_LEN = 160;
const MAX_USER_LEN = 10;
const HASH_OUT_LEN = 20;
const MAX_ENCRYPT_LEN = 256;

const SIZEOF_APIMSG = 832;

const timestampSize = 8; 

// Adapted from https://stackoverflow.com/questions/11177153/null-padding-a-string-in-javascript
// Formats a string to a null terminated length
function nullpad( str, len ) {
    if( str.length >= len - 1) {
        return str.substring(0, len-1);
    }

    return str + Array( len-str.length + 1).join("\x00");
}

// Fills the rest of the api_msg bytes
function fillBytes(b){
    return new Blob([b, new Uint8Array(SIZEOF_APIMSG-b.size)])
}

function removeNullBytes(msg){
    return msg.replaceAll("\0", "");
}

// ==============================================================================================================================
// Ugly Functions to format binary that represents api_msg, it was this or to parse JSON in C, so this felt like the lesser evil
// ==============================================================================================================================
function getKey(to){
    const b = new Blob([
        new Uint32Array([msgtype.KEY]),
        new Uint32Array([0]),                 // Errcode
        new Uint16Array([0]),
        new Uint16Array([0]),
        new Uint32Array([0]),
        new String(nullpad("", MAX_ENCRYPT_LEN)), // Padding
        new Uint8Array(timestampSize), // Padding
        new String(nullpad("", MAX_USER_LEN)),                      // padding
        new String(nullpad(to, MAX_USER_LEN))
    ]);

    return fillBytes(b);
}

function getPrivMsg(msg, to){
    if(!keys.has(to)){
        return getKey(to);
    }

    const signature = sign(privkey, msg);

    msg+="\0"; // Add nullbyte so it's encrypted and clients can correctly read the message

    otherkey = keys.get(to);

    msgfrom = rsaEncrypt(pubkey, msg);
    msgto = rsaEncrypt(otherkey, msg);

    from = nullpad("", MAX_USER_LEN);
    to = nullpad(to, MAX_USER_LEN);

    const b = new Blob([
        new Uint32Array([msgtype.PRIV_MSG]),         // Type
        new Uint32Array([0]),                 // Errcode
        new Uint16Array([0]),
        new Uint16Array([0]),
        new Uint32Array([0]),
        new Uint8Array(signature),
        new Uint8Array(timestampSize),
        from,
        to,
        new Uint8Array(msgfrom),                      // msg
        new Uint8Array(msgto)
    ]);

    return fillBytes(b);
}

function getPubMsg(msg){
    const signature = sign(privkey, msg);
    msg = nullpad(msg, MAX_MSG_LEN);

    const b = new Blob([
        new Uint32Array([msgtype.PUB_MSG]),         // Type
        new Uint32Array([0]),                 // Errcode
        new Uint16Array([0]),
        new Uint16Array([0]),
        new Uint32Array([0]),
        new Uint8Array(signature),
        new Uint8Array(timestampSize),
        new Uint8Array(MAX_USER_LEN),
        new String(msg)                      // msg
    ]);

    return fillBytes(b);
}

function getWho(){
    const b = new Blob([new Uint32Array([msgtype.WHO])]);

    return fillBytes(b);
}

function getLogin(username, password){
    password = sha256(password, username);
    username = nullpad(username, MAX_USER_LEN);

    const b = new Blob([
        new Uint32Array([msgtype.LOGIN]),
        new Uint32Array([0]),
        new Uint16Array([0]),
        new Uint16Array([0]),
        new Uint32Array([0]),
        new String(username),
        new Uint8Array(password)
    ]);

    return fillBytes(b);
}

function getReg(username, password){
    password = sha256(password, username);
    username = nullpad(username, MAX_USER_LEN);

    const b = new Blob([
        new Uint32Array([msgtype.REG]),
        new Uint32Array([0]),
        new Uint16Array([0]),
        new Uint16Array([0]),
        new Uint32Array([0]),
        new String(username),
        new Uint8Array(password)
    ]);

    return fillBytes(b);
}

function sendData(data){
    document.commSocket.send(data);
}

function errcodeToString(errcode){
    switch(-errcode){
        case 1: return "Internal Server Error";
        case 2: return "Invalid name";
        case 3: return "Invalid API Message";
        case 4: return "Error: Username already exists";
        case 5: return "Error: Invalid Username/Password";
        case 6: return "Error: Authentication Error";
        case 7: return "Error: No User";
        case 8: return "Error: Already logged in";
        case 9: return "Error: User does not exist";
    }
}


// Displays a message on a div given by outid
// Returns if it was a valid message or not
function showMessage(msg, outid){
    const outElement = document.getElementById(outid);
    if(msg.type == msgtype.ERR){
        outElement.className = "alert alert-danger";
        outElement.innerHTML = errcodeToString(msg.errcode);

        if(msg.errcode == -8){
            document.dispatchEvent(e_loggedIn);
        }

        return true;
    }
    else if(msg.type == msgtype.STATUS){
        outElement.className = "alert alert-info";
        outElement.innerHTML = msg.status;
        return true;
    }

    return false;
}

function handleIncomingKey(msg){
    if(msg.type == msgtype.KEY){
        if(!verifyTTP(msg.cert, cacert)) return;
        if(msg.key == undefined) return;

        keys.set(msg.who, msg.key);
    }
}

function handleLoginAck(msg){
    if(msg.type == msgtype.LOGINACK){
        if(pubkey != 0 || privkey != 0) return;

        pubkey = msg.cert;
        privkey = removeNullBytes(aesDecrypt(api_username, api_password, msg.privkey));
        
        document.dispatchEvent(e_loggedIn);
    }
}

function handleMsg(msg){
    if(msg.type == msgtype.PUB_MSG || msg.type == msgtype.PRIV_MSG){
        if(msg.cert != undefined){
            if(!verifyTTP(msg.cert, cacert)) return;
            keys.set(msg.from, msg.cert);
        }
    }
}

// Taken from https://stackoverflow.com/questions/847185/convert-a-unix-timestamp-to-time-in-javascript
function formatUnix(unix_timestamp){
    // Create a new JavaScript Date object based on the timestamp
    // multiplied by 1000 so that the argument is in milliseconds, not seconds.
    var date = new Date(unix_timestamp * 1000);
    // Hours part from the timestamp
    var hours = date.getHours();
    // Minutes part from the timestamp
    var minutes = "0" + date.getMinutes();
    // Seconds part from the timestamp
    var seconds = "0" + date.getSeconds();

    // Will display time in 10:30:23 format
    return hours + ':' + minutes.substr(-2) + ':' + seconds.substr(-2);
}

function createWebsocket(){
    const ws = new WebSocket("wss://" + location.host);

    ws.onmessage = (event) => {
        const nremoved = event.data.replaceAll("\n", " "); // Remove newlines that could cause issues with json

        const msg = JSON.parse(nremoved);

        document.dispatchEvent(new CustomEvent("recievedMessage", {detail: msg})); // The recieve message event is triggered when an api msg is recieved from the server
    }

    return ws;
}

window.addEventListener("load", () => {
    // bad global variable! But I'm not sure how it should be properly done
    document.commSocket = createWebsocket();

    // Syncronously get (This is slow, but in a real app the ttp cert should already be installed, see README)
    const request = new XMLHttpRequest();
    request.open('GET', '/ca.cert', false);  // `false` makes the request synchronous
    request.send(null);

    if (request.status === 200) {
        cacert = request.responseText;
    }

    document.addEventListener("recievedMessage", (event) => {
        showMessage(event.detail, "statusbox");
        handleIncomingKey(event.detail);
        handleLoginAck(event.detail);
        handleMsg(event.detail);
    }); // Add listener to show status messages / errors
});