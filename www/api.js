/*
    This is probably terrible javacscript code, and the html is probably also terrible. 
    But the goal is to be secure, and I don't usually program in javacsript so I don't 
    know best practices outside of general programming best practices
*/

// Globals

// Events that other scripts can use to listen for events
const e_loggedIn = new Event("loggedIn");

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
const HASH_OUT_LEN = 20;

const timestampSize = 8; 

// Adapted from https://stackoverflow.com/questions/11177153/null-padding-a-string-in-javascript
// Formats a string to a null terminated length
function nullpad( str, len ) {
    if( str.length >= len ) {
        return str.substring(0, len-1);
    }

    return str + Array( len-str.length + 1).join("\x00");
}

// Functions to format binary that represents api_msg, it was this or to parse JSON in C, so this felt like the lesser evil
function getPrivMsg(msg, to){
    // Length constraints
    msg = nullpad(msg, MAX_MSG_LEN);
    from = nullpad("", MAX_USER_LEN);
    to = nullpad(to, MAX_USER_LEN);

    const b = new Blob([
        new Uint32Array([msgtype.PRIV_MSG]),         // Type
        new Uint32Array([0]),                 // Errcode
        new Uint8Array(timestampSize),
        new String(msg),                      // msg
        new String(from),
        new String(to)
    ]);

    return b;
}

function getPubMsg(msg){
    msg = nullpad(msg, MAX_MSG_LEN);

    const b = new Blob([
        new Uint32Array([msgtype.PUB_MSG]),         // Type
        new Uint32Array([0]),                 // Errcode
        new Uint8Array(timestampSize),
        new String(msg)                      // msg
    ]);

    return b;
}

function getWho(){
    const b = new Blob([new Uint32Array([msgtype.WHO])]);

    return b;
}

function getLogin(username, password){
    username = nullpad(username, MAX_USER_LEN);
    password = sjcl.hash.sha1.hash(password)
    password = sjcl.codec.bytes.fromBits(password);

    const b = new Blob([
        new Uint32Array([msgtype.LOGIN]),
        new Uint32Array([0]),
        new String(username),
        new Uint8Array(password)
    ]);

    return b;
}

function getReg(username, password){
    username = nullpad(username, MAX_USER_LEN);
    password = sjcl.hash.sha1.hash(password)
    password = sjcl.codec.bytes.fromBits(password);

    const b = new Blob([
        new Uint32Array([msgtype.REG]),
        new Uint32Array([0]),
        new String(username),
        new Uint8Array(password)
    ]);

    return b;
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

        if(msg.errcode == 8){
            document.dispatchEvent(e_loggedIn);
        }

        return true;
    }
    else if(msg.type == msgtype.STATUS){
        outElement.className = "alert alert-info";
        outElement.innerHTML = msg.status;

        // Ugly, but it will be fixed later when the method of login comfirmation changes
        if(msg.status == "authentication succeeded"){
            document.dispatchEvent(e_loggedIn);
        }

        return true;
    }

    return false;
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
    // TODO: Not static URL
    const ws = new WebSocket("wss://localhost");

    ws.onmessage = (event) => {
        const nremoved = event.data.replaceAll("\n", " "); // Remove newlines that could cause issues with json
        console.log(nremoved);

        const msg = JSON.parse(nremoved);

        document.dispatchEvent(new CustomEvent("recievedMessage", {detail: msg})); // The recieve message event is triggered when an api msg is recieved from the server
    }

    return ws;
}

window.addEventListener("load", () => {
    // bad global variable! But I'm not sure how it should be properly done
    document.commSocket = createWebsocket();
    document.addEventListener("recievedMessage", (event) => {showMessage(event.detail, "statusbox");}); // Add listener to show status messages / errors
});