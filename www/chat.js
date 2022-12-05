
// Converts a message to a div and adds it
function addMessage(msg){
    const dmSource = msg.type == msgtype.PRIV_MSG ? "@"+msg.to : "";

    if(msg.type == msgtype.PRIV_MSG){
        msg.msg = rsaDecrypt(privkey, msg.msg)
    }

    const msgDiv = `<div class='message'>${formatUnix(msg.timestamp)} ${msg.from}: ${dmSource} ${msg.msg}</div>\n`;
    document.getElementById("chat").innerHTML += msgDiv;
}

function handleMessageSend(event){
    event.preventDefault();
    const form = document.getElementById("msg-form");
    var message = form.elements["message"].value;

    if(message[0] == "@"){
        var withoutat = form.elements["message"].value.slice(1);
        const tokenized = withoutat.split(" ");
        const name = tokenized[0];
        tokenized.shift();
        const message = tokenized.join(" ");

        sendData(getPrivMsg(message, name));
    }else{
        sendData(getPubMsg(message));
    }
}

function who(){
    sendData(getWho());
}

window.addEventListener("load", () => {
    document.getElementById("msg-form").addEventListener("submit", handleMessageSend);
    document.getElementById("msgbox").style.display = "none";

    document.addEventListener("loggedIn", () => {
        document.getElementById("msgbox").style.display = "";

        // Update online users every 5s
        setInterval(who, 5000);
    });

    document.addEventListener("recievedMessage", (event)=>{
        const msg = event.detail;

        if(msg.type == msgtype.PUB_MSG || msg.type == msgtype.PRIV_MSG){
            addMessage(msg);
        }else if (msg.type == msgtype.WHO){
            document.getElementById("who").innerHTML = msg.who;
        }
    });
});