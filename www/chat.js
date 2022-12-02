
// Converts a message to a div and adds it
function addMessage(msg){
    const dmSource = msg.type == msgtype.PRIV_MSG ? "@"+msg.to : "";
    const msgDiv = `<div class='message'>${formatUnix(msg.timestamp)} ${msg.from}: ${dmSource} ${msg.msg}</div>\n`;
    document.getElementById("chat").innerHTML += msgDiv;
}

function handleMessageSend(event){
    event.preventDefault();
    const form = document.getElementById("msg-form");
    const message = form.elements["message"].value;

    // TODO: Private messages
    sendData(getPubMsg(message));
}

window.addEventListener("load", () => {
    document.getElementById("msg-form").addEventListener("submit", handleMessageSend);
    document.getElementById("msgbox").style.display = "none";

    document.addEventListener("loggedIn", () => {
        document.getElementById("msgbox").style.display = "";
    });

    document.addEventListener("recievedMessage", (event)=>{
        const msg = event.detail;

        if(msg.type == msgtype.PUB_MSG || msg.type == msgtype.PRIV_MSG){
            addMessage(msg);
        }
    });
});