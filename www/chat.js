function addMessage(msg){
    const dmSource = msg.type == msgtype.PRIV_MSG ? "@"+msg.to : "";
    const msgDiv = `<div class='message'>${formatUnix(msg.timestamp)} ${msg.who}: ${dmSource} ${msg.msg}</div>\n`;
    document.getElementById("chat").innerHTML += msgDiv;

}

function pollMessages(){
    var xmlHTTP = new XMLHttpRequest();
    xmlHTTP.open("POST", "/poll", false);
    xmlHTTP.onreadystatechange = () => {
        if(xmlHTTP.readyState = XMLHttpRequest.DONE){
            console.log(xmlHTTP.responseText);
            const msg = JSON.parse(xmlHTTP.responseText);
            
            for(const message of msg){
                addMessage(message);
            }
        }
    }
    xmlHTTP.send();
}

function handleMessageSend(event){
    event.preventDefault();
    const form = document.getElementById("msg-form");
    const message = form.elements["message"].value;

    var xmlHTTP = new XMLHttpRequest();
    xmlHTTP.open("POST", "/postMessage", false);
    xmlHTTP.onreadystatechange = () => {
        if(xmlHTTP.readyState = XMLHttpRequest.DONE){
            const msg = JSON.parse(xmlHTTP.responseText);
            showMessage(msg, "messagebox");
        }
    }
    xmlHTTP.send();

}

window.addEventListener("load", () => {
    document.getElementById("msg-form").addEventListener("submit", handleMessageSend);
    document.getElementById("msgbox").style.display = "none";

    document.addEventListener("loggedIn", () => {
        document.getElementById("msgbox").style.display = "";
        setInterval(pollMessages, 5000);
    });
});