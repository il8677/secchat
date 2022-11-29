function submitForm(event){
    event.preventDefault();
    const form = document.getElementById("login-form");
    const username = form.elements["username"].value;
    const password = form.elements["password"].value;
    const type = form.submitted;
    console.log(form.elements);
    const msg = type == "register" ? getReg(username, password) : getLogin(username, password);

    var xmlHTTP = new XMLHttpRequest();
    xmlHTTP.open("POST", "/postMessage", false);
    xmlHTTP.onreadystatechange = () =>{
        if(xmlHTTP.readyState == XMLHttpRequest.DONE){   
            showMessage(JSON.parse(xmlHTTP.responseText), "messagebox");
        }
    }
    xmlHTTP.send(msg);
}

window.addEventListener("load", () => {
    document.getElementById("login-form").addEventListener("submit", submitForm); 
    document.addEventListener("loggedIn", () => {
        document.getElementById("loginbox").style.display = "none";
    });
});
