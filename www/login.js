function submitForm(event){
    event.preventDefault();
    const form = document.getElementById("login-form");
    const username = form.elements["username"].value;
    const password = form.elements["password"].value;
    const type = form.submitted;
    const msg = type == "register" ? getReg(username, password) : getLogin(username, password);
    
    api_username = username; // Set api username
    api_password = password; // Set api password
    sendData(msg);
}

window.addEventListener("load", () => {
    document.getElementById("login-form").addEventListener("submit", submitForm); 
    document.addEventListener("loggedIn", () => {
        document.getElementById("loginbox").style.display = "none";
    });
});
