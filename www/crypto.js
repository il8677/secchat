// I have helper functions here that I DID NOT WRITE!! This is because they do pretty fundemental things (conversions) that I don't think is important if I do for the purposes of the assignemnt

// https://stackoverflow.com/questions/39460182/decode-base64-to-hexadecimal-string-with-javascript
function base64ToHex(str) {
    const raw = atob(str);
    let result = '';
    for (let i = 0; i < raw.length; i++) {
      const hex = raw.charCodeAt(i).toString(16);
      result += (hex.length === 2 ? hex : '0' + hex);
    }
    return result.toUpperCase();
  }

// FROM CRYPTO-JS
function hexToBytes(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

// Returns bytes of signature
function sign(privkeyPEM, msg){
    var sig = new KJUR.crypto.Signature({"alg": "SHA1withRSA"});

    sig.init(RSAKeyFromPEM(privkeyPEM));
    
    sig.updateString(msg);

    return hexToBytes(sig.sign());
}

function verify(signatureB64, msg, certPEM){
    if(certPEM == undefined) return false;
    console.log("Verifying " + msg);
    var sig = new KJUR.crypto.Signature({"alg": "SHA1withRSA"});

    sig.init(certPEM);

    sig.updateString(msg);

    return sig.verify(base64ToHex(signatureB64))
}

// Used for reference: https://github.com/kjur/jsrsasign/issues/176
// A lot of these functions in C I refered to the SSL examples, since these libs are quite complicated
// With javascript I looked online a lot for examples
function verifyTTP(certPEM, cacertPEM){ // TODO: Name verification
    if(cacertPEM == 0) return false;

    var c = new X509();
    c.readCertPEM(certPEM);

    var hexCert = ASN1HEX.getTLVbyList(c.hex, 0, [0]);
    var alg = c.getSignatureAlgorithmField();
    var certSig = c.getSignatureValueHex();

    var sig = new KJUR.crypto.Signature({"alg": alg});
    sig.init(cacertPEM);
    sig.updateHex(hexCert);
    return sig.verify(certSig);
}

function RSAKeyFromCert(certPEM){
    var c = new X509();
    c.readCertPEM(certPEM);

    return c.getPublicKey();
}

function RSAKeyFromPEM(keyPEM){
    var key = new RSAKey();
    key.readPrivateKeyFromPEMString(keyPEM);
    return key;
}

// Encrypts message, returns bytes
function rsaEncrypt(keyCertPEM, msg){
    return hexToBytes(KJUR.crypto.Cipher.encrypt(msg, RSAKeyFromCert(keyCertPEM), "RSAOAEP"));
}

function rsaDecrypt(privkeyPEM, msgBytes){
    return KJUR.crypto.Cipher.decrypt(base64ToHex(msgBytes), RSAKeyFromPEM(privkeyPEM), "RSAOAEP");
}

function aesDecrypt(iv, password, encText){
    password = nullpad(password, 16);
    iv = nullpad(iv, 16);

    // Make iv and password correct length
    const decrypted = CryptoJS.AES.decrypt({ciphertext: CryptoJS.enc.Base64.parse(encText), salt:""}, 
        CryptoJS.enc.Utf8.parse(password), {iv: CryptoJS.enc.Utf8.parse(iv)});

    return decrypted.toString(CryptoJS.enc.Utf8);
}