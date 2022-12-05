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

// FROM CRYPTO-JS
function bytesToHex(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) {
        var current = bytes[i] < 0 ? bytes[i] + 256 : bytes[i];
        hex.push((current >>> 4).toString(16));
        hex.push((current & 0xF).toString(16));
    }
    return hex.join("");
}


// Returns bytes of signature
function sign(privkey, msg){
    var sig = new JKUR.crypto.Signature({"alg": "SHA1withRSA"});

    sig.init(privkey);
    
    sig.updateString(msg);

    return hexToBytes(sig.sign);
}

function verify(signatureB64, msg, certPEM){
    var sig = new KJUR.crypto.Signature({"alg": "SHA1withRSA"});

    sig.init(certPEM);

    sig.updateString(msg);

    return sig.verify(base64ToHex(signatureB64))
}

// Used for reference: https://github.com/kjur/jsrsasign/issues/176
// A lot of these functions in C I refered to the SSL examples, since these libs are quite complicated
// With javascript I looked online a lot for examples
function verifyTTP(certPEM, cacertPEM){
    var c = new X509();
    c.readCertPem(certPEM);

    var hexCert = KJUR.ASN1HEX.getDecendantHexTLVByNthList(c.hex, 0, [0]);
    var alg = c.getSignatureAlgorithmField();
    var certSig = KJUR.X509.getSignatureValueHex(certificate.hex);

    var sig = new KJUR.crypto.Signature({"alg": alg});
    sig.init(cacertPem);
    sig.updateHex(hexCert);
    return sig.verify(certSig);
}