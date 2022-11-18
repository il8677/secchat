#/bin/python3
import ssl
import os
import argparse

ttpdir = "ttpkeys"
serverdir = "serverkeys"
clientdir = "clientkeys"

def generateKeyPair(dir):
    # Generate priv key
    os.system(f"openssl genrsa -out {dir}/priv.pem")
    
    # Generate public key
    os.system(f"openssl rsa -pubout -in {dir}/priv.pem -out {dir}/pub.pem")

def generateCA():
    os.system(f"openssl req -new -x509 -key {ttpdir}/priv.pem -out {ttpdir}/ca-cert.pem -nodes -subj '/CN=ca\.ttp\.com'")

def generateCert(dir, name):
    # Generate request
    os.system(f"openssl req -new -key {dir}/priv.pem -out {dir}/csr.pem -nodes -subj '/CN={name}\.secchat\.com'")
    
    # CA signs
    os.system(f"openssl x509 -req -CA {ttpdir}/ca-cert.pem -CAkey {ttpdir}/priv.pem -CAcreateserial -in {dir}/csr.pem -out {dir}/{name}-cert.pem")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="ttp", description="generates keys")

    parser.add_argument("action")
    args = parser.parse_args()
    
    def createDir(dir):
        if not os.path.isdir(dir):
            os.mkdir(dir)
    
    createDir(ttpdir)
    createDir(serverdir)
    createDir(clientdir)

    if args.action == "server":
        generateKeyPair(serverdir)
        generateCert(serverdir, "server")
    elif args.action == "ttp":
        generateKeyPair(ttpdir)
        generateCA()