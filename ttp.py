#/bin/python3
import shutil
import os
import argparse

ttpdir = "ttpkeys"
serverdir = "serverkeys"
clientdir = "clientkeys"

def createDir(dir):
    if not os.path.isdir(dir):
        os.mkdir(dir)
        return True
    return False

def generateKeyPair(dir):
    # Generate priv key
    os.system(f"openssl genrsa -out {dir}/priv.pem 2> /dev/null")
    
    # Generate public key
    os.system(f"openssl rsa -pubout -in {dir}/priv.pem -out {dir}/pub.pem 2> /dev/null")

def generateCA():
    os.system(f"openssl req -new -x509 -key {ttpdir}/priv.pem -out {ttpdir}/ca-cert.pem -nodes -subj '/CN=ca\.ttp\.com' 2> /dev/null")

def generateCert(dir, name):
    # Generate request
    os.system(f"openssl req -new -key {dir}/priv.pem -out {dir}/csr.pem -nodes -subj '/CN={name}' 2> /dev/null")
    
    # CA signs
    os.system(f"openssl x509 -req -CA {ttpdir}/ca-cert.pem -CAkey {ttpdir}/priv.pem -CAcreateserial -in {dir}/csr.pem -out {dir}/cert.pem 2> /dev/null")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="ttp", description="generates keys")

    parser.add_argument("-s", required=False, action="store_true")
    parser.add_argument("-ca", required=False, action="store_true")
    parser.add_argument("-c", required=False)
    args = parser.parse_args()
    
    createDir(clientdir)

    if args.s:
        if createDir(serverdir): # Only generate new pair if they don't already exist
            generateKeyPair(serverdir)
            generateCert(serverdir, "server")
    elif args.ca:
        if createDir(ttpdir):
            generateKeyPair(ttpdir)
            generateCA()

            shutil.copyfile(f"{ttpdir}/ca-cert.pem", f"{clientdir}/ca.cert")
    elif args.c:
        generateKeyPair(clientdir)
        generateCert(clientdir, args.c)