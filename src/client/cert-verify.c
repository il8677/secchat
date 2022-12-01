#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

/* This example helps shows how to load a certificate from memory and obtain
 * the common name and public key of its subject. The certificate specified
 * on the command line is used to verify the signature in stdin for the message
 * provided as argv[3].
 *
 * Example to sign "Hello world" with key in file server-key.pem,
 * and then verify signature with key in certificate in the file
 * server-self-cert.pem:
 * ./rsa-sign server-key.pem 'Hello world' | ./cert-verify "`cat server-ca-cert.pem`" "`cat ca-cert.pem`" 'Hello world'
 *
 * Note that the quotes ensure that the contents (not the name) of the file
 * are passed to the program (so as to demonstrate how to parse a certificate
 * from a memory buffer).
 *
 * See Makefile for how to generate the keys.
 */

static void usage(void) {
  printf("usage:\n");
  printf("  cert-verify cert ca-cert message\n");
  printf("\n");
  printf("The signature for the message is provided in stdin.\n");
  exit(1);
}

static X509 *certfromstr(const char *str) {
  /* this creates an OpenSSL I/O Stream (BIO) to read from a memory buffer */
  BIO *bio = BIO_new_mem_buf(str, strlen(str));

  /* parse PEM-formatted certificate from memory I/O stream */
  X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  BIO_free(bio);

  return cert;
}

int main(int argc, char **argv) {
  X509 *cert, *cacert;
  char *commonName;
  EVP_MD_CTX *ctx;
  int len;
  X509_NAME *name;
  EVP_PKEY *pubkey, *capubkey;
  int r;
  unsigned char *sig;
  ssize_t siglen;

  if (argc != 4) usage();

  /* load certificates from arguments as strings */
  cert = certfromstr(argv[1]);
  cacert = certfromstr(argv[2]);

  /* get CA public key from certificate; note: we do not verify the
   * CA certificate, it is only use to obtain the trusted public key
   */
  capubkey = X509_get0_pubkey(cacert);

  /* verify CA signature */
  r = X509_verify(cert, capubkey);
  printf("certificate is %scorrectly signed by CA\n", (r == 1) ? "" : "not ");

  /* get common name (CN) length */
  name = X509_get_subject_name(cert);
  len = X509_NAME_get_text_by_NID(name, NID_commonName, NULL, 0);

  /* copy common name (CN) into buffer and print it */
  commonName = malloc(len + 1);
  X509_NAME_get_text_by_NID(name, NID_commonName, commonName, len + 1);
  printf("common name: %s\n", commonName);
  free(commonName);

  /* get public key from certificate */
  pubkey = X509_get0_pubkey(cert);

  /* read signature from stdin into sig */
  sig = malloc(EVP_PKEY_size(pubkey));
  siglen = read(0, sig, EVP_PKEY_size(pubkey));

  /* verify signature */
  ctx = EVP_MD_CTX_create();
  EVP_VerifyInit(ctx, EVP_sha1());
  EVP_VerifyUpdate(ctx, argv[3], strlen(argv[3]));
  r = EVP_VerifyFinal(ctx, sig, siglen, pubkey);
  printf("signature is %s\n", (r == 1) ? "good" : "bad");
  EVP_MD_CTX_free(ctx);
  /* EVP_PKEY_free(pubkey) not needed, the object is owned by the certificate */
  X509_free(cert);
  return 0;
}
