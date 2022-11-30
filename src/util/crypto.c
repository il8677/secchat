#include "crypto.h"

// TODO: Use sha-2 and salt
// https://www.openssl.org/docs/man1.1.1/man3/SHA512_Init.html
void hash(char* data, uint32_t len, unsigned char* output){
    SHA_CTX ctx;

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, data, len);
    SHA1_Final(output, &ctx);
}


// WE DID NOT WRITE THIS CODE!!
// This was literally just needed for the websockets, so we took it from this site
// https://doctrina.org/Base64-With-OpenSSL-C-API.html
int Base64Encode(const unsigned char* buffer, size_t length, char** b64text) { //Encodes a binary safe base 64 string
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*b64text=(*bufferPtr).data;

	return (0);
}