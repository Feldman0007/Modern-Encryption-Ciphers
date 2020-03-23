#include "AES.h"

/**
 * Sets the key to use
 * @param key - the first byte of this represents whether
 * to encrypt or to decrypt. 00 means encrypt and any other
 * value to decrypt.  Then come the bytes of the 128-bit key
 * (should be 16 of them).
 * @return - True if the key is valid and False otherwise
 */
bool AES::setKey(const unsigned char* keyArray)
{
    unsigned char encORdec = keyArray[0];
    size_t blockSize = 16;
    memcpy(&aes_key, &keyArray[1], blockSize);

    if (encORdec == (unsigned char)1)
	{
		/* Set the encryption key */
        if (AES_set_encrypt_key(aes_key, 128, &enc_key) != 0)
		{
			fprintf(stderr, "AES_set_encrypt_key() failed!\n");
			exit(-1);
		}
	}
    else if (encORdec == (unsigned char)0)
	{
		if (AES_set_decrypt_key(aes_key, 128, &dec_key) != 0)
		{
			fprintf(stderr, "AES_set_decrypt_key() failed!\n");
			exit(-1);
		}
    }
    else
    {
        fprintf(stderr, "First bit of key should either be a 1 or a 0 for Encrypt or Decrypt");
        return false;
    }
    return true;
}

/**	
 * Encrypts a plaintext string
 * @param plaintext - the plaintext string
 * @return - the encrypted ciphertext string
 */
unsigned char* AES::encrypt(const unsigned char* plainText)
{
	
	//TODO: 1. Dynamically allocate a block to store the ciphertext.
	//	2. Use AES_ecb_encrypt(...) to encrypt the text (please see the URL in setKey(...)
	//	and the aes.cpp example provided.
	// 	3. Return the pointer to the ciphertext

	unsigned char * enc_out = new unsigned char[17];
	memset(enc_out, 0, 17);
    AES_ecb_encrypt(plainText, enc_out, &enc_key, AES_ENCRYPT);
	return NULL;	
}

/**
 * Decrypts a string of ciphertext
 * @param cipherText - the ciphertext
 * @return - the plaintext
 */
unsigned char* AES::decrypt(const unsigned char* cipherText)
{
	unsigned char * dec_out = new unsigned char[17];
	memset(dec_out, 0, 17);
    AES_ecb_encrypt(cipherText, dec_out, &dec_key, AES_DECRYPT);
	//TODO: 1. Dynamically allocate a block to store the plaintext.
	//	2. Use AES_ecb_encrypt(...) to decrypt the text (please see the URL in setKey(...)
	//	and the aes.cpp example provided.
	// 	3. Return the pointer to the plaintext
		
	return NULL;
}



