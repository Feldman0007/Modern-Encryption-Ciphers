#include "AES.h"

/**
 * Sets the key to use
 * @param key - the first byte of this represents whether
 * to encrypt or to decrypt. 00 means encrypt and any other
 * value to decrypt.  Then come the bytes of the 128-bit key
 * (should be 16 of them).
 * @return - True if the key is valid and False otherwise
 */
bool AES::setKey(const unsigned char* inputKey)
{
    bool success = true;

    unsigned char encORdec = inputKey[0];
    const unsigned char * aes_key = &inputKey[1];

    /* Set the encryption key */
    if (encORdec == '1')
	{

        if (AES_set_encrypt_key(aes_key, 128, &enc_key) != 0)
		{
			fprintf(stderr, "AES_set_encrypt_key() failed!\n");
			exit(-1);
		}
	}
    else if (encORdec == '0')
	{
        if (AES_set_decrypt_key(aes_key, 128, &dec_key) != 0)
		{
			fprintf(stderr, "AES_set_decrypt_key() failed!\n");
            success = false;
		}
    }
    else
    {
        fprintf(stderr, "First bit of key should either be a 1 or a 0 for Encrypt or Decrypt");
        success = false;
    }
    return success;
}

/**	
 * Encrypts a plaintext string
 * @param plaintext - the plaintext string
 * @return - the encrypted ciphertext string
 */
unsigned char* AES::encrypt(const unsigned char* plainText)
{
    unsigned char * cipherText = new unsigned char[17];
    memset(cipherText, 0, 17);
    AES_ecb_encrypt(plainText, cipherText, &enc_key, AES_ENCRYPT);
    return cipherText;
}

/**
 * Decrypts a string of ciphertext
 * @param cipherText - the ciphertext
 * @return - the plaintext
 */
unsigned char* AES::decrypt(const unsigned char* cipherText)
{
    unsigned char * plainText = new unsigned char[17];
    memset(plainText, 0, 17);
    AES_ecb_encrypt(cipherText, plainText, &dec_key, AES_DECRYPT);
    return plainText;
}



