#include "DES.h"
/**
 * Sets the key to use
 * @param key - the key to use
 * @return - True if the key is valid and False otherwise
 */
bool DES::setKey(const unsigned char* keyArray)
{
	/**
	 * First let's covert the char string
	 * into an integer byte string
	 */
	
	
	/* The key error code */
	int keyErrorCode = -1;

	/* A single byte */
	unsigned char singleByte = 0;	
	
	/* The key index */
	int keyIndex = 0;
	
	/* The DES key index */
	int desKeyIndex = 0;
		
	/* Go through the entire key character by character */
	while(desKeyIndex != 8)
	{
		/* Convert the key if the character is valid */
		if((this->des_key[desKeyIndex] = twoCharToHexByte(keyArray + keyIndex)) == 'z')
			return false;
		
		/* Go to the second pair of characters */
		keyIndex += 2;	
		
		/* Increment the index */
		++desKeyIndex;
	}
	
	fprintf(stdout, "DES KEY: ");
	
	/* Print the key */
	for(keyIndex = 0; keyIndex < 8; ++keyIndex)
		fprintf(stdout, "%x", this->des_key[keyIndex]);
	
	fprintf(stdout, "\n");	
	
	
	/* Set the encryption key */
    if ((keyErrorCode = DES_set_key_checked(&des_key, &key)) != 0)
	{
		fprintf(stderr, "\nkey error %d\n", keyErrorCode);
		
		return false;
	}
	
	/* All is well */	
	return true;
}

/**	
 * Encrypts a plaintext block 8 characters at a time
 * @param plaintext - the plaintext string
 * @return - the encrypted ciphertext string
 */
unsigned char* DES::encrypt(const unsigned char* plaintext)
{
	unsigned char cipherText[9]; //ciphertext block
	memset(cipherText, 0, 9);

    unsigned char plaintextCopy[9];
    memcpy(&plaintext, plaintextCopy, sizeof(plaintextCopy));

	DES_LONG block[2];
    block[0] = ctol(plaintextCopy);
    block[1] = ctol(plaintextCopy + 4);
	
    DES_encrypt1(block, &key, ENC);
	

	ltoc(block[0], cipherText);
	ltoc(block[1], cipherText + 4);

	//store the block of ciphertext in a buffer that will be written to the file
	unsigned char * ciphertextBlockPtr = cipherText;

	return ciphertextBlockPtr;
}

/**
 * Decrypts a string of ciphertext
 * @param ciphertext - the ciphertext
 * @return - the plaintext
 */
unsigned char* DES::decrypt(const unsigned char* ciphertext)
{
	//LOGIC:
	// Same logic as encrypt(), except in step 4. decrypt instead of encrypting
	unsigned char plainText[9]; //ciphertext block
	memset(plainText, 0, 9);

    unsigned char ciphertextCopy[9];
    memcpy(&ciphertext, ciphertextCopy, sizeof(ciphertextCopy));

	DES_LONG block[2];
    block[0] = ctol(ciphertextCopy);
    block[1] = ctol(ciphertextCopy + 4);

    DES_encrypt1(block, &key, DEC);


	ltoc(block[0], plainText);
	ltoc(block[1], plainText + 4);

	//store the block of ciphertext in a buffer that will be written to the file
	unsigned char * ciphertextBlockPtr = plainText;

	return ciphertextBlockPtr;
}

/**
 * Converts an array of 8 characters
 * (i.e. 4 bytes/32 bits)
 * @param c - the array of 4 characters (i.e. 1-byte per/character
 * @return - the long integer (32 bits) where each byte
 * is equivalent to one of the bytes in a character array
 */
DES_LONG DES::ctol(unsigned char *c) 
{
        /* The long integer */
	DES_LONG l;
        
	l =((DES_LONG)(*((c)++)));
        l = l | (((DES_LONG)(*((c)++)))<<8L);
        l = l | (((DES_LONG)(*((c)++)))<<16L);
        l = l | (((DES_LONG)(*((c)++)))<<24L);
        return l;
};


/** 
 * Converts a long integer (4 bytes = 32 bits)
 * into an array of 8 characters.
 * @param l - the long integer to convert
 * @param c - the character array to store the result
 */
void DES::ltoc(DES_LONG l, unsigned char *c) 
{
        *((c)++)=(unsigned char)(l&0xff);
        *((c)++)=(unsigned char)(((l)>> 8L)&0xff);
        *((c)++)=(unsigned char)(((l)>>16L)&0xff);
        *((c)++)=(unsigned char)(((l)>>24L)&0xff);
}

/**
 * Converts a character into a hexidecimal integer
 * @param character - the character to convert
 * @return - the converted character, or 'z' on error
 */
unsigned char DES::charToHex(const char& character)
{
	/* Is the first digit 0-9 ? */	
	if(character >= '0' && character <= '9')	
		/* Convert the character to hex */
		return character - '0';
	/* It the first digit a letter 'a' - 'f'? */
	else if(character >= 'a' && character <= 'f')
		/* Conver the cgaracter to hex */
		return (character - 97) + 10;	
	/* Invalid character */
	else return 'z';
}

/**
 * Converts two characters into a hex integers
 * and then inserts the integers into the higher
 * and lower bits of the byte
 * @param twoChars - two charcters representing the
 * the hexidecimal nibbles of the byte.
 * @param twoChars - the two characters
 * @return - the byte containing having the
 * valud of two characters e.g. string "ab"
 * becomes hexidecimal integer 0xab.
 */
unsigned char DES::twoCharToHexByte(const unsigned char* twoChars)
{
	/* The byte */
	unsigned char singleByte;
	
	/* The second character */
	unsigned char secondChar;

	/* Convert the first character */
	if((singleByte = charToHex(twoChars[0])) == 'z') 
	{
		/* Invalid digit */
		return 'z';
	}
	
	/* Move the newly inserted nibble from the
	 * lower to upper nibble.
	 */
	singleByte = (singleByte << 4);
	
	/* Conver the second character */
	if((secondChar = charToHex(twoChars[1])) == 'z')
		return 'z'; 
	
	/* Insert the second value into the lower nibble */	
	singleByte |= secondChar;

	return singleByte;
}


