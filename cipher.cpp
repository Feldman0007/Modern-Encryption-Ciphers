#include <string>
#include <iostream>
#include <fstream>
#include "CipherInterface.h"
#include "AES.h"
#include "DES.h"
#include <stdio.h>
#include <stdlib.h>
#include <cmath>

using namespace std;

/*Case insensitive string comparison helper function used in processing command line arguments*/
bool iequals(const string&, const string&);
/*Error checking to see if we have correctly set up an instance of our cipher*/
void assertValidCipherAssignment(const CipherInterface*);
/*Validate the key against the type of cypher selected and assign the cipher's key*/
void validateAndSetKey(CipherInterface* const, const string&);
/*Perform either encryption or decryption and write to output file*/
void performOperation(CipherInterface* const, const string&, const string&, const string&, const bool&);

int main(int argc, char** argv)
{

    //Testing
    //CipherInterface* cipher = new DES();
    //CipherInterface* cipher1 = new AES();

    //validateAndSetKey(cipher, "0123456789abcdef");
    //validateAndSetKey(cipher1, "00112233445566778899aabbccddeeff");

    //performOperation(cipher, "enc", "small.txt", "desencrypt.txt", false);
    //performOperation(cipher1, "enc", "small.txt", "aesencrypt.txt", true);;

    //performOperation(cipher, "enc", "big.txt", "desencrypt.txt", false);
    //performOperation(cipher1, "enc", "big.txt", "aesencrypt.txt", true);

    //performOperation(cipher, "dec", "desencrypt.txt", "desdecrypt.txt", false);
    //performOperation(cipher1, "dec", "csencrypt.txt", "aesdecrypt.txt", true);

    //return 0;

	/*Make sure we have only 5 command line arguments before moving forward*/
    if (argc != 6)
    {
        cout << "cipher.exe only accepts 5 arguments: <CIPHER NAME> <KEY> <ENC/DEC> <INPUTFILE> <OUTPUT FILE>" << endl;
        exit(-1);
    }

    /*Variables used to parse the command line argument and execute the ciphers dynamically*/
    string cipherName = argv[1];
    string key = argv[2];
    string operation = argv[3];
    string inputFileName = argv[4];
    string outputFileName = argv[5];

    CipherInterface* cipher = NULL; /*pointer to an instance of our cipher*/
    bool isAES; //false = DES, true = AES

    if (iequals(cipherName, "AES"))
    {
        cipher = new AES();
        isAES = true;
        if (iequals(operation, "ENC"))
        {
            key.insert(0, 1, '1');
        }
        else
        {
            key.insert(0, 1, '0');
        }
    }
    else if (iequals(cipherName, "DES"))
    {
        isAES = false;
        cipher = new DES();
    }
    else
    {
        assertValidCipherAssignment(cipher);
    }

    validateAndSetKey(cipher, key);
    performOperation(cipher, operation, inputFileName, outputFileName, isAES);

    return 0;
}

void validateAndSetKey(CipherInterface* const cipher, const string& key)
{
	bool validKey = cipher->setKey((const unsigned char *)key.c_str());
	if (!validKey)
	{
		cout << "This key is not valid for the selected cipher!" << endl;
		exit(-1);
	}
}

void performOperation(CipherInterface* const cipher, const string& operation, const string& inputFilename, const string& outputFilename, const bool& isAES)
{
    const char* c_in_filename = inputFilename.c_str();
    const char* c_out_filename = outputFilename.c_str();
    FILE *fileReader;
    FILE *fileWriter;
	
	/*Encrypt or decrypt block by block*/
	if (iequals(operation, "ENC"))
	{
        fileReader = fopen(c_in_filename, "rb");
        fileWriter = fopen(c_out_filename, "wb");
		//Depending on the algorithm used we will be encrypting/decrypting using different block sizes
		if (isAES) 
		{
			bool doneEncrypting = false;

			while (!doneEncrypting) 
            {
                unsigned char plaintextBlock[16];
                memset(plaintextBlock,'\0', 16); //assume padding

                uint8_t charsReadSuccessfully = fread(plaintextBlock, 1, 16, fileReader);
                if(charsReadSuccessfully != 16) //If block is incomplete
                {
                    unsigned char * ciphertextBlockPtr;
                    uint8_t charsWroteSuccessfully;
                    uint8_t charsRemaining = 16 - charsReadSuccessfully; //Get remaining characters in case block is unfinished
                    if(charsRemaining != 16) // If charsRemaining is 16, then the block is empty anyways so don't bother with padding
                    {
                        ciphertextBlockPtr = cipher->encrypt(plaintextBlock);  //encrypt padded block
                        charsWroteSuccessfully = fwrite(ciphertextBlockPtr, 1, 16, fileWriter); //write the last block to file
                        delete [] ciphertextBlockPtr;
                        if(charsWroteSuccessfully != 16)
                        {
                            cout << "Something may be up with file writing AES ENC";
                        }
                    }
                    else
                    {
                        charsRemaining = 0;
                    }
                    memset(plaintextBlock,'\0', 15); //Create padding block that will give us information on the amount of padding used.
                    plaintextBlock[15] = charsRemaining; //Set the last byte to the amount of padding used is the last
                    ciphertextBlockPtr = cipher->encrypt(plaintextBlock);  //encrypt padding info block
                    charsWroteSuccessfully = fwrite(ciphertextBlockPtr, 1, 16, fileWriter);//write padding info block
                    delete [] ciphertextBlockPtr; //free memory
                    if(charsWroteSuccessfully != 16)
                    {
                        cout << "Something may be up with file writing AES ENC";
                    }
                    doneEncrypting = true; //We are done encrypting
                }
                else //block is full, encrypt normally
                {
                    unsigned char * ciphertextBlockPtr = cipher->encrypt(plaintextBlock); //encrypt block
                    uint8_t charsWroteSuccessfully = fwrite(ciphertextBlockPtr, 1, 16, fileWriter);
                    delete [] ciphertextBlockPtr;
                    if(charsWroteSuccessfully != 16)
                    {
                        cout << "Something may be up with file writing AES ENC";
                    }
                }
            }
		}
		else //DES
		{
			bool doneEncrypting = false;

			while (!doneEncrypting)
			{
                unsigned char plaintextBlock[8];
                memset(plaintextBlock,'\0', 8);

                uint8_t charsReadSuccessfully = fread(plaintextBlock, 1, 8, fileReader);
                if(charsReadSuccessfully != 8)
                {
                    unsigned char * ciphertextBlockPtr;
                    uint8_t charsWroteSuccessfully;
                    uint8_t charsRemaining = 8 - charsReadSuccessfully;
                    if(charsRemaining != 8)
                    {
                        ciphertextBlockPtr = cipher->encrypt(plaintextBlock);
                        charsWroteSuccessfully = fwrite(ciphertextBlockPtr, 1, 8, fileWriter);
                        delete [] ciphertextBlockPtr;
                        if(charsWroteSuccessfully != 8)
                        {
                            cout << "Something may be up with file writing DES ENC";
                        }
                    }
                    else
                    {
                        charsRemaining = 0;
                    }
                    memset(plaintextBlock,'\0', 7);
                    plaintextBlock[7] = charsRemaining;
                    ciphertextBlockPtr = cipher->encrypt(plaintextBlock);
                    charsWroteSuccessfully = fwrite(ciphertextBlockPtr, 1, 8, fileWriter);
                    delete [] ciphertextBlockPtr;
                    if(charsWroteSuccessfully != 8)
                    {
                        cout << "Something may be up with file writing DES ENC";
                    }
                    doneEncrypting = true;
                }
                else
                {
                    unsigned char * ciphertextBlockPtr = cipher->encrypt(plaintextBlock);
                    uint8_t charsWroteSuccessfully = fwrite(ciphertextBlockPtr, 1, 8, fileWriter);
                    delete [] ciphertextBlockPtr;
                    if(charsWroteSuccessfully != 8)
                    {
                        cout << "Something may be up with file writing DES ENC";
                    }
                }
			}
		}
        fclose(fileReader);
        fclose(fileWriter);
	}
	else if (iequals(operation, "DEC"))
	{
        fileReader = fopen(c_in_filename, "rb");
        fileWriter = fopen(c_out_filename, "wb");
        fseek (fileReader , 0 , SEEK_END);
        long fileSize = ftell(fileReader); //calculate file size
        rewind(fileReader);

		if (isAES)
		{
            long numBlocksToDecrypt =  ceil(fileSize / 16.0); //n = (size -1) / blocksize

            for(int i = 0; i < numBlocksToDecrypt; i++)
			{
                unsigned char ciphertextBlock[16];
                memset(ciphertextBlock,'\0', 16);
                uint8_t charsReadSuccessfully = fread(ciphertextBlock, 1, 16, fileReader);
                if(charsReadSuccessfully != 16)
                {
                    cout << "Issue reading file during AES DEC\n";
                }

                unsigned char * plaintextBlockPtr = cipher->decrypt(ciphertextBlock);

                if(i == numBlocksToDecrypt - 2) //If we're on the final block before the padding block
                {
                    unsigned char encryptedPaddingInfoBlock[16]; //We are going to look ahead at the padding block to see how we'll handle the last legit block
                    charsReadSuccessfully = fread(encryptedPaddingInfoBlock, 1, 16, fileReader); //read the next block which should be the encrypted padding information block
                    if(charsReadSuccessfully != 16)
                    {
                        cout << "Issue reading padding block during AES DEC\n";
                    }
                    unsigned char * paddingInfoBlock = cipher->decrypt(encryptedPaddingInfoBlock); //decrypt that block to get padding information

                    int paddingNumber = paddingInfoBlock[15];
                    delete [] paddingInfoBlock; //done using, free memory
                    if(paddingNumber != 0)//If last byte of padding block is 0 or null, padding was not used.
                    {
                        int8_t charsWroteSuccessfully = fwrite(plaintextBlockPtr, 1, 16 - paddingNumber, fileWriter); //Padding was used so write back the non-padded portion of the last block
                        delete [] plaintextBlockPtr;
                        if(charsWroteSuccessfully != 16 - paddingNumber)
                        {
                            cout << "Issue writing final block to file during AES DEC\n";
                        }
                        break;
                    }
                    else
                    {
                        int8_t charsWroteSuccessfully = fwrite(plaintextBlockPtr, 1, 16, fileWriter); //Padding was not used, so write the last block in whole
                        delete [] plaintextBlockPtr;
                        if(charsWroteSuccessfully != 16 )
                        {
                            cout << "Issue writing a block to file during AES DEC\n";
                        }
                        break;
                    }
                }
                else
                {
                    fwrite(plaintextBlockPtr, 1, 16, fileWriter);
                    delete [] plaintextBlockPtr;
                }
			}
		}
		else //DES
		{
            long numBlocksToDecrypt =  ceil(fileSize / 8.0); //n = (size -1) / blocksize (the -1 is to account for that last byte).

            for(int i = 0; i < numBlocksToDecrypt; i++)
            {
                unsigned char ciphertextBlock[8];
                memset(ciphertextBlock,'\0', 8);
                uint8_t charsReadSuccessfully = fread(ciphertextBlock, 1, 8, fileReader);
                if(charsReadSuccessfully != 8)
                {
                    cout << "Issue reading file during DES DEC\n";
                }

                unsigned char * plaintextBlockPtr = cipher->decrypt(ciphertextBlock);

                if(i == numBlocksToDecrypt - 2) //If we're on the second to last block
                {
                    unsigned char encryptedPaddingInfoBlock[8];
                    charsReadSuccessfully = fread(encryptedPaddingInfoBlock, 1, 8, fileReader); // read the next block which should be the encrypted padding information block
                    if(charsReadSuccessfully != 8)
                    {
                        cout << "Issue reading file during DES DEC\n";
                    }
                    unsigned char * paddingInfoBlock = cipher->decrypt(encryptedPaddingInfoBlock); //decrypt that block to get padding information

                    int paddingNumber = paddingInfoBlock[7];
                    delete [] paddingInfoBlock;
                    if(paddingNumber != 0)//If last byte of padding block is not 0 or null, padding was used.
                    {
                        uint8_t charsWroteSuccessfully = fwrite(plaintextBlockPtr, 1, 8 - paddingNumber, fileWriter);
                        delete [] plaintextBlockPtr;
                        if(charsWroteSuccessfully != 8 - paddingNumber)
                        {
                            cout << "Issue writing final block to file during DES DEC\n";
                        }
                        break;
                    }
                    else
                    {
                        fwrite(plaintextBlockPtr, 1, 8, fileWriter);
                        delete [] plaintextBlockPtr;
                        break;
                    }
                }
                else
                {
                    fwrite(plaintextBlockPtr, 1, 8, fileWriter);
                    delete [] plaintextBlockPtr;
                }
            }
        }
        fclose(fileReader);
        fclose(fileWriter);
	}
	else
	{
		cout << "This is not a valid operation!" << endl;
		exit(-1);
	}
}

bool iequals(const string& a, const string& b) //case insensitive comparison
{
	unsigned int sz = a.size();
	if (b.size() != sz)
		return false;
	for (unsigned int i = 0; i < sz; ++i)
		if (tolower(a[i]) != tolower(b[i]))
			return false;
	return true;
}

void assertValidCipherAssignment(const CipherInterface* cipher)
{
	/*Error checking*/
	if (!cipher)
	{
		fprintf(stderr, "ERROR [%s %s %d]: could not allocate memory\n",
			__FILE__, __FUNCTION__, __LINE__);
		exit(-1);
	}
    else
    {
        cout << "Undefined state!";
    }
}
