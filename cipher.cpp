#include <string>
#include <iostream>
#include <fstream>
#include "CipherInterface.h"
#include "AES.h"
#include "DES.h"
#include <iostream>
#include <vector>
#include <iomanip>

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

	////Testing
    CipherInterface* cipher = new DES();
	//CipherInterface* cipher1 = new AES();

    validateAndSetKey(cipher, "0123456789abcdef");
	//validateAndSetKey(cipher1, "00112233445566778899aabbccddeeff");

    performOperation(cipher, "enc", "small.txt", "desencrypt.txt", false);
    //performOperation(cipher1, "enc", "small.txt", "aesencrypt.txt", true);;

    //performOperation(cipher, "enc", "big.txt", "desencrypt.txt", false);
    //performOperation(cipher1, "enc", "big.txt", "aesencrypt.txt", true);

    performOperation(cipher, "dec", "desencrypt.txt", "desdecrypt.txt", false);
    //performOperation(cipher1, "dec", "csencrypt.txt", "aesdecrypt.txt", true);

    return 0;

	/*Make sure we have only 5 command line arguments before moving forward*/
//	if (argc != 6)
//	{
//		cout << "cipher.exe only accepts 5 arguments: <CIPHER NAME> <KEY> <ENC/DEC> <INPUTFILE> <OUTPUT FILE>" << endl;
//		exit(-1);
//	}

//	/*Variables used to parse the command line argument and execute the ciphers dynamically*/
//	string cipherName = argv[1];
//	string key = argv[2];
//	string operation = argv[3];
//	string inputFileName = argv[4];
//	string outputFileName = argv[5];

//	CipherInterface* cipher = NULL; /*pointer to an instance of our cipher*/
//	bool isAES = false; //false = DES, true = AES

//	if (iequals(cipherName, "AES"))
//	{
//		cipher = new AES();
//		isAES = true;
//		if (iequals(operation, "ENC"))
//		{
//			key.insert(0, 1, '1');
//		}
//		else
//		{
//			key.insert(0, 1, '0');
//		}
//	}
//	else if (iequals(cipherName, "DES"))
//	{
//		cipher = new DES();
//	}
//	else
//	{
//		assertValidCipherAssignment(cipher);
//	}

//	validateAndSetKey(cipher, key);
//	performOperation(cipher, operation, inputFileName, outputFileName, isAES);

//	return 0;
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
	ifstream fileReader;
	fileReader.open(inputFilename);
	if (fileReader.fail()) {
		cout << "Error opening input file!" << endl;
		exit(-1);
	}
	if (fileReader.peek() == std::ifstream::traits_type::eof())
	{
		cout << "Input file has no text!";
		exit(-1);
	}
	
	ofstream fileWriter;
	fileWriter.open(outputFilename);
	if (fileWriter.fail()) {
		cout << "Error opening output file!" << endl;
		exit(-1);
	}
	if (fileReader.peek() == std::ifstream::traits_type::eof())
	{
		cout << "Input file has no text!";
		exit(-1);
	}

	/*Encrypt or decrypt block by block*/
	if (iequals(operation, "ENC"))
	{
		//Depending on the algorithm used we will be encrypting/decrypting using different block sizes
		if (isAES) 
		{
			bool doneEncrypting = false;

			while (!doneEncrypting) 
			{
				unsigned char plaintextBlock[17]; //block of plaintext to encrypt
				unsigned char * plaintextBlockPtr = plaintextBlock; //used to pass block to encrypt function
				for (int i = 0; i < 16; i++)
				{
					if (!fileReader.eof())
					{
						plaintextBlock[i] = (unsigned char)fileReader.get();
					}
					else
					{
						plaintextBlock[i] = '0'; //If we have read the whole file but the block is not filled, start padding
						doneEncrypting = true; //we have reached the end of the file so we are done encrypting after this run
					}
				}
				plaintextBlock[16] = '\0';

				unsigned char * ciphertextBlockPtr = cipher->encrypt(plaintextBlockPtr); //encrypt block
				for (int i = 0; i < 16; i++)
				{
					fileWriter << ciphertextBlockPtr[i]; //write encrypted block to file
				}
			}
		}
		else //DES
		{
			bool doneEncrypting = false;

			while (!doneEncrypting)
			{
				unsigned char plaintextBlock[9];
				unsigned char * plaintextBlockPtr = plaintextBlock;
				for (int i = 0; i < 8; i++)
				{
					if (!fileReader.eof())
					{
						plaintextBlock[i] = (unsigned char)fileReader.get();
					}
					else
					{
						plaintextBlock[i] = '0';
						doneEncrypting = true;
					}
				}
				plaintextBlock[8] = '\0';

				unsigned char * ciphertextBlockPtr = cipher->encrypt(plaintextBlockPtr);
				for (int i = 0; i < 8; i++)
				{
                    fileWriter << ciphertextBlockPtr[i];
				}
			}
		}
		fileReader.close();
		fileWriter.close();
	}
	else if (iequals(operation, "DEC"))
	{
		if (isAES)
		{
			bool doneDecrypting = false;

			while (!doneDecrypting)
			{
				unsigned char ciphertextBlock[17];
				unsigned char * ciphertextBlockPtr = ciphertextBlock;
				for (int i = 0; i < 16; i++)
				{
					if (!fileReader.eof())
					{
						ciphertextBlock[i] = (unsigned char)fileReader.get();
					}
					else
					{
						ciphertextBlock[i] = '0';
						doneDecrypting = true;
					}
				}
				ciphertextBlock[16] = '\0';
				unsigned char * plaintextBlockPtr = cipher->encrypt(ciphertextBlockPtr);
				for (int i = 0; i < 16; i++)
				{
					fileWriter << plaintextBlockPtr[i];
				}
			}
		}
		else //DES
		{
			bool doneDecrypting = false;

			while (!doneDecrypting)
			{
				unsigned char ciphertextBlock[9];
				unsigned char * ciphertextBlockPtr = ciphertextBlock;
				for (int i = 0; i < 8; i++)
				{
					if (!fileReader.eof())
					{
						ciphertextBlock[i] = (unsigned char)fileReader.get();
					}
					else
					{
						ciphertextBlock[i] = '0';
						doneDecrypting = true;
					}
				}
				ciphertextBlock[8] = '\0';
				unsigned char * plaintextBlockPtr = cipher->encrypt(ciphertextBlockPtr);
				for (int i = 0; i < 8; i++)
				{
					fileWriter << plaintextBlockPtr[i];
				}
			}
		}
		fileReader.close();
		fileWriter.close();
	}
	else
	{
		fileReader.close();
		fileWriter.close();
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
}
