#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include "libtomcrypt-develop/src/headers/tomcrypt.h"

#define KEY_SIZE 32 //keysize in bytes
static const char magicNumber[] = {0xbe, 0xbe, 0xbe, 0xbe};//magick number to add in header
//function to check if path i directory or not
int isPathDirectory(char *path) 
{
   struct stat statbuf;
   if (stat(path, &statbuf) != 0)
       return 0;
   return S_ISDIR(statbuf.st_mode);
}
void printHeader(char* header)
{
	printf("Printing the header on encryption completion\n");

   	for(int i = 0; i < 16; i++)
   	{
   		printf("%02hhx", header[i]);
   	}
   	printf("\n");
}

//handles Arguments passed to executeble and returns 1 only when : 
//file to encypt exists and can be readed
//and directory to save encrypted file exist
//and key is valid
char handleArguments(int argc, char *argv[], FILE **binaryTOEncryptOut, char** dirTosaveFileOut, unsigned char** encrKeyOut)
{
	if(argc == 2)
	{
		if(strcmp(argv[1], "-h") == 0)//check if user wants to read help
		{
			printf("help:\n to use this programm pass it as a first argument path to file which will be encripted\n second argument path to directory where encrypted and then decrypted files will be saved\n third argument must be a key for encryption/decryption it should be 256 bit(32 byte) long and consist of hexidecimal digits\n after that CRC32 of original file and encrypted than decrypted files will be compared\n");
			return 0;	
		}
		else
		{
			printf("invalid argument");
			return 0;
		}
	}
	else if(argc == 4)
	{
		if((*binaryTOEncryptOut = fopen(argv[1], "r")) != NULL)//check if we can read suplied file
		{
			

			//
			if(mkdir(argv[2], 0700) == 0 || errno == EEXIST)
			{
				if (!isPathDirectory(argv[2]))//check if directory exist
				{
					printf("directory was not created becouse file with same name exist");
					return 0;
				}
				else
				{

					*dirTosaveFileOut = (char*)malloc(strlen(argv[2]) + 1);
					memset(*dirTosaveFileOut, '\0', strlen(argv[2]) + 1);
					strncpy(*dirTosaveFileOut, argv[2], strlen(argv[2]));



					if(strlen(argv[3]) == 64)//check if key length is valid
					{
						*encrKeyOut = (unsigned char*)malloc(KEY_SIZE);
						memset(*encrKeyOut, '\0', KEY_SIZE);


						for(unsigned int i = 0; i < KEY_SIZE; i++)
						{

							if(isxdigit(argv[3][i * 2]) != 0 && isxdigit(argv[3][(i * 2) + 1]) != 0)//check if evry char in key is hexidecimal digit
							{
								sscanf(&argv[3][i * 2], "%2hhx", &(*encrKeyOut)[i]);
							}
							else
							{
								printf("Invalid key, key must contain only hexidecimal values");
								return 0;
							}
						}

						
						//strncpy(*encrKeyOut, argv[3], strlen(argv[3]));

						return 1;
					}
					else
					{
						printf("Invalid key size, must be 32 bytes long");
						return 0;
					}

				}

    			
			}
			else
			{
				printf("Error: %s : \"%s\"\n", strerror(errno), argv[1]);//notify user why directory can not be created
				return 0;
			}

		}
		else
		{
			printf("Error: %s : \"%s\"\n", strerror(errno), argv[1]);//notify user why file was not opened
			return 0;
		}
	}
	else//user run programm with invalid number of arguments
	{
		printf("Not valid number of arguments: %d\n", argc);
		printf("Please consider to run programm with \"-h\" argument for help");
		return 0;
	}
}


char encryptFileAndSave(FILE *binaryTOEncrypt, 
	symmetric_key skey, 
	char *dirToSaveFile, 
	unsigned char **encryptedDataOut, 
	unsigned long long *encryptedDataLengthOut, 
	unsigned long long *originalFileDataLengthOut, 
	unsigned char* crcToCompareOut)
{
	unsigned long long fSize = 0;
	unsigned char* fileBytes = NULL;
	unsigned char* encryptedDataToSave = NULL;
	unsigned char crcOut[4];
	crc32_state ctx;
	int status;
	FILE *fPtr;

	if(fseek(binaryTOEncrypt, 0, SEEK_END) == 0)
	{
		fSize = ftell(binaryTOEncrypt);
		if(fSize != -1L)
		{
			rewind(binaryTOEncrypt);
			fileBytes = (unsigned char *)malloc(fSize);
			if(fileBytes != NULL)
			{
				fread(fileBytes, fSize, 1, binaryTOEncrypt);

				*originalFileDataLengthOut = fSize;

				crc32_init(&ctx);
   				crc32_update(&ctx, fileBytes, fSize);
   				crc32_finish(&ctx, crcOut, 4);
   				memcpy(crcToCompareOut, crcOut, 4);

				if(fSize % 16 != 0)
				{
					fSize += (16 - (fSize % 16));//if fSize % 16 !=0 AES will add padding we need to be aware of that
				}

				*encryptedDataOut = (unsigned char *)malloc(fSize);
				if(*encryptedDataOut != NULL)
				{
					memset(*encryptedDataOut, '\0', fSize);

					for(unsigned long i = 0; i < (fSize / 16); i++)
					{
						status = aes_ecb_encrypt(fileBytes + (i * 16), *encryptedDataOut + (i * 16), &skey);
						if(status != CRYPT_OK)
						{
							printf("File encrypt error: %s: %s\n", error_to_string(status));
							free(fileBytes);
							return 0;
						}
					}
					*encryptedDataLengthOut = fSize;

   					


   					//fSize += (fSize % 16);//if fSize % 16 !=0 AES will add padding we need to be ready


   					encryptedDataToSave = (unsigned char *)malloc(4 + sizeof(unsigned long long) + 4 + fSize);
   					if(encryptedDataToSave != NULL)
   					{

   						memset(encryptedDataToSave, '\0', 4 + 4 + sizeof(unsigned long long) + fSize);

   						memcpy(encryptedDataToSave, magicNumber, 4);
   						memcpy(encryptedDataToSave + 4, crcOut, 4);
   						memcpy(encryptedDataToSave + 4 + 4, &fSize, sizeof(unsigned long long));
   						memcpy(encryptedDataToSave + 4 + 4 + sizeof(unsigned long long), *encryptedDataOut, fSize);

   						
   						printHeader(encryptedDataToSave);

    					char pathFile[PATH_MAX];
    					sprintf(pathFile, "%s\\encryptedBinaryImage", dirToSaveFile);

    					if((fPtr = fopen(pathFile, "w")) != NULL)
    					{
    						fseek(fPtr, 0, SEEK_CUR);
    						fwrite(encryptedDataToSave, 4 + 4 + sizeof(unsigned long long) + fSize, 1, fPtr);

    						free(fileBytes);
    						free(encryptedDataToSave);
    						fclose(fPtr);
    						return 1;
    					}
    					else
						{
							printf("Error creating file: %s at path: \"%s\"\n", strerror(errno), pathFile);//notify user why file was not created
							free(fileBytes);
							return 0;
						}

   					}
   					else
   					{
   						printf("Error allocating memory for encrypted file to save: \n");
   						free(fileBytes);
   						return 0;
   					}

				}
				else
				{
					printf("Error allocating memory for encrypted data: \n");
					free(fileBytes);
					return 0;
				}
			}
			else
			{
				printf("Error allocating memory for file: \n");
				return 0;
			}

		}
		else
		{
			printf("Error when getting file size: %s \n", strerror(errno));
			return 0;
		}
	}
	else
	{
		printf("Error seeking end of file: \n");
		return 0;
	}
}

char decryptAndCompareCrc(unsigned char* encryptedData, unsigned long long ecryptedDataLength, unsigned long long originalFileDataLength, symmetric_key skey, unsigned char* oldCrc, char *dirToSaveFile)
{
	unsigned char crcOut[4];
	crc32_state ctx;
	int status;
	unsigned char* decryptedData = (unsigned char *)malloc(ecryptedDataLength);
	FILE* fPtr;

	
	if(decryptedData != NULL)
	{
		memset(decryptedData, '\0', ecryptedDataLength);
	

		for(unsigned long i = 0; i < (ecryptedDataLength / 16); i++)
		{
			status = aes_ecb_decrypt(encryptedData + (i * 16), decryptedData + (i * 16), &skey);
			if(status != CRYPT_OK)
			{
				printf("File decrypt error: %s: %s\n", error_to_string(status));
				return 0;
			}
		}


    	char pathFile[PATH_MAX];
    	sprintf(pathFile, "%s\\dectyptedBinaryImage", dirToSaveFile);

    	if((fPtr = fopen(pathFile, "w")) != NULL)
    	{
    		fseek(fPtr, 0, SEEK_CUR);
    		fwrite(decryptedData, originalFileDataLength, 1, fPtr);

    		fclose(fPtr);
    	}
    	else
		{
			printf("Error creating file: %s at path: \"%s\"\n", strerror(errno), pathFile);//notify user why file was not created
		}


		crc32_init(&ctx);
   		crc32_update(&ctx, decryptedData, originalFileDataLength);
   		crc32_finish(&ctx, crcOut, 4);

   		printf("comparing CRCs");

   		if(memcmp(oldCrc, crcOut, 4) == 0)
   		{
   			printf("CRC of file before encription and CRC of same file after encription and decription are equal");
   			free(decryptedData);
   			return 1;
   		}

   		printf("CRCa are not equal, something went wrong");
   		free(decryptedData);
		return 0;
	}
	else
	{
		printf("Error allocating memory for decrypted data: \n");
		return 0;
	}
}

int main(int argc, char **argv) 
{

	FILE* binaryTOEncrypt;
	char* dirToSaveFile = NULL;
	unsigned char* encrKey = NULL;
	unsigned char* fileBytes = NULL;
	unsigned char* fileEncryptedBytes = NULL;
	unsigned char* fileDecryptedBytes = NULL;
	unsigned char crcFromEncrypted[4];
	unsigned long long encryptedDataSize = 0;
	unsigned long long originalFileDataLength = 0;


	if(handleArguments(argc, argv, &binaryTOEncrypt, &dirToSaveFile, &encrKey) == 1)
	{
		symmetric_key skey;
    	int keysize = KEY_SIZE;
    	int status;

    	status = aes_keysize(&keysize);
    	status = aes_setup(encrKey, KEY_SIZE, 0, &skey);


		if(encryptFileAndSave(binaryTOEncrypt, skey, dirToSaveFile, &fileEncryptedBytes, &encryptedDataSize, &originalFileDataLength, crcFromEncrypted) == 1)
		{
			decryptAndCompareCrc(fileEncryptedBytes, encryptedDataSize, originalFileDataLength, skey, crcFromEncrypted, dirToSaveFile);
			free(fileEncryptedBytes);
		}


    	fclose(binaryTOEncrypt);
    	free(fileBytes);
		free(dirToSaveFile);
		free(encrKey);
	}

	

	return  0;
}