# encryptDecryp
Encryption and decryption of file using libtomcrypt-develop in cygwin

To compile it you will need gcc and compiled libtomcrypt-develop library near "encripDecriptImage.c" file
Than you can compile it with this comand:
gcc encripDecriptImage.c -L./libtomcrypt-develop -ltomcrypt -o execute.exe
