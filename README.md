# Creating Certificate and Private key
```
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout mycert.pem -out mycert.pem
```
# Compile
```
gcc -Wall -o main main.c -L/usr/lib -lssl -lcrypto
```
# Start
Server must be started with root rights
```
sudo ./main
```
## Encrypting data
![image](https://github.com/KachkoBart/openssl/assets/39676602/5426870d-71e0-45f9-b735-848ca3ea0aaa)

## settings for WireShark to decrypt
Edit -> Preferences -> Protocols -> TLS.
Then Edit RSA keys list and add file mycert.pem.
Then like in the photo:   
![image](https://github.com/KachkoBart/openssl/assets/39676602/3d9b9dc1-3594-485d-94bb-261ca0ee0b6b)
## Decryption
### WireShark
Start WireShark, then start sever, then client, choose in Wireshark. Choose 'Decrypted TLS' at the bottom of the photo
![image](https://github.com/KachkoBart/openssl/assets/39676602/982a7c83-48fe-4e88-bbf2-758c5331f824)
### Log file
You also can see log file 'my_log.txt':
![image](https://github.com/KachkoBart/openssl/assets/39676602/1b4f6196-a443-4062-ad30-7462bd1c0572)


