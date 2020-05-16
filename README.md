# SecureFileTransferDemo
Encryption for the communication between client and server using RSA and AES

Introduction
------------
This application is intended to simulate file transfer between a user and a server.
Due to technical difficulty only one connection is allowed at a time.
The application has two programs: client.py and server.py.
DH with RSA signature is used for login and symmetric key establishment.
AES in GCM mode is used for secure channel encryption. 

How to use for the first time
-----------------------------
1. start network.py in commandline  
	`python network.py -p <NET_PATH> -a <addresses>`
	<NET_PATH> has to be a existing folder.

2. generate RSA keypairs for client and server  
	`python server.py -k -a <address> -x <public key filename> -y <private key filename>`
	`python client.py -k -a <address> -x <public key filename> -y <private key filename>`
-x and -y arguments are optional and are not recommended to use.  
client.py will need a password to protect private key, and the same password is used for login later

3. start server.py  
	`python server.py -p <NET_PATH> -a <address>`

4. start client.py  
	`python client.py -p <NET_PATH> -a <address>`
	
client.py will ask for server address and password  
If the password is correct then authentication protocol will start  
Once authentication is done and secure channel is established, you will see "->>>" as input indicator  
Type HLP for help
	
5. no more RSA key generations are required unless addresses are changed.

An example
----------
	python network.py -p './network/' -a 'ABCDE' --clean
	python server.py -k -a B
	python client.py -k -a A
	python server.py -p './network/' -a B
	python client.py -p './network/' -a A
