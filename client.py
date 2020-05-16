# client.py

import os, sys, getopt, time, getpass
from netinterface import network_interface
from security import sessionAuth
from security import secureChannel

NET_PATH = './network/'
KEY_PATH = './keys/'
OWN_ADDR = None
operation = 'com'
pubkeyfilename = 'pubkey'
privkeyfilename = 'privkey'

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hkp:a:x:y:', longopts=['help', 'kpg', 'path=', 'addr=', 'pubkeyname', 'privkeyname'])
except getopt.GetoptError:
    print('Usage:')
    print('  - RSA key pair generation:')
    print('    python client.py -k -a <own addr> -x <pubkeyfilename> -y <privkeyfilename>')
    print('  - launch client:') 
    print('    python client.py -p <network path> -a <own addr>')
    sys.exit(1)

for opt, arg in opts:
    if opt in ('-h','--help'):
        print('Usage:')
        print('  - RSA key pair generation:')
        print('    python client.py -k -a <own addr> -x <pubkeyfilename> -y <privkeyfilename>')
        print('  - launch client:')
        print('    python client.py -p <network path> -a <own addr>')
        sys.exit(0)
    elif opt in ('-k', '--kpg'):
        operation = 'kpg'
    elif opt in ('-x', 'pubkeyname'):
        pubkeyfilename = arg
    elif opt in ('-y', 'privkeyname'):
        privkeyfilename = arg
    elif opt in ('-p', '--path'):
        NET_PATH = arg
    elif opt in ('-a', '--addr'):
        OWN_ADDR = arg
    
if operation not in ('com', 'kpg'):
    print('Error: Operation does not exist.')
    sys.exit(1)  
    
if not os.access(KEY_PATH, os.F_OK) and operation!='kpg':
	print('Error: Cannot access path ' + KEY_PATH)
	sys.exit(1)
    
if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if not os.access(NET_PATH, os.F_OK):
	print('Error: Cannot access path ' + NET_PATH)
	sys.exit(1)
    
if (not OWN_ADDR) and (operation == 'com' or operation == 'kpg'):
    print('Error: Network address is missing.')
    sys.exit(1)

if len(OWN_ADDR) > 1: OWN_ADDR = OWN_ADDR[0]

if OWN_ADDR not in network_interface.addr_space:
	print('Error: Invalid address ' + OWN_ADDR)
	sys.exit(1)
    
if operation == 'kpg':
    authObj = sessionAuth()
    passphrase = getpass.getpass('Enter a passphrase to protect the saved private key: ')
    authObj.keypairGeneration(pubkeyfilename, privkeyfilename, KEY_PATH, OWN_ADDR, passphrase)
    sys.exit(0)
     
# main loop
print('Client started...')
netif = network_interface(NET_PATH, OWN_ADDR)
authObj = sessionAuth()
authenticated = False
serverAddr = input("Server address: ")
passphrase = getpass.getpass('Enter password: ')
sc = secureChannel()

while True:
    if not authenticated:
        # auth process
        pubkeyfile = KEY_PATH+serverAddr+'/'+ pubkeyfilename + '.pem'
        privkeyfile = KEY_PATH+OWN_ADDR+'/'+ privkeyfilename + '.pem'
        initial = OWN_ADDR + str(authObj.snd)
        netif.send_msg(serverAddr, initial.encode('utf-8'))
        status, rcvMsg = netif.receive_msg(blocking=True)
        if rcvMsg.decode('utf-8')=='nope':
            print("Channel occupied.")
            sys.exit(1)
        authObj.digestServer(rcvMsg, OWN_ADDR, serverAddr, pubkeyfile)
        encodedSig = authObj.generateSig(OWN_ADDR, serverAddr, privkeyfile, 'toServer', passphrase)
        if not encodedSig:
            netif.send_msg(serverAddr, 'exit'.encode('utf-8'))
            sys.exit(1)
        sndMsg = OWN_ADDR.encode('utf-8')+b'\n'+encodedSig
        netif.send_msg(serverAddr, sndMsg)
        authObj.generateKey()
        authenticated = True
        print("Login Success.")
    else:
        sndMsg = input('->>>: ')
        if sndMsg[0:3]=='LGO':
            print("Disconnected.")
            sndMsg = sndMsg[0:3] + ',' + sndMsg[4:]
            sndMsg = sc.encryption(sndMsg.encode('utf-8'), authObj.key)
            sndMsg = OWN_ADDR.encode('utf-8')+sndMsg
            netif.send_msg(serverAddr, sndMsg)
            sys.exit(0)
        sndMsg = sndMsg[0:3] + ',' + sndMsg[4:]
        sndMsg = sc.encryption(sndMsg.encode('utf-8'), authObj.key)
        sndMsg = OWN_ADDR.encode('utf-8')+sndMsg
        netif.send_msg(serverAddr, sndMsg)
        status, rcvMsg = netif.receive_msg(blocking=True)
        rcvMsg = sc.decryption(rcvMsg, authObj.key)
        print(rcvMsg.decode('utf-8'))




