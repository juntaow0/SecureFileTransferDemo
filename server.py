# server.py

import os, sys, getopt, time, getpass
from netinterface import network_interface
from storage import serverFileSystem
from security import sessionAuth
from security import secureChannel

NET_PATH = './network/'
STORAGE_PATH = './storage/'
KEY_PATH = './keys/'
OWN_ADDR = None
operation = 'com'
pubkeyfilename = 'pubkey'
privkeyfilename = 'privkey'
passphrase = '114514'

def messageParsing(message):
    message = message.decode('utf-8')
    parts = message.split(',')
    op = parts[0]
    msg = parts[1]
    return op, msg

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hkp:s:a:x:y:', longopts=['help', 'kpg', 'path=', 'storage=','addr=','pubkeyname', 'privkeyname'])
except getopt.GetoptError:
    print('Usage:')
    print('  - RSA key pair generation:')
    print('    python server.py -k -a <own addr> -x <pubkeyfilename> -y <privkeyfilename>')
    print('  - launch server:')
    print('    python server.py -p <network path> -s <storage path> -a <own addr>')
    sys.exit(1)

for opt, arg in opts:
    if opt in ('-h','--help'):
        print('Usage:')
        print('  - RSA key pair generation:')
        print('    python server.py -k -a <own addr> -x <pubkeyfilename> -y <privkeyfilename>')
        print('  - launch server:')
        print('    python server.py -p <network path> -s <storage path> -a <own addr>')
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
    elif opt in ('-s', '--storage'):
        STORAGE_PATH = arg

if operation not in ('com', 'kpg'):
    print('Error: Operation does not exist.')
    sys.exit(1)  
if not os.access(KEY_PATH, os.F_OK) and operation!='kpg':
	print('Error: Cannot access path ' + KEY_PATH)
	sys.exit(1)

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'
if (STORAGE_PATH[-1] != '/') and (STORAGE_PATH[-1] != '\\'): STORAGE_PATH += '/'

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
    authObj.keypairGeneration(pubkeyfilename, privkeyfilename, KEY_PATH, OWN_ADDR, passphrase)
    sys.exit(0)

loginStatus = {}
for char in network_interface.addr_space:
    loginStatus[char] = False

addresses = list(loginStatus.keys())

# main loop
netif = network_interface(NET_PATH, OWN_ADDR)
filesys = serverFileSystem(STORAGE_PATH, addresses)
authObj = sessionAuth()
sc = secureChannel()
connected = False
cUser = None
timeStart = time.time()
print('Server started...')
while True:
    status, rcvMsg = netif.receive_msg(blocking=False)
    if status:
        netAddr = rcvMsg[0:1].decode('utf-8')
        if not loginStatus[netAddr]:
            if connected:
                netif.send_msg(netAddr, 'nope'.encode('utf-8'))
                continue
            # start DH exchange
            pubkeyfile = KEY_PATH+netAddr+'/'+ pubkeyfilename + '.pem'
            privkeyfile = KEY_PATH+OWN_ADDR+'/'+ privkeyfilename + '.pem'
            rcv = int(rcvMsg[1:].decode('utf-8'))
            authObj.rcv = rcv
            encodedSig = authObj.generateSig(netAddr, OWN_ADDR, privkeyfile, 'toUser', passphrase)
            sndMsg = str(authObj.snd).encode('utf-8')+b'\n'+encodedSig
            netif.send_msg(netAddr, sndMsg)
            status, rcvMsg = netif.receive_msg(blocking=True)
            if (rcvMsg.decode('utf-8')=='exit'):
                print("Malicious connection rejected.")
                continue
            authObj.digestUser(rcvMsg, netAddr, OWN_ADDR, pubkeyfile)
            authObj.generateKey()
            loginStatus[netAddr] = True
            connected = True
            cUser = netAddr
            print('User '+netAddr+ ' connected.')
            continue
        
        rcvMsg = sc.decryption(rcvMsg[1:], authObj.key)
        op, msg = messageParsing(rcvMsg)
        sndMsg = ''
        
        if op =='HLP': # help
            sndMsg = filesys.getHelp()
            sndMsg = sc.encryption(sndMsg.encode('utf-8'), authObj.key)
            netif.send_msg(netAddr, sndMsg)
            continue
        elif op=='LGO':
            loginStatus[netAddr] = False
            connected = False
            cUser = None
            print("User "+netAddr+" disconnected.") 
            filesys.currentDir[netAddr] = '/'
            continue
        elif op=='MSG':
            print("message:",msg)
            sndMsg = "Message received."
        elif op =='MKD': # make directory
            made = filesys.makeDir(netAddr, msg)
            sndMsg = "Folder " + "\"" + msg + "\"" + " created."
            if (not made):
                sndMsg = 'Invalid folder name.'
        elif op =='RMD': # remove directory
            removed = filesys.removeDir(netAddr, msg)
            sndMsg = "Folder removed."
            if (not removed):
                sndMsg = "Folder is not empty or does not exist."
        elif op =='GWD': # get directory
            sndMsg = "Current directory: " + filesys.getCurrentDir(netAddr)
        elif op =='CWD': # go to directory
            changed = filesys.changeDir(netAddr, msg)
            sndMsg = "Directory changed."
            if (not changed):
                sndMsg = "Path is invalid."    
        elif op =='LST': # list items
            sndMsg = filesys.listDir(netAddr)
        elif op =='UPL': # upload
            complete = filesys.upload(netAddr, msg)
            sndMsg = "File Uploaded."
            if not complete:
                sndMsg = 'File does not exist.'
        elif op =='DNL': # download
            msg = msg.split(' ')
            complete = filesys.download(netAddr, msg[0], msg[1])
            sndMsg = "File Downloaded."
            if not complete:
                sndMsg = "Invalid filename or destination."
        elif op =='RMF': # remove file
            removed = filesys.removeFile(netAddr, msg)
            sndMsg = "File " + "\"" + msg + "\"" + " removed."
            if (not removed):
                sndMsg = "File does not exist."
        else:
            sndMsg = "Invalid OP."
        sndMsg = sc.encryption(sndMsg.encode('utf-8'), authObj.key)
        netif.send_msg(netAddr, sndMsg)
        timeStart = time.time()
    else:
        timepassed = time.time()-timeStart
        if (connected and timepassed>300):
            loginStatus[cUser] = False
            connected = False
            print("User "+cUser+" disconnected.") 
            cUser = None
            timeStart = time.time()

