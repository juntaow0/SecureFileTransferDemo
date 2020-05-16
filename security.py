import sys, getopt, getpass, os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random

class sessionAuth():
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
    g = 2
    x = 0
    snd = 0
    rcv = 0
    key = 0
    sig = 0
    def __init__(self):
        self.x = Random.random.getrandbits(12)
        self.snd = (self.g ** self.x) % self.p
        
    def save_publickey(self, pubkey, pubkeyfile):
        with open(pubkeyfile, 'wb') as f:
            f.write(pubkey.export_key(format='PEM'))

    def load_publickey(self, pubkeyfile):
        with open(pubkeyfile, 'rb') as f:
            pubkeystr = f.read()
        try:
            return RSA.import_key(pubkeystr)
        except ValueError:
            print('Error: Cannot import public key from file ' + pubkeyfile)
            sys.exit(1)

    def save_keypair(self, keypair, privkeyfile, passphrase):
        with open(privkeyfile, 'wb') as f:
            f.write(keypair.export_key(format='PEM', passphrase=passphrase))

    def load_keypair(self, privkeyfile, passphrase):
        with open(privkeyfile, 'rb') as f:
            keypairstr = f.read()
        try:
            return RSA.import_key(keypairstr, passphrase=passphrase)
        except ValueError:
            print('Error: Cannot import private key from file ' + privkeyfile)
            return False
        
    def generateKey(self):
        result = (self.rcv ** self.x) % self.p
        result = result.to_bytes((result.bit_length()//8)+1,'big')
        hashfn = SHA256.new()
        hashfn.update(result)
        self.key = hashfn.digest()
        
    def generateSig(self, uid, sid, keyFile, direction, passphrase):
        keypair = self.load_keypair(keyFile, passphrase)
        if not keypair:
            return False
        signer = pss.new(keypair)
        hashfn = SHA256.new()
        UID = uid.encode('utf-8')
        SID = sid.encode('utf-8')
        SND = str(self.snd).encode('utf-8')
        RCV = str(self.rcv).encode('utf-8')
        if direction=='toUser':
            hashfn.update(UID+RCV+SID+SND)
        else:
            hashfn.update(UID+SND+SID+RCV)
        self.sig = signer.sign(hashfn)
        return b64encode(self.sig)
            
    def checkSig(self, uid, sid, sig, pubkeyfile, direction):
        pubkey = self.load_publickey(pubkeyfile)
        verifier = pss.new(pubkey)
        hashfn = SHA256.new()
        UID = uid.encode('utf-8')
        SID = sid.encode('utf-8')
        SND = str(self.snd).encode('utf-8')
        RCV = str(self.rcv).encode('utf-8')
        
        if direction=='toServer':
            hashfn.update(UID+SND+SID+RCV)
        else:
            hashfn.update(UID+RCV+SID+SND)
        try:
            verifier.verify(hashfn, sig)
        except (ValueError, TypeError):
            print('Signature verification is failed.')
            yn = input('Do you want to continue (y/n)? ')
            if yn != 'y': 
                sys.exit(1)
                
    def digestServer(self, rcvMsg, uid, sid, pubkeyfile):
        # g^y mod p | Sig_s(U | g^x | S | g^y)
        rcvMsg = rcvMsg.split(b'\n')
        self.rcv = int(rcvMsg[0].decode('utf-8'))
        sig = b64decode(rcvMsg[1])
        self.checkSig(uid,sid,sig,pubkeyfile,'toServer')
        
    def digestUser(self, rcvMsg, uid, sid, pubkeyfile):
        # U | Sig_s(U | g^x | S | g^y)
        rcvMsg = rcvMsg.split(b'\n')
        sig = b64decode(rcvMsg[1])
        self.checkSig(uid,sid,sig,pubkeyfile,'toUser')
        
    def keypairGeneration(self, pubname, privname, keypath, addr, passphrase):
        if not os.path.exists(keypath):
            os.mkdir(keypath)
        if not os.path.exists(keypath+addr):
            os.mkdir(keypath+addr)
        print('Generating a new 2048-bit RSA key pair...')
        keypair = RSA.generate(2048)
        self.save_publickey(keypair.publickey(), keypath+addr+'/'+pubname+'.pem')
        self.save_keypair(keypair, keypath+addr+'/'+privname+'.pem', passphrase)
        print('Done.')
        
class secureChannel():
    statefile = 'states.txt'
    header_version = b'\x01\x00'
    authtag_length = 12
    header_bytes = 16
    
    def __init__(self):
        if self.statefile not in (os.listdir('./')):
            state =  "rcv: 0" + '\n' + "snd: 0"
            with open(self.statefile, 'wt') as sf:
                sf.write(state)
                
    def encryption(self, payload, key):
        with open(self.statefile, 'rt') as sf:
            rcv = int(sf.readline()[len("rcv: "):].strip(), base=10)
            snd = int(sf.readline()[len("snd: "):], base=10)
        payload_length = len(payload)
        msg_length = self.header_bytes + payload_length + self.authtag_length
        header_length = msg_length.to_bytes(2, byteorder='big')
        header_sqn = (snd + 1).to_bytes(4, byteorder='big')
        header_rnd = Random.get_random_bytes(8)
        header = self.header_version + header_length + header_sqn + header_rnd
        nonce = header_sqn + header_rnd
        AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=self.authtag_length)
        AE.update(header)
        encrypted_payload, authtag = AE.encrypt_and_digest(payload)
        message = header + encrypted_payload + authtag
        state =  "rcv: " + str(rcv) + '\n' + "snd: " + str(snd + 1)
        with open(self.statefile, 'wt') as sf:
            sf.write(state)
        return message # in bytes
    
    def decryption(self, message, key):
        with open(self.statefile, 'rt') as sf:
            rcv = int(sf.readline()[len("rcv: "):].strip(), base=10)
            snd = int(sf.readline()[len("snd: "):], base=10)
        header = message[0:16]
        authtag = message[-12:]
        encrypted_payload = message[16:-12]
        header_version = header[0:2]
        header_length = header[2:4]
        header_sqn = header[4:8]
        header_rnd = header[8:16]
        if len(message) != int.from_bytes(header_length, byteorder='big'):
            print("Message length value in header is wrong!")
            sys.exit(1)
        sndsqn = int.from_bytes(header_sqn, byteorder='big')
        if (sndsqn <= rcv):
            print("Error: Message sequence number is too old!")
            print("Processing completed.")
            sys.exit(1)    
        nonce = header_sqn + header_rnd
        AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=self.authtag_length)
        AE.update(header)
        try:
            payload = AE.decrypt_and_verify(encrypted_payload, authtag)
        except Exception as e:
            print("Error: Operation failed!")
            print("Processing completed.")
            sys.exit(1)
        state =  "rcv: " + str(sndsqn) + '\n' + "snd: " + str(snd)
        with open(self.statefile, 'wt') as sf:
            sf.write(state)
        return payload

        
    
        
    
        
        
    