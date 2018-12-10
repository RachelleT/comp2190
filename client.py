# Client to implement simplified RSA algorithm.
# The client says hello to the server, and the server responds with a Hello
# and its public key. The client then sends a session key encrypted with the
# server's public key. The server responds to this message with a nonce
# encrypted with the server's public key. The client decrypts the nonce
# and sends it back to the server encrypted with the session key. Next,
# the server sends the client a message with a status code. If the status code
# is "250" then the client can ask for the server to roll the dice. Otherwise,
# the client's connection to the server will be terminated.
# Author: fokumdt 2017-11-09

#!/usr/bin/python3

import socket
import math
import random
import sys
import time
import simplified_AES


def expMod(b,n,m):
    """Computes the modular exponent of a number returns (b^n mod m)"""
    if n==0:
        return 1
    elif n%2==0:
        return expMod((b*b)%m, n/2, m)
    else:
        return(b*expMod(b,n-1,m))%m

def RSAencrypt(m, e, n):
    """Encryption side of RSA"""
    encrypted = expMod(m, e, n) # Encrypting m
    return encrypted  ## Add code to encrypt. You _must_ use the expMod method. 

def RSAdecrypt(c, d, n):
    """Decryption side of RSA"""
    decrypted = expMod(c, d, n) # Decryptint c
    return decrypted ## Add code to decrypt. You _must_ use the expMod method.

def serverHello():
    """Sends server hello message"""
    status = "100 Hello"
    return status

def sendSessionKey(s):
    """Sends server session key"""
    status = "110 SessionKey " + str(s)
    return status

def sendTransformedNonce(xform):
    """Sends server nonce encrypted with session key"""
    status = "130 Transformed Nonce " + str(xform)
    return status

def computeSessionKey():
    """Computes this node's session key"""
    sessionKey = random.randint(1, 65536)
    return sessionKey

def serverHello():
    """Generates server hello message"""
    status = "100 Hello"
    return status

def RollDice():
    """Generates message to get server to roll some or all dice."""
    toRoll = input('Enter dice to roll separated by commas: ')
    status = "200 Roll Dice " + str(toRoll)
    return status

# s       = socket
# msg     = initial message being processed
# state   = dictionary containing state variables
def processMsgs(s, msg, state):
    """This function processes messages that are read through the socket. It
        returns a status, which is an integer indicating whether the operation
        was successful"""
        
    status = -2
    rcvr_mod = int(state['modulus'])            # Receiver's modulus for RSA
    rcvr_exp = int(state['pub_exp'])            # Receiver's public exponent
    symmetricKey = int(state['SymmetricKey'])   # shared symmetric key
    rolls = int(state['Rolls'])                 # Number of dice rolls used
    
    strTest = "101 Hello "
    if (strTest in msg and status==-2):
        print("Message received: "+ msg)
        RcvdStr = msg.split(' ')
        rcvr_mod = int(RcvdStr[2]) # Modulus for public key encryption
        rcvr_exp = int(RcvdStr[3]) # Exponent for public key encryption
        print("Server's public key: ("+ str(rcvr_mod)+","+str(rcvr_exp)+")")
        symmetricKey = computeSessionKey()
		## Add code to handle the case where the symmetricKey is
		## greater than the modulus.
        while(symmetricKey > rcvr_mod): # While loop is executed if symmetric key is greater than the modulus.
            temp = computeSessionKey() # Generates new session key.
            symmetricKey = temp # Set symmetricKey to newly generated session key. 
        encSymmKey = RSAencrypt(symmetricKey, rcvr_exp, rcvr_mod)   ## Add code to encrypt the symmetric key.
        msg = sendSessionKey(encSymmKey)
        print(msg)
        s.sendall(bytes(msg,'utf-8'))
        state['modulus'] = rcvr_mod
        state['pub_exp'] = rcvr_exp
        state['SymmetricKey'] = symmetricKey
        status = 1
    
    strNonce = "120 Nonce"
    if (strNonce in msg and status==-2):
        print("Message received: " + msg)
        RcvdStr = msg.split(' ')
        encNonce = int(RcvdStr[2])
        nonce = RSAdecrypt(encNonce, rcvr_exp, rcvr_mod) ## Add code to decrypt nonce
        """Setting up for Simplified AES encryption"""
        plaintext = nonce
        simplified_AES.keyExp(symmetricKey) # Generating round keys for AES.
        ciphertext = simplified_AES.encrypt(plaintext) # Running simplified AES.
        msg = sendTransformedNonce(ciphertext)
        s.sendall(bytes(msg,'utf-8'))
        status = 1
        
    strDiceRoll = "205 Roll Dice ACK"
    if (strDiceRoll in msg and status==-2):
        print("Message received: " + msg)
        DiceValues = msg[18:].split(',')
        if rolls < 2:
            WantstoRollMore = input("Do you wish to roll more dice? (y/n): ")
            if WantstoRollMore=='y':
                msg = RollDice()
                s.sendall(bytes(msg,'utf-8'))
                rolls += 1
                status = 1
            else:
                status = 0
        else:
            status = 0
        state['Rolls'] = rolls            
        
    strSuccess = "250 OK"
    strFailure = "400 Error"
    if (strFailure in msg and status==-2):
        print("Message received: " + str(msg))
        status = 0 # To terminate loop at client
    if (strSuccess in msg and status==-2):
        print("Cryptographic checks completed successfully")
        print(msg)
        if rolls ==0:
            msg = "200 Roll Dice"
        else:
            msg = RollDice()
        s.sendall(bytes(msg,'utf-8'))
        rolls += 1
        status = 1
    
    if status==-2:
        print("Incoming message was not processed. \r\n Terminating")
        status = -1
    return status

def main():
    """Driver function for the project"""
    args = sys.argv
    if len(args) != 3:
        print ("Please supply a server address and port.")
        sys.exit()
    serverHost = str(args[1])       # The remote host
    serverPort = int(args[2])       # The same port as used by the server
    
    print("Client of Rachelle")
    print('''
    The dice in this program are numbered from 0--4.
    No error checking is done, so ensure that the dice numbers are correct.
    If you do not want to enter any dice, simply hit the enter key.
    ''')
    
    # Bogus values that will be overwritten with values read from the socket.
    sndr_exp = 3
    sndr_mod = 60769
    symmKey = 32767
    rolls = 0
    state = {'modulus': sndr_mod, 'pub_exp': sndr_exp, 'SymmetricKey': symmKey,
             'Rolls': rolls }
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((serverHost, serverPort))
    msg = serverHello()
    s.sendall(bytes(msg,'utf-8'))
    status = 1
    while (status==1):
        msg = s.recv(1024).decode('utf-8')
        if not msg:
            status = -1
        else:
            status = processMsgs(s, msg, state)
    if status < 0:
        print("Invalid data received. Closing")
    s.close()

if __name__ == "__main__":
    main()
