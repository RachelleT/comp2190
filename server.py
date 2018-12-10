# Server to implement simplified RSA algorithm. 
# The server waits for the client to say Hello. Once the client says hello,
# the server sends the client a public key. The client uses the public key to
# send a session key with confidentiality to the server. The server then sends
# a nonce (number used once) to the client, encrypted with the server's private
# key. The client decrypts that nonce and sends it back to server encrypted 
# with the session key. Next, the server sends the client a message with a
# status code. If the status code is "250" then the client can ask for the
# server to roll the dice. Otherwise, the server's connection to the client
# will be terminated.

# Author: fokumdt 2017-11-09

#!/usr/bin/python3

import socket
import random
import math
import hashlib
import time
import sys
import simplified_AES

def expMod(b,n,m):
    """Computes the modular exponent of a number"""
    """returns (b^n mod m)"""
    if n==0:
        return 1
    elif n%2==0:
        return expMod((b*b)%m, n/2, m)
    else:
        return(b*expMod(b,n-1,m))%m

def RSAencrypt(m, e, n):
    """Encryption side of RSA"""
    encrypted = expMod(m, e, n) # Encrypting m.
    return encrypted              ## Add code here to do encryption

def RSAdecrypt(c, d, n):
    """Decryption side of RSA"""
    decrypted = expMod(c, d, n) # Decrypting c.
    return decrypted              ## Add code here to do decryption

def gcd(u, v):
    """Iterative Euclidean algorithm"""
    ## Write code to compute the gcd of two integers
    if v==0:
        return u
    else:
        return gcd(v, u%v) # Returns greatest common divisor between v and u.

def ext_Euclid(m,n): # Used to find a valid number for d.
    """Extended Euclidean algorithm"""
    ## Write code to implement the Extended Euclidean algorithm. See Tutorial 7
    ## This method should return the multiplicative inverse of n mod m.
    ## i.e., (n*n^(-1) mod m = 1
    ## If this method returns a negative number add m to that number until
    ## it becomes positive.
    A1 = 1
    A2 = 0
    A3 = m
    B1 = 0
    B2 = 1
    B3 = n
    run = True
    while (run == True):
        if B3 == 0:
            return A3 # Returns A3 is B3 is equal to 0.
            run = False
        if B3 == 1:
            if B2 > 0:
                return B2 # Returns B2 if it is a positive number.
                run = False
            if B2 < 0:
                d = B2 + m # Adds m to B2 if B2 is a negative number.
            return d
            run = False
        Q = int(A3/B3)
        T1 = (A1 - (Q * B1))
        T2 = (A2 - (Q * B2))
        T3 = (A3 - (Q * B3))
        A1 = B1
        A2 = B2
        A3 = B3
        B1 = T1
        B2 = T2
        B3 = T3
        

def generateNonce():
    """This method returns a 16-bit random integer derived from hashing the
        current time. This is used to test for liveness"""
    hash = hashlib.sha1()
    hash.update(str(time.time()).encode('utf-8'))
    return int.from_bytes(hash.digest()[:2], byteorder=sys.byteorder)

def findE(phi, p, q):
    """Method to find e given phi, p, and q"""
    """while loop to increment e until it is relatively prime to phi"""
    ## Add code to find e given phi, p, and q
    n = p * q
    number = phi
    digits = 0
    while number > 0:
        number = int(number / 10)
        digits = digits + 1 # Determining the number of digits in a number.
    for i in range(digits, phi): # Specifying a range for e.
        if(i%2 != 0):
            e = random.randint(i, phi-1) # Setting e to a random integer within the specified range.
            if (gcd(e, phi) == 1): # Checking that e mod phi is equal to 1.
                return e # Returning e valid number for e.
    
def findE(phi):
    """Method to randomly choose a good e given phi"""
    number = phi
    digits = 0
    while number > 0:
        number = int(number / 10)
        digits = digits + 1
    erange = 10**(digits - 1) # Specifying a range for e.
    e = random.randint(erange, phi-1) # Setting e to a random integer within the specified range.
    # phi-1 to make sure e < phi.
    while e < phi: # Checking that e is less than phi
        if (gcd(e, phi) == 1): # Checking that e mod phi is equal to 1.
            return e # Returning e valid number for e.
        e = random.randint(erange, phi-1)

def genKeys(p, q):
    """Generate n, phi(n), e, and d."""
    n = p * q                     ## Complete this
    phi = (p-1) * (q-1)           ## Complete this
    e = findE(phi)                ## Complete this
    d = ext_Euclid(phi, e)        ## Complete this
    print ("n = "+ str(n))
    print ("phi(n) = "+ str(phi))
    print ("e = "+ str(e))
    print ("d = "+ str(d))
    print
    return n, e, d    

def clientHelloResp(n, e):
    """Responds to client's hello message with modulus and exponent"""
    status = "101 Hello "+ str(n) + " " + str(e)
    return status

def SessionKeyResp(nonce):
    """Responds to session key with nonce"""
    status = "120 Nonce "+ str(nonce)
    return status

def nonceVerification(nonce, decryptedNonce):
    """Verifies that the transmitted nonce matches that received
       from the client."""
    if (nonce == decryptedNonce):
        status = "250 OK"
    else:
        status = "400 Error"
    return status

def clientHello():
    """Generates client hello message"""
    status = "100 Hello"
    return status

def rollDice(dice, toRoll=[0,1,2,3,4]):
    """Rolls specified dice. If no dice are specified, all dice are rolled."""
    for i in toRoll:
        dice[i] = random.randint(1,6)
        
def RollDiceACK(dice):
    """Generates message with dice values"""
    strDice = ','.join([str(x) for x in dice])
    status = "205 Roll Dice ACK " + strDice
    return status

# s      = socket
# msg     = initial message being processed
# state  = dictionary containing state variables
def processMsgs(s, msg, state):
    """This function processes messages that are read through the socket. It
        returns a status, which is an integer indicating whether the operation
        was successful"""
    status = -2
    modulus = int(state['modulus'])          # modulus   = modulus for RSA
    pub_exp = int(state['pub_exp'])          # pub_exp   = public exponent
    priv_exp = int(state['priv_exp'])        # priv_exp  = secret key
    challenge = int(state['nonce'])          # challenge = nonce sent to client
    SymmKey = int(state['SymmetricKey'])     # SymmKey   = shared symmetric key
    rolls = int(state['Rolls'])              # rolls     = number of dice rolls
    dice  = state['Dice']                    # Dice      = values of dice
    dice = list(map(int,dice))               # Converting dice values to ints
    
    strTest = "100 Hello"
    if strTest in msg and status == -2:
        print("Message received: " + msg)
        msg = clientHelloResp(modulus, pub_exp)
        s.sendall(bytes(msg,'utf-8'))
        status = 1
        print ("Message sent: ", msg)
    
    strSessionKey = "110 SessionKey"
    if strSessionKey in msg and status == -2:
        print("Message received: "+ msg)
        RcvdStr = msg.split(' ')
        encSymmKey = int(RcvdStr[2])
        SymmKey = RSAdecrypt(encSymmKey, priv_exp, modulus) ## Add code to decrypt symmetric key
        state['SymmetricKey'] = SymmKey
        # The next line generates the round keys for simplified AES
        simplified_AES.keyExp(SymmKey)
        challenge = generateNonce()
        # Add code to ensure that the challenge can always be encrypted
        #  correctly with RSA.
        while(challenge > modulus): # While loops executes if challenge is more than modulus.
            temp = generateNonce() # Generating a new nonce.
            challenge = temp # Setting challenge to the newly generated nonce.
        #Do this
        state['nonce'] = challenge
        msg = SessionKeyResp(RSAdecrypt(challenge, priv_exp, modulus))
        s.sendall(bytes(msg, 'utf-8'))
        status = 1
        print ("Decrypted Symmetric Key: ", SymmKey)
        print("d: ", priv_exp)
        print ("n: ", modulus)
        print ("Challenge: ", challenge)
        print ("Message sent: ", msg)
    
    strSessionKeyResp = "130 Transformed Nonce"
    if strSessionKeyResp in msg and status == -2:
        print("Message received: " + msg)
        RcvdStr = msg[22:]
        encryptedChallenge = int(RcvdStr)
        # The next line runs AES decryption to retrieve the key.
        decryptedChallenge = simplified_AES.decrypt(encryptedChallenge)
        msg = nonceVerification(challenge, decryptedChallenge)
        s.sendall(bytes(msg,'utf-8'))
        status = 1
        
    strDiceRollResp = "200 Roll Dice"
    if strDiceRollResp in msg and status == -2:
        print("Message received: " + msg)
        RcvdStr = msg[14:]
        if (len(RcvdStr)>0):
            RcvdStrParams = RcvdStr.split(',')
            toRoll = list(map(int,RcvdStrParams))
            rollDice(dice, toRoll)
        else:
            rollDice(dice)
        if (rolls<3):
            status = 1
        else:
            status = 0
        rolls += 1
        state['Dice'] = dice
        state['Rolls'] = rolls 
        msg = RollDiceACK(dice)
        s.sendall(bytes(msg,'utf-8'))
    
    # status can only be -2 if none of the other branches were followed
    if status==-2:
        print("Incoming message was not processed. \r\n Terminating")
        status = -1
    return status

def main():
    """Driver function for the project"""
    args = sys.argv
    if len(args) != 2:
        print ("Please supply a server port.")
        sys.exit()
    HOST = ''        		# Symbolic name meaning all available interfaces
    PORT = int(args[1])     # The port on which the server is listening
    if PORT < 1023 or PORT > 65535:
        print("Invalid port specified.")
        sys.exit()
    print ("Enter prime numbers. One should be between 907 and 1013, and\
 the other between 53 and 67")
    p = int(input('Enter P : '))
    q = int(input('Enter Q: '))
    n, e, d = genKeys(p, q)
    
    random.seed()
    SymmKey = 1013    # Initializing symmetric key with a bogus value.
    nonce = generateNonce()
    dice = [random.randint(1,6), random.randint(1,6), random.randint(1,6),
            random.randint(1,6),random.randint(1,6)]
    
    rolls = 0    
    state = {'nonce': nonce, 'modulus': n, 'pub_exp': e, 'priv_exp': d,
    'SymmetricKey': SymmKey, 'Rolls': rolls, 'Dice': dice}
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            status = 1
            while (status==1):
                msg = conn.recv(1024).decode('utf-8')
                if not msg:
                    status = -1
                else:
                    status = processMsgs(conn, msg, state)
            if status < 0:
                print("Invalid data received. Closing")
            conn.close()
            print("Closed connection socket")

if __name__ == "__main__":
    main()
