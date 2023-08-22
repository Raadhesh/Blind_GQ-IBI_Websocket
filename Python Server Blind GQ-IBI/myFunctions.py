from Crypto.PublicKey import RSA
from Crypto.Util.number import size, inverse
import math
import random
import timeit
import time
import ast
import pickle
from hashlib import sha256


#test function to test the received info is correct
def checkIfSameResults(stringID, blindSigma, r, N, e, hashID, blindID, sigma, y, Y):
    print("\nChecking if values are equal...\n")
    count = 0

    #hashID check
    myByteID = stringID.encode('utf-8')
    myHashID = sha256(myByteID).hexdigest()
    if myHashID == hashID:
        print("HashID checks out\n")
        count+=1
    else:
        print("HashID does not check out")
        print("myHashID = ", myHashID)
        print("hashID = ", hashID)
        print("\n")
    
    #blindID check
    myIntVal = int_from_hex(myHashID)
    myBlindIntVal = (myIntVal * pow(r, e, N)) % N
    myBlindID = hex_from_int(myBlindIntVal)

    myUnblindIntVal = (myBlindIntVal * inverse(r,N)) % N
    myUnblindID = hex_from_int(myUnblindIntVal)
    if myUnblindID == myHashID:
        print("myUnblindID is equal to myHashID\n")
    else:
        print("myUnblindID is not equal to myHashID\n")

    if myBlindID == blindID:
        print("BlindID checks out\n")
        count += 1
    else:
        print("BlindID does not check out")
        print("myBlindID = ", myBlindID)
        print("blindID = ", blindID)
        print("\n")

    #sigma check
    myBlindIntSigma = int_from_hex(blindSigma)
    myIntSigma =  (inverse(r, N) * myBlindIntSigma) % N
    mySigma = hex_from_int(myIntSigma)

    if mySigma == sigma:
        print("sigma checks out\n")
        count += 1
    else:
        print("sigma does not check out")
        print("mySigma = ", mySigma)
        print("sigma = ", sigma)
        print("\n")
    
    #Y Check
    myY = pow(y,e,N)
    
    if myY == Y:
        print("Y checks out\n")
        count += 1
    else:
        print("Y does not check out")
        print("myY = ", myY)
        print("Y = ", Y)
        print("y = ", y)
        print("\n")

    if count == 4:
        print("\n\n")
        print("No Problem with the values used\n")
        return True
    else:
        print("\n\n")
        print("PROBLEM with values\n")
        print("N = ", N)
        print("e = ", e)
        print("stringID = ", stringID)
        print("hashID = ", hashID)
        print("r = ", r)
        print("blindID = ", blindID)
        print("sigma = ", sigma)
        print("blindSigma = ", blindSigma)
        print("y = ", y)
        print("Y = ", Y)


# to save string to file
def saveStringToFile(message, fileName):
    with open(fileName, 'w', encoding='utf-8') as f:
        f.write(str(message))

# to read string from file
def readStringFromFile(fileName):
    with open(fileName, 'r', encoding='utf-8') as f:
        res = f.readline()
        return stringDict_to_dict(res)
    
#
# to save object to file
def save_object(obj, filename): 
    objName = [ i for i, j in locals().items() if j == obj][0]  # get variable name of object
    with open(filename, 'wb') as outp:  # Overwrites any existing file.
        pickle.dump(obj, outp, pickle.HIGHEST_PROTOCOL)
        print("\nSaved object " + objName + " in filename: " + filename + "\n")

# to read object from file
def read_object(filename):
    with open(filename, 'rb') as inp:
        obj = pickle.load(inp)
        objName = [ i for i, j in locals().items() if j == obj][0]  # get variable name of object
        print("\nRead object " + objName + " from filename: " + filename + "\n")
        return obj

# to convert string dictionary to dictionary
def stringDict_to_dict(stringMessage):
    return ast.literal_eval(stringMessage)

# to convert from int to hex string
def hex_from_int(message):
    hexMessage = f'{message:x}'
    return hexMessage
# to convert from hex to int string
def int_from_hex(message):
    hexMessage = int(message, 16)
    return hexMessage


#gcd function
def gcd(a,b):
    while b > 0:
        a, b = b, a % b
    return a

def setupRSA(keySize):
    setupStartTime = time.time()
    keyPair = RSA.generate(keySize)
    N = keyPair.n
    e = keyPair.e
    d = keyPair.d
    # p = keyPair.p
    # q = keyPair.q
    # phi_N = (p-1) * (q-1)

    # Show attributes of keyPair.
    # print("N = ", N)
    # print("e = ", e)
    # print("d = ", d)
    # print("p = ", p)
    # print("q = ", q)
    setupEndTime = time.time()
    setupTime =  setupEndTime - setupStartTime
    print("Setup Time = ", str(setupTime))
    return (N, e, d)

def signRSA(N, exponent, message):
    sigma = pow(message, exponent, N)
    return sigma

def generateRandomVal(N):
    y = random.randint(3, N)
    while gcd(y, N) != 1:
        y = random.randint(3,N)
    return y

def generateCMT(N, e):
    y = generateRandomVal(N)
    Y = pow(y, e, N)
    return(y, Y)

def generateCHL(N):
    c = random.randint(1,N)
    while gcd(c, N) != 1:
        c = random.randint(3,N)
    return c

def generateRSP(N, c, sigma, y):
  z = pow(y*pow(sigma, c, N), 1, N)
  return z
  

def GQ_IBI_verification(N, e, Y, c, z, intPublicID):
    val1 = pow(z, e, N)
    temp1 = Y * pow(intPublicID, c, N)
    val2 = pow(temp1, 1, N)
    print("\n")
    print("val1 = ", val1)
    print("val2 = ", val2)
    print("\n")
    check = (val1 == val2)
    if check:
        print("Prover is verified through blinded identity")
    else:
        print("Prover is false")
    
    return check
    
