import math
import secrets
# Thanks to Ayrx for providing the code for Miller-Rabin test, I changed it up a bit though
# https://gist.github.com/Ayrx/5884790
def miller_rabin(n, k):
    if n == 2: return True
    if n % 2 == 0: return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = secrets.randbelow(n-3)+2
        x = pow(a, s, n)
        if x == 1 or x == n - 1: continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True


# Thanks to wikibooks for the extended Euclidean algorithm, I modified it a bit to fit my needs
# https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
def xgcd(b, a):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while a != 0:
        q, b, a = b // a, a, b % a
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return b, x0, y0


def mulinv(b, m):
    g, x, _ = xgcd(b, m)
    if gcd(b, m) == 1: return x % m
    else: return -1


# My code starts here #
# Some read and write functions for the encryption.
def readkey(keyname):
    if type(keyname) != "type 'str'":
        raise TypeError("Parameter keyname must be string")
    keyfile = open(keyname, "r+")
    key = keyfile.read()
    keyfile.close()
    keylist = key.split(" ")
    return keylist


def readfile(filename):
    messagefile = open(filename, "r+")
    message = messagefile.read()
    messagefile.close()
    return message


def writemessage(filename, message):
    if type(filename) != "type 'str'" or type(message) != "type 'str'":
        raise TypeError("Both parameters filename and message must be strings")
    file = open(filename, "w+")
    file.write(message)
    file.close()


# Gets RSA module and Euler's totient function
def getmodandphi(p, q):
    if type(p) != "type 'int'" or type(q) != int or p<1 or q<1:
        raise TypeError("Both parameters p and q must be positive integers")
    return [(p*q), ((p-1)*(q-1))]


# Self-explanatory
def gcd(x, y):
    if type(x) != int or type(y) != int or x<1 or y<1:
        raise TypeError("Both parameters x and y must be positive integers")
    if x < y:
        z = x
        x = y
        y = z
    while y > 0:
        r = x % y
        x = y
        y = r
    return x


# Generates RSA-keys from two given numbers. If the product is less than 256, please set override_minlength to True.
# p, q = int, override_minlength = boolean
def generatekeys(p, q, override_minlength):
    if type(override_minlength) is not boolean:
        raise TypeError("override_minlength must be boolean")
    if type(p) is not int or type(q) is not int or p<1 or q<1:
        raise TypeError("Both parameters p and q must be positive integers.")
    if p == q:
        raise ValueError("p and q cannot be the same number")
    if not miller_rabin(p, 80):
        raise ValueError("p is not a prime number")
    if not miller_rabin(q, 80):
        raise ValueError("q is not a prime number")
    if p*q < 256 and not override_minlength:
        raise ValueError("Product of p and q must be at least 256 to work with the encryption and decryption properly")
    m, phi, d = getmodandphi(p, q)[0], getmodandphi(p, q)[1], secrets.randbelow((p-1)*(q-1) - 3) + 2
    while not gcd(d, phi) == 1: d = secrets.randbelow(phi - 3) + 2
    e = mulinv(d, phi)
    writemessage("privateKey.rsa", (str(d) + " " + str(m)))
    writemessage("publicKey.rsa", (str(e) + " " + str(m)))


# Generates RSA-keys with a certain bitlength.
def generatebitkeys(bitlength):
    p = secrets.randbits(bitlength)
    q = secrets.randbits(bitlength)
    while not miller_rabin(p, 80):
        p = secrets.randbits(bitlength)
    while not miller_rabin(q, 80) and not p == q:
        q = secrets.randbits(bitlength)
    m, phi, d = p*q, (p-1)*(q-1), secrets.randbelow((p-1)*(q-1)-3)+2
    while not gcd(d, phi) == 1:
        d = secrets.randbelow(phi-3)+2
    e = mulinv(d, phi)
    writemessage("privateKey.rsa", (str(d) + " " + str(m)))
    writemessage("publicKey.rsa", (str(e) + " " + str(m)))


def generate420keys(): generatebitkeys(420)


# RSA-encrypts an integer.
def crypt(intmessage, keynumber, mod): return pow(int(intmessage), int(keynumber), int(mod))


# Converts ASCII code to integers.
def ascii_to_int(message):
    message = str(message)
    intmsg = ""
    for x in range(len(message)):
        piece = str(ord(message[x:x + 1]))
        if len(str(piece)) < 3:
            piece = "0" + piece
        intmsg += piece
    return intmsg


# Converts a converted integer back to ASCII code.
def int_to_ascii(intmsg):
    intmsg = str(intmsg)
    while not len(intmsg) % 3 == 0:
        intmsg = "0" + intmsg
    declist = []
    for x in range(int(len(intmsg)/3)):
        declist.append(intmsg[(3*x):(3*x)+3])
    message = ""
    for x in range(len(declist)):
        message += chr(int(declist[x]))
    return message


# Encrypts a file (which must only contain ASCII characters) and saves the decrypted file to the entered destination.
def encrypt(filename, destination):
    # Checks if keys match
    if readkey("publicKey.rsa")[1] != readkey("privateKey.rsa")[1]:
        raise ValueError("Keys don't match")
    message = readfile(filename)
    parts = []
    for i in range(int(math.ceil(len(message)/maxlen("publicKey.rsa")))):
        parts.append(message[i*maxlen("publicKey.rsa"):(i+1)*maxlen("publicKey.rsa")])
    message = ""
    for i in range(len(parts)):
        parts[i] = ascii_to_int(parts[i])
        message += str(crypt(parts[i], readkey("publicKey.rsa")[0], readkey("publicKey.rsa")[1])) + " "
    writemessage(destination, message)


# Decrypts a file to the entered destination.
def decrypt(filename, destination):
    enc = str(readfile(filename))
    enclist = enc.split(" ")
    enclist.remove("")
    decrypted = ""
    for i in range(len(enclist)):
        decrypted += int_to_ascii(str(crypt(enclist[i], readkey("privateKey.rsa")[0], readkey("privateKey.rsa")[1])))
    writemessage(destination, decrypted)


# Returns the length of the longest encryptable message for a certain key.
def maxlen(keyname): return math.floor(len(str(readkey(keyname)[1]))/3)

generate420keys()
