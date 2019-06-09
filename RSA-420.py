import math
import secrets
# Thanks to Ayrx for providing the code for Miller-Rabin test, I changed it up a bit though
# https://gist.github.com/Ayrx/5884790
def miller_rabin(n, k):
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = secrets.randbelow(n-3)+2
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True


# Thanks to wikibooks for the extended Euclidean algorithm, I modified it a bit to fit my needs
# https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
def xgcd(b, a):
    x0 = 1
    x1 = 0
    y0 = 0
    y1 = 1
    while a != 0:
        q, b, a = b // a, a, b % a
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return b, x0, y0


def mulinv(b, m):
    if gcd(b, m) == 1:
        g, x, _ = xgcd(b, m)
        return x % m
    else:
        raise ValueError("b and m are not relatively prime")


# My code starts here #
# Self-explanatory
def generatebitprime(bitlength, iterations):
    """
    This function generates numbers and if they pass the miller-rabin test, they are
    accepted as prime numbers and returned.
    :param bitlength: Length of the prime in bits
    :param iterations: Iterations of the miller-rabin test (recommended 40+)
    :return:
    """
    x = secrets.randbits(bitlength)
    while not miller_rabin(x, iterations):
        x = secrets.randbits(bitlength)
    else:
        return x


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


# Some read and write functions for the encryption.
def readkey(keyname):
    keyfile = open(keyname, "r+")
    key = keyfile.read()
    keyfile.close()
    keylist = key.split(" ")
    return keylist


def readbinary(filename):
    messagefile = open(filename, "rb+")
    message = messagefile.read()
    messagefile.close()
    return message


def readmessage(filename):
    messagefile = open(filename, "r+")
    message = messagefile.read()
    messagefile.close()
    return message


def writebinary(filename, message):
    file = open(filename, "wb+")
    file.write(message)
    file.close()

def writemessage(filename, message):
    file = open(filename, "w+")
    file.write(message)
    file.close()


# Gets RSA module and Euler's totient function
def getmodandphi(p, q):
    return [(p*q), ((p-1)*(q-1))]


# Generates RSA-keys from two given numbers. If the product is less than 256, please set override_minlength to True.
# p, q = int, override_minlength = boolean
def generatekeys(p, q, override_minlength):
    m, phi, d = getmodandphi(p, q)[0], getmodandphi(p, q)[1], secrets.randbelow((p-1)*(q-1) - 3) + 2
    while not gcd(d, phi) == 1:
        d = secrets.randbelow(phi - 3) + 2
    e = mulinv(d, phi)
    writemessage("privateKey.rsa", (str(format(d, "x")) + " " + str(format(m, "x"))))
    writemessage("publicKey.rsa", (str(format(e, "x")) + " " + str(format(m, "x"))))


# Generates RSA-keys with a certain bitlength.
def generatebitkeys(bitlength):
    p, q = generatebitprime(bitlength, 80), generatebitprime(bitlength, 80)
    while p == q:
        q = generatebitprime(bitlength, 80)
    m, phi, d = p*q, (p-1)*(q-1), secrets.randbelow((p-1)*(q-1)-3)+2
    while not gcd(d, phi) == 1:
        d = secrets.randbelow(phi-3)+2
    e = mulinv(d, phi)
    writemessage("privateKey.rsa", str(format(d, "x")) + " " + str(format(m, "x")))
    writemessage("publicKey.rsa", str(format(e, "x")) + " " + str(format(m, "x")))


generate420keys = lambda: generatebitkeys(420)


# Converts ASCII code to a hexstring.
def ascii_to_hex(message):
    message = str(message)
    hexmessage = ""
    for i in range(len(message)):
        hexmessage += format(ord(message[i:i+1]), "x")
    return format(int(hexmessage, 16), "x")


# Converts a hexstring to ASCII code.
def hex_to_ascii(hexmsg):
    hexmsg = str(hexmsg)
    message = ""
    if len(hexmsg) % 2 != 0:
        hexmsg = "0" + hexmsg
    for i in range(int(len(hexmsg)/2)):
        message += chr(int(hexmsg[2*i:2*i+2], 16))
    return message


def file_to_hex(filename):
    file = readbinary(filename)
    return file.hex()


def hex_to_file(message, filename):
    file = bytes.fromhex(message)
    writebinary(filename, file)




# Encrypts a file (which must only contain ASCII characters) and saves the decrypted file to the entered destination.
def encrypt(message, keyname="publicKey.rsa"):
    """
    Encrypts or decrypts a hex message.
    :param message: Must be a hexadecimal number. Example: 3e40f3ad, not: 0x3e40f3ad
    :param keyname: Must be the name of the keyfile in the RSA-420 path.
    :return: Returns encrypted or decrypted hexadecimal string (Example: "4723d8ea") with spaces as block splitters.
    """
    crypted = ""
    key = readkey(keyname)
    exp, mod = format(int(key[0], 16), "x"), format(int(key[1], 16), "x")
    blocklength = len(mod) - 1
    blockcount = math.ceil(len(message)/blocklength)
    for i in range(blockcount-1):
        part = message[i*blocklength:((i+1)*blocklength)]
        crypted += format(pow(int(part, 16), int(exp, 16), int(mod, 16)), "x") + " "
    i = blockcount-1
    part = message[i*blocklength:((i+1)*blocklength)]
    lastlen = len(part)
    crypted += format(pow(int(part, 16), int(exp, 16), int(mod, 16)), "x") + " "
    return crypted + str(blocklength) + " " + str(lastlen)


def decrypt(message, keyname="privateKey.rsa"):
    """
    Encrypts or decrypts a hex message.
    :param message: Must be a hexadecimal string with spaces as block splitters. Example: 3e40f3ad; not: 0x3e40f3ad
    :param keyname: Must be the name of the keyfile in the RSA-420 path.
    :return: Returns encrypted or decrypted hexadecimal number (Example: 4723d8ea).
    """
    decrypted = ""
    key = readkey(keyname)
    exp, mod = key[0], key[1]
    parts = message.split(" ")
    lastlen = parts.pop()
    blocklength = parts.pop()
    lastpart = parts.pop()
    for part in parts:
        part = format(pow(int(part, 16), int(exp, 16), int(mod, 16)), "x")
        while not len(part) == int(blocklength):
            part = "0" + part
        decrypted += part
    lastpart = format(pow(int(lastpart, 16), int(exp, 16), int(mod, 16)), "x")
    while len(lastpart) < int(lastlen):
        lastpart = "0" + lastpart
    # crypted = format(pow(message, exp, mod), "x")
    return decrypted + lastpart


def encrypt_ascii(message, keyname="publicKey.rsa"):
    """
    Encrypts an ASCII-formated string into a hexstring with spaces as block seperators.
    :param message: Must not contain any characters outside Extended ASCII.
    :param keyname: Define a custom key file if you want
    :return: A string containing hex numbers with spaces as block seperators.
    """
    message = ascii_to_hex(message)
    message = encrypt(message, keyname)
    return message


def decrypt_ascii(message, keyname="privateKey.rsa"):
    message = decrypt(message, keyname)
    message = hex_to_ascii(message)
    return message


def encrypt_file(filename, destination="encrypted.xx", keyname="publicKey.rsa"):
    message = file_to_hex(filename)
    print(message)
    message = encrypt(message, keyname)
    writemessage(destination, message)


def decrypt_file(filename,destination="decrypted.xx", keyname="privateKey.rsa"):
    message = readmessage(filename)
    message = decrypt(message, keyname)
    print(message)
    hex_to_file(message, destination)
    
