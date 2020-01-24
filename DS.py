#created by Efe Nadir, Oyku Ercin
# coding: utf-8

# In[ ]:


import math
import string
import sympy
import os.path
import sys
import random
import pyprimes
import warnings
import string
from Crypto.Hash import SHA3_256
from Crypto.Hash import SHAKE128

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def random_prime(bitsize):
    warnings.simplefilter('ignore')
    chck = False
    while chck == False:
        p = random.randrange(2**(bitsize-1), 2**bitsize-1)
        chck = pyprimes.isprime(p)
    warnings.simplefilter('default')    
    return p

def large_DL_Prime(q, bitsize):
    warnings.simplefilter('ignore')
    chck = False
    while chck == False:
        k = random.randrange(2**(bitsize-1), 2**bitsize-1)
        p = k*q+1
        chck = pyprimes.isprime(p)
    warnings.simplefilter('default')    
    return p

def modinv(a, m):
    if a < 0:
        a = a+m
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m
        
#Random string generator with parameter string size
def random_string(str_size):
    chars = string.ascii_letters + string.punctuation
    return ''.join(random.choice(chars) for x in range(str_size))

qsize = 224
psize = 2048

#Public parameter generation
def Setup(qsize, psize):    
    q = random_prime(qsize)
    p = large_DL_Prime(q, psize-qsize)
    while p.bit_length() != 2048:
        p = large_DL_Prime(q, psize-qsize)        
    tmp = (p-1)//q
    g = 1
    while g == 1:
        alpha = random.randrange(1, p)
        g = pow(alpha, tmp, p)
    return q, p, g

q,p,g = Setup(qsize,psize)

#Key generation
def KeyGen(q, p, g):
    alpha = random.randint(1, q-2) # private key
    beta = pow(g, alpha, p)         # public key
    return alpha, beta

alpha, beta = KeyGen(q,p,g)

#Signature generation
def SignGen(message, q, p, g, alpha):
    sha = SHA3_256.new()
    sha.update(message)
    h = int.from_bytes(sha.digest(), byteorder='big')%q
    k = random.randint(1,q-2)    
    r = pow(g, k, p)%q
    s = (alpha*r -k*h)%q
    return s, r

#Signature verification
def SignVer(message, s, r, q, p, g, beta):
    sha = SHA3_256.new()
    sha.update(message)
    h = int.from_bytes(sha.digest(), byteorder='big')%q
    v = modinv(h,q)%q
    z1 = (s*v)%q
    z2 = (r*v)%q
    u = (modinv(pow(g,z1,p),p)*pow(beta,z2,p)%p)%q
    if u == r:
        return 0
    else:
        return -1

#GenerateOrRead function with parameter .txt file 
def GenerateOrRead(txt):   
    file = open(txt, "r+")
    output = file.read()
    if not output:
        qsize = 224
        psize = 2048 
        q,p,g = Setup(qsize,psize)
        pubparams = str(q) + '\n' + str(p) + '\n' + str(g)
        file.write(pubparams) 
        file.close()
        q = int(q)
        p = int(p)
        g = int(g)
        return q,p,g
    else:
        output = output.split('\n')
        q = output[0]
        p = output[1]
        g = output[2]
        file.close()
        q = int(q)
        p = int(p)
        g = int(g)
        return q,p,g
