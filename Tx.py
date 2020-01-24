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


def KeyGen(q, p, g):
    alpha = random.randint(1, q-2) # private key
    beta = pow(g, alpha, p)         # public key
    return alpha, beta

def SignGen(message, q, p, g, alpha):
    sha = SHA3_256.new()
    sha.update(message)
    h = int.from_bytes(sha.digest(), byteorder='big')%q
    k = random.randint(1,q-2)
    r = pow(g, k, p)%q
    s = (alpha*r -k*h)%q
    return s, r

#Random transaction generator function
def gen_random_tx(q, p, g):
    alpha_payer, beta_payer = KeyGen(q,p,g)
    alpha_payee, beta_payee = KeyGen(q,p,g)
    serial_number = random.getrandbits(128)
    amount = random.randint(1,1000000)
    message = ''.join("**** Bitcoin transaction ****" + '\n' + "Serial number: " + str(serial_number) + '\n' + "Payer public key (beta): "+ str(beta_payer) +'\n'+"Payee public key (beta): "+str(beta_payee)+'\n'+"Amount: " + str(amount)+'\n').encode('UTF-8')
    s_payer, r_payer = SignGen(message, q, p, g, alpha_payer)
    transaction = "**** Bitcoin transaction ****" + '\n' + "Serial number: " + str(serial_number) + '\n' + "Payer public key (beta): "+ str(beta_payer) +'\n'+"Payee public key (beta): "+str(beta_payee)+'\n'+"Amount: " + str(amount) +'\n'+"Signature (s): " +str(s_payer)+'\n'+"Signature (r): " + str(r_payer)
    return transaction

def gen_random_txblock(q, p, g, TxCnt, filename):
    for range in TxCnt:
        gen_random_tx(q,p,g)
        f= open("pubparams.txt","w+")
        f.write(TxCnt)
        f.close()

