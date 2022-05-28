import random
import time
max_PrimLength = 1000000

'''
e ve phi nin modüler tersini hesaplar
'''
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

'''
iki int değerin ortak bölenini hesaplar
'''
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

'''
Sayının asallığını kontrol eder
'''
def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True

def generateRandomPrim():
    while(1):
        ranPrime = random.randint(0,max_PrimLength)
        if is_prime(ranPrime):
            return ranPrime

def generate_keyPairs():
    p = generateRandomPrim()
    q = generateRandomPrim()
    
    n = p*q
    print("n ",n)
    '''phi(n) = phi(p)*phi(q)'''
    phi = (p-1) * (q-1) 
    print("phi ",phi)
    
    '''n'ye asal e seç ve 1 > e > phi olsun'''    
    e = random.randint(1, phi)
    g = gcd(e,phi)
    while g != 1:
        e = random.randint(1, phi)
        g = gcd(e, phi)
        
    print("e=",e," ","phi=",phi)
    '''d[1] = e ve phi'nin modüler tersi'''
    d = egcd(e, phi)[1]
    
    '''d'nin pozitif olduğundan emin oluyoruz'''
    d = d % phi
    if(d < 0):
        d += phi
    
    print ("printing key pairs",(e,n),(d,n),"done")
    return ((e,n),(d,n))
        
def decrypt(ctext,private_key):
    try:
        key,n = private_key
        text = [chr(pow(char,key,n)) for char in ctext]
        return "".join(text)
    except TypeError as e:
        print(e)

def encrypt(text,public_key):
    key,n = public_key
    ctext = [pow(ord(char),key,n) for char in text]
    return ctext

if __name__ == '__main__':
    public_key,private_key = generate_keyPairs() 
    print("Public: ",public_key)
    print("Private: ",private_key)
    
    ctext = encrypt("IstanbulKulturUniversitesiMatematikBilgisayarBolumuKadirCemYunus",public_key)
    Time = time.perf_counter()
    print("encrypted  =",ctext)
    plaintext = decrypt(ctext, private_key)
    print("decrypted =",plaintext)
    print (time.perf_counter()-Time)