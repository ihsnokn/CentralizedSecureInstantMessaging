import math
import random, sys, os, prime, cryptomath




print("Creat an account")
currentUser = input("Enter a username: ")
password = input("Enter a password: ")
users = [[currentUser, password]]
with open("users.txt", "a+") as txt_file:
    for line in users:
        txt_file.write(" ".join(line) + "\n")

print("Account created successfully")

def main():
    if (currentUser == 'server'):
        print("The server file is already created.")
    else:
        makeKeyFiles(currentUser, 1024)
        print("Key files for", currentUser, "created.")





def key_Generation(keySize):
    # Generating public and private keys with RSA Algorithm.
    p = 0
    q = 0
    #Here, we want p and q to be different numbers, that's why we make the loop search the prime numbers for p and q till they are not the same numbers.
    while p == q:
        p = prime.prime_Number_Generating(keySize)
        q = prime.prime_Number_Generating(keySize)
    n = p * q

   # print('Generating e that is relatively prime to (p-1)*(q-1)...')
    while True:
        # Searching a valid value for e.
        e = random.randrange(2 ** (keySize - 1), 2 ** (keySize))
        if cryptomath.gcd(e, (p - 1) * (q - 1)) == 1:
            break

    #Calculating d.
    #print('Calculating d that is mod inverse of e...')
    d = cryptomath.findModInverse(e, (p - 1) * (q - 1))

    publicKey = (n, e)
    privateKey = (n, d)
# Bu satırları çalıştırmaya gerek klamayacak. Çünkü public ve private keyler dosyalara yazdırılacak.
  #  print('Public key:', publicKey)
   # print('Private key:', privateKey)

    return (publicKey, privateKey)


def makeKeyFiles(name, keySize):

    # Our safety check will prevent us from overwriting our old key files:
    if os.path.exists('%s_PublicKey' % (name)) or os.path.exists('%s_PrivateKey' % (name)):
        sys.exit('WARNING: Key files for %s are already exists! Please use a different name.' % (name))

    publicKey, privateKey = key_Generation(keySize)

    print()
    
    #kullanici dosyasinda keyleri array olarak kaydet
    keys = [[keySize, privateKey[0], privateKey[1]], [keySize, publicKey[0], publicKey[1]]]
    with open(currentUser+".txt", "a+") as txt_file:
        for line in keys:
            txt_file.write("".join(str(line)) + "\n")
        txt_file.close()
    #diger kullanicilarin public keylerini al
    userList = []
    with open('users.txt') as my_file:
        for line in my_file:
            for word in line.split():
                userList.append(word)
    
    userNamesOnly = userList[::2]


    #Public key exchange with other users
    a=0
    while a<len(userNamesOnly):
    
        with open(userNamesOnly[a]+".txt", "a+") as txt_file:
            if currentUser != userNamesOnly[a]:
                txt_file.write(currentUser + str([keySize, publicKey[0], publicKey[1]]))
                txt_file.close()
                with open(userNamesOnly[a]+".txt", "r+") as txt_file:    
                    k = txt_file.readlines()
                with open(currentUser+".txt", "a+") as txt_file:
                    txt_file.write(userNamesOnly[a] + k[1])
        a +=1
                

if __name__ == '__main__':
    main()