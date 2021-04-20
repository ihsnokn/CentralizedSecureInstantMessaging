import sys, math, re

SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 */(),?;.:'
#mesajın kime gönderilip kimden alınacağına dair input girilmesi gerekir.
#Mesaj önce server'a gönderilecek.
#Server'dan client'a gönderilecek.
#Mesaj gönderilecek mi okunacak mı, bunun için de input gerekir.


def main():

    print("-Login to your account-")
    userName = input("Enter your username: ")
    password = input("Enter your password: ")
    
    with open ("users.txt") as f:
        if userName and password in f.read():
            print("Login Successfull!")
        else:
            print("Wrong username or password!!")
            main()

    messageFile = 'message.txt'
    print("Please choose one: write or read a message")
    action = input()

    if action == 'write':
        print("To whom do you want to send the message? Please write as username.")
        toWhom = input()
        print("Please type your message...")
        messageToBeSent = input()
        
        #toWhom icin string olarak alicinin public keyini yolla
        with open(userName+".txt") as userTxt:
            lines = userTxt.readlines()
            userTxt.close()
        for x in range(len(lines)):
            if toWhom in lines[x]:
                receiverPK=lines[x]
        
        receiverPublicKey=receiverPK.split(toWhom+"[",1)[1]        
        receiverPublicKey= receiverPublicKey[:-1]
        encryptMessage = writeToFile (messageFile, receiverPublicKey, messageToBeSent)
        print("You can see your message's encrypted version in message.txt file.")

    elif action == 'read':
        #print("From whom do you have a message? Please write as username.")
        #fromWhom = input()

        #burasi read
        with open(userName+".txt") as userTxt:
            lines = userTxt.readlines()
            userTxt.close()
        receiverPrivateKey=lines[0]
        
        receiverPrivateKey=receiverPrivateKey[1:]    
        receiverPrivateKey=receiverPrivateKey[:-2]
       

        print("Your message is: ")
        decryptMessage = readFromFile (messageFile, receiverPrivateKey)
        print(decryptMessage)

def getBlocksFromText(messageToBeSent, blockSize):
    # Converts a string message to a list of block integers.
    for character in messageToBeSent:
        if character not in SYMBOLS:
            print('ERROR: The symbol set does not have the character %s' % (character))
            sys.exit()
    blockInts = []
    for blockStart in range(0, len(messageToBeSent), blockSize):
        # Calculate the block integer for this block of text:
        blockInt = 0
        for i in range(blockStart, min(blockStart + blockSize, len(messageToBeSent))):
            blockInt += (SYMBOLS.index(messageToBeSent[i])) * (len(SYMBOLS) ** (i % blockSize))
        blockInts.append(blockInt)
    return blockInts

def getTextFromBlocks(blockInts, messageLength, blockSize):
    # Converts a list of block integers to the original message string.
    # The original message length is needed to properly convert the last
    # block integer.
    messageToBeSent = []
    for blockInt in blockInts:
        blockMessage = []
        for i in range(blockSize - 1, -1, -1):
            if len(messageToBeSent) + i < messageLength:
                # Decode the message string for the 128 (or whatever
                # blockSize is set to) characters from this block integer:
                charIndex = blockInt // (len(SYMBOLS) ** i)
                blockInt = blockInt % (len(SYMBOLS) ** i)
                blockMessage.insert(0, SYMBOLS[charIndex])
        messageToBeSent.extend(blockMessage)
    return ''.join(messageToBeSent)


def encryptMessage(messageToBeSent, key, blockSize):
    # Converts the message string into a list of block integers, and then
    # encrypts each block integer. Pass the PUBLIC key to encrypt.
    encryptedBlocks = []
    n, e = key

    for block in getBlocksFromText(messageToBeSent, blockSize):
        # ciphertext = plaintext ^ e mod n
        encryptedBlocks.append(pow(block, e, n))
    return encryptedBlocks


def decryptMessage(encryptedBlocks, messageLength, key, blockSize):
    # Decrypts a list of encrypted block ints into the original message
    # string. The original message length is required to properly decrypt
    # the last block. Be sure to pass the PRIVATE key to decrypt.
    decryptedBlocks = []
    n, d = key
    for block in encryptedBlocks:
        # plaintext = ciphertext ^ d mod n
        decryptedBlocks.append(pow(block, d, n))
    return getTextFromBlocks(decryptedBlocks, messageLength, blockSize)


def readKeyFile(keyFile):
    # Given the filename of a file that contains a public or private key,
    # return the key as a (n,e) or (n,d) tuple value.
    #fo = open(keyFilename)
    #content = fo.read()
    #fo.close()
    keySize, n, EorD = keyFile.split(',')
    return (int(keySize), int(n), int(EorD))

#keyFileName yerine alicinin public keyini gonder
def writeToFile(messageFilename, receiverPublicKey, messageToBeSent, blockSize=None):
    # Using a key from a key file, encrypt the message and save it to a
    # file. Returns the encrypted message string.
    keySize, n, e = readKeyFile(receiverPublicKey)
    if blockSize == None:
        # If blockSize isn't given, set it to the largest size allowed by the key size and symbol set size.
        blockSize = int(math.log(2 ** keySize, len(SYMBOLS)))
    # Check that key size is large enough for the block size:
    if not (math.log(2 ** keySize, len(SYMBOLS)) >= blockSize):
        sys.exit('ERROR: Block size is too large for the key and symbol set size. Did you specify the correct key file and encrypted file?')
    # Encrypt the message:
    encryptedBlocks = encryptMessage(messageToBeSent, (n, e), blockSize)

    # Convert the large int values to one string value:
    for i in range(len(encryptedBlocks)):
        encryptedBlocks[i] = str(encryptedBlocks[i])
    encryptedContent = ','.join(encryptedBlocks)

    # Write out the encrypted string to the output file:
    encryptedContent = '%s_%s_%s' % (len(messageToBeSent), blockSize, encryptedContent)
    fo = open(messageFilename, 'w')
    fo.write(encryptedContent)
    fo.close()
    # Also return the encrypted string:
    return encryptedContent


def readFromFile(messageFilename, receiverPrivateKey):
    # Using a key from a key file, read an encrypted message from a file
    # and then decrypt it. Returns the decrypted message string.
    keySize, n, d = readKeyFile(receiverPrivateKey)


    # Read in the message length and the encrypted message from the file:
    fo = open(messageFilename)
    content = fo.read()
    messageLength, blockSize, encryptedMessage = content.split('_')
    messageLength = int(messageLength)
    blockSize = int(blockSize)

    # Check that key size is large enough for the block size:
    if not (math.log(2 ** keySize, len(SYMBOLS)) >= blockSize):
        sys.exit('ERROR: Block size is too large for the key and symbol set size. Did you specify the correct key file and encrypted file?')

    # Convert the encrypted message into large int values:
    encryptedBlocks = []
    for block in encryptedMessage.split(','):
        encryptedBlocks.append(int(block))

    # Decrypt the large int values:
    return decryptMessage(encryptedBlocks, messageLength, (n, d), blockSize)


# If publicKeyCipher.py is run (instead of imported as a module) call
# the main() function.
if __name__ == '__main__':
    main()



