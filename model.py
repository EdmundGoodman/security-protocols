import time
import collections
import random

def chunks(braces):
    """helper function to pair a list up 1st with last, 2nd with
    penultimateetc."""
    newbraces = collections.OrderedDict()
    for i in range(0, int(len(braces)/2)):
        newbraces[braces[i]] = braces[-(i+1)]
    return newbraces

def encrypt(plain, keys):
    """The most basic private key encryption I could think of - the focus is not
    on cryptography #it works by multiplying the key(s) by the plaintext - both
    of which are numerically encoded"""
    superKey, cipher = 1, []
    for n in keys:
        superKey *= n
    for i in plain:
        cipher.append(i*superKey)
    return cipher        

def generateNonce():
    """Note this is NOT a timestamp, but merely a nonce based off the time"""
    #Ensure timestamps do not collide, compromising their use as nonces
    time.sleep(0.1)
    #Remove all zeroes, to eliminate math error
    return int(time.strftime('%S%M%H').replace("0", "")) 

def assignVariables(newMessageParts):
    """Long helper function to make a dictionary of variables, so they can be
    accessed #the sequence of if statements handeles different variable types"""
    message = []
    for newMessagePart in newMessageParts:
        while 1:
            try:
                message.append(variables[newMessagePart])
                break
            except:
                if "I" in newMessagePart:
                    variables[newMessagePart] = generateNonce()
                elif bool(set(["+", "-", "*", "/"]) & set(newMessagePart)):
                    newMessagePart = resolveOperands(newMessagePart)
                    variables[newMessagePart] = newMessagePart
                elif bool(set([str(x) for x in range(0, 3*10**3)]) & set(newMessagePart)):
                    variables[newMessagePart] = int(newMessagePart)
                else:
                    variables[newMessagePart] = random.randint(0, 35)
    return message

def resolveOperands(message):
    """Short helper function to "resolve operands" i.e. do the arithmetic"""
    message = [i for i in message]
    delList = []
    for i in ["+", "-", "*", "/"]:
        for n in range(0, len(message)):
            if message[n] == i:
                delList.append(n)
    for n in delList:
        exec("working = int(message[n-1]){}int(message[n+1])".format(message[n]))
        message.pop(n+1)
        message.pop(n)
        message[n-1] = working
    return message



needhamSchroederConventional2Way = [
    "A -> AS: A, B, I^A",
    "AS -> A: {I^A, B, CK, {CK, A}^KB}^KA",
    "A -> B: {CK, A}^KB",
    "B -> A: {I^B}^CK",
    "A -> B: {I^B - 1}^CK",
]
variables = {}
print("             AS <-> A              |", end="")
print("              A <-> B              |", end="")
print("              B <-> AS")
print("-----------------------------------|------------------", end="")
print("-----------------|-----------------------------------")
for step in needhamSchroederConventional2Way: #evaluate statement
    #Split up command into recipient and command
    command = step.split(": ")
    command[0] = (command[0].split(" -> "))
    recipient = [command[0][0], command[0][1], "public"]
    
    #Find braces so as to evaluate statement
    braces = [i for i, x in enumerate([i for i in command[1]]) if x == "{"]
    braces.extend([i for i, x in enumerate([i for i in command[1]]) if x == "}"])
    braces = chunks(braces)
    
    #Sse the positions of the braces to find the encryption keys and continue
    #cutting up the command
    encryptionKeys, messageParts = [], []
    for k, v in braces.items():
        encryptionKeys.append(command[1][(v+2):(v+4)])  
        messageParts.append(command[1][k:v+1])
    if messageParts == []:
        messageParts.append(command[1])
    if encryptionKeys == []:
        encryptionKeys.append('1')
    
    #Format the command to remove repeats and make linked lists of the 
    #schema (messageParts : encryptionKeys)
    for i in range(1, len(messageParts)):
        if messageParts[i] in messageParts[i-1]:
            startIndex = messageParts[i-1].find(messageParts[i]) - 2
            endIndex = startIndex + len(messageParts[i]) + 5
            messageParts[0] = messageParts[0].split(
                messageParts[0][startIndex:endIndex]
            )
            messageParts = [x for sublist in messageParts for x in sublist]
            messageParts = "".join(messageParts)
            messageParts = messageParts.split("{")[1:]
            messageParts = ["{"+x for x in messageParts]    
    for i in range(0, len(messageParts)):
        if "{" in messageParts[i]:
            messageParts = [l[1:-1] for l in messageParts]
            break
    
    #Assign values to the variables
    concFinalMessage = []
    for e in range(0, len(encryptionKeys)):
        formatEncryptionKeys = [encryptionKeys[i] for i in list(set(
            [ee for ee in range(0, e+1)]
        ))]
        splitMessageParts = messageParts[e].split(", ")
        message = assignVariables(splitMessageParts)
        keys = assignVariables(formatEncryptionKeys)
        finalMessage = encrypt(message, keys)
        concFinalMessage.append(finalMessage)

    #display the generated data in a tabular format
    comLen, mesLen, spaLen = len(command[1]), len(str(concFinalMessage)), 35
    comLen2, mesLen2 = (35-comLen)/2, (35-mesLen)/2
    space, line = spaLen*" ", spaLen*"-"
    com = int(comLen2)*" "+str(command[1])+(int(comLen2)+1)*" "
    mes = int(mesLen2)*" "+str(concFinalMessage)+(int(mesLen2)+1)*" "
    #print(com, mes, space)
    if command[0] == ['A', 'AS'] or command[0] == ['AS', 'A']:
        print("{}|{}|{}\n{}|{}|{}\n{}|{}|{}".format(
            com, space, space, mes, space, space, line, line, line)
        )
    if command[0] == ['A', 'B'] or command[0] == ['B', 'A']:
        print("{}|{}|{}\n{}|{}|{}\n{}|{}|{}".format(
            space, com, space, space, mes, space, line, line, line)
        )
    if command[0] == ['B', 'AS'] or command[0] == ['AS', 'B']:
        print("{}|{}|{}\n{}|{}|{}\n{}|{}|{}".format(
            space, space, com, space, space, mes, line, line, line)
        )
