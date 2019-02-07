#!/usr/bin/env python

try:
    import sys
    sys.dont_write_bytecode = True

    import threading
    import getopt
    import hashlib
    import itertools
    import time
    import base64
    import re
    import math
    import urllib

except KeyboardInterrupt:
    errorMsg = "User Aborted"

    print(errorMsg)


def b64(toEncode):
    return base64.b64encode(toEncode.encode('utf-8'))


def checkIfMatch(thisToken, thisString):
    if thisToken == targetToken:
        print("This is a match!: {} and it is made of: {} ".format(thisToken, thisString))
        print("exiting!")
        exit()


def delimiterPermutations(permList, customDelim):
    if customDelim is None:
        delimiters = [';', ',', '-', '_', '=', '+', '.', '/', ':', '|', ' ']
    else:
        delimiters = [customDelim]
    resultList = []

    # print("delim is: {}".format(delimiters))

    for i in permList:
        permLen = len(i)
        count = 0

        for x in delimiters:
            if outputFormat is not None:
                checkIfMatch(finalEncode(x + x.join(i)), (x + x.join(i)))
                checkIfMatch(finalEncode(x.join(i) + x), (x.join(i) + x))
                checkIfMatch(finalEncode(x + x.join(i) + x), (x + x.join(i) + x))

                resultList.append(finalEncode(x + x.join(i)))
                resultList.append(finalEncode(x.join(i) + x))
                resultList.append(finalEncode(x + x.join(i) + x))

                if permLen == 1 and i[0] not in resultList:
                    checkIfMatch(finalEncode(x.join(i)), (x.join(i)))
                    resultList.append(finalEncode(x.join(i)))
                elif permLen > 1 and i[0] not in resultList:
                    checkIfMatch(finalEncode(x.join(i)), (x.join(i)))
                    resultList.append(finalEncode(x.join(i)))

                    for k in i:
                        # This count ensures that for single length permutations the base word doesn't get added for each delimiter.
                        # It also adds the no delimiter combination.
                        if count == 0:
                            if outputFormat is not None and ''.join(i) not in resultList:
                                checkIfMatch(finalEncode(''.join(i)), (''.join(i)))

                                resultList.append(finalEncode(''.join(i)))
                            elif ''.join(i) not in resultList:
                                resultList.append(''.join(i))
                        count += 1

            else:
                resultList.append(x+x.join(i))
                resultList.append(x.join(i) + x)
                resultList.append(x + x.join(i) + x)

                if permLen == 1 and x.join(i) not in resultList:
                    resultList.append(x.join(i))
                elif permLen > 1 and x.join(i) not in resultList:
                    resultList.append(x.join(i))

                    for k in i:
                        # This count ensures that for single length permutations the base word doesn't get added for each delimiter.
                        # It also adds the no delimiter combination.
                        if count == 0:
                            if outputFormat is not None and ''.join(i) not in resultList:
                                checkIfMatch(finalEncode(''.join(i)), (''.join(i)))

                                resultList.append(finalEncode(''.join(i)))
                            elif ''.join(i) not in resultList:
                                resultList.append(''.join(i))
                        count += 1

    return resultList


def detectTargetType(targetString):
    supportedTargets = {
        "md5": "(^[a-fA-F\d]{32}$)",
        "sha1": "(^[0-9a-f]{40}$)",
        "sha256": "(^[A-Fa-f0-9]{64}$)",
        "sha512": "(^\w{128}$)",
        "b64": "(^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$)"
    }

    targetType = []

    for i in supportedTargets:
        if re.match(supportedTargets[i], targetString) is not None:
            targetType.append(i)

    return targetType


# Iterate through each specified encoding method and execute them. Returns the final encoded string.
def finalEncode(thisString):
    finalString = thisString
    for encode in outputFormat:
        finalString = supportedOutputs[encode](finalString)
    return finalString


def hexEncode(toEncode):
    return toEncode.encode('utf8').hex()

# generates all possible permutations of provided input strings.
def inputPermutations(inputList):
    inputLen = len(inputList)
    resultPermutation = []

    for x in range(0, inputLen):
        for i in (itertools.permutations(inputList, x+1)):
            resultPermutation.append(list(i))
    return resultPermutation


def loadInputs(fileName):
    openFile = open(fileName)
    inputList = openFile.read().splitlines()
    openFile.close()

    return inputList


def main():

    # get arguments
    cmdArgs = sys.argv
    argumentList = cmdArgs[1:]

    # set up and declare variables
    global targetToken
    global outputFormat
    global supportedOutputs
    global toFileName

    outputFormat = None
    toFileName = None
    targetToken = None
    inputFile = []
    customDelim = None

    # supported arguments and Options
    unixOptions = "hd:o:i:t:w:v"
    gnuOptions = ["help", "inputStrings", "outputFormat", "target", "write", "verbose", "delimiter"]
    supportedOutputs = {'plain': plain, 'md5': md5, 'sha1': sha1, 'sha256': sha256, 'sha512': sha512, 'b64': b64, 'hex': hexEncode, 'url': urlEncode, 'urlPlus': urlPlusEncode}

    # print Banner
    print("  _____     _              _____                       ")
    print(" |_   _|__ | | _____ _ __ |  ___|__  _ __ ___ ___ _ __ ")
    print("   | |/ _ \| |/ / _ \ '_ \| |_ / _ \| '__/ __/ _ \ '__|")
    print("   | | (_) |   <  __/ | | |  _| (_) | | | (_|  __/ |   ")
    print("   |_|\___/|_|\_\___|_| |_|_|  \___/|_|  \___\___|_|   ")
    print("\n")

    try:
        arguments, values = getopt.getopt(argumentList, unixOptions, gnuOptions)
    except getopt.error as err:
        print (str(err))
        sys.exit(2)

    # parse through arguments
    for currentArgument, currentValue in arguments:
        if currentArgument in ("-v", "--verbose"):
            print ("not yet implemented, sorry.")
        elif currentArgument in ("-h", "--help"):
            showHelp()
            exit()
        elif currentArgument in ("--outputFormat"):
            encodeList = currentValue.split(",")
            outputFormat = []
            outputSupported = True

            for encodeType in encodeList:
                if encodeType.lower() in supportedOutputs:
                    outputFormat.append(encodeType.lower())
                else:
                    outputSupported = False
                    print("The following output encoding/hashing is not supported: {}, QUITING!".format(encodeType.lower()))
                    print("The supported output formats are: \n"
                        "       * plain (plain-text, no encoding. this shouldn't be needed.)\n"
                        "       * md5\n"
                        "       * sha1\n"
                        "       * sha256\n"
                        "       * sha512\n"
                        "       * b64\n"
                        "       * hex (prints hex equivalent of string. e.g: ABC = 414243)\n"
                        "       * urlEncode (uses %20 to encode spaces)\n"
                        "       * urlPlusEncode (Uses + instead of %20 to encode spaces)\n")
                    exit()
        elif currentArgument in ("-i", "--inputStrings"):
            inputFile = currentValue
        elif currentArgument in ("-t", "--target"):
            targetToken = currentValue
        elif currentArgument in ("-w", "--write"):
            toFileName = currentValue
        elif currentArgument in ("-d", "--delimiter"):
            customDelim = currentValue

    # Check if required arguments are required.
    # Output format OR target token needs to be provided. If both are not it will simply print all permutations
    # If output format and the guessed target token type are different the program will quit as a conclusive answer will never be reached

    if outputFormat is None and targetToken is None:
        print("No output format and no target token provided!")
        if toFileName is None:
            print("No output file name provided, dumping results to standard output")
    elif outputFormat is None:
        print("No output format provided, attempting to guess format based on the target token!")
        outputFormat = detectTargetType(targetToken)
        print("Target Token Type is: {}".format(outputFormat))
        if toFileName is None:
            print("No output file name provided, dumping results to standard output")
    elif targetToken is None:
        print("No target token provided!")
        if toFileName is None:
            print("No output file name provided, dumping results to standard output")
    # if output typed specified and determined output type don't match, quit. this caused issues. Either leave as is, and ignore, or re-implement as a warning whether or not to continue
    # else:
    #    targetToken = detectTargetType(targetToken)
    #    if targetToken != outputFormat:
    #        print("The provided output format and target token type do not match! Results will be inconclusive, quitting!")
    #        exit()

    # if no input, quit!
    if not inputFile:
        print("No input provided! Quitting!")
        exit()

    # Read the input file and assign it to a list "input List"
    inputList = loadInputs(inputFile)

    permCalc(inputList)
    # generate all permutations for the input list and store it in the permResult list
    permResult = list(inputPermutations(inputList))

    print("Number of input Perms is: {}".format(len(permResult)))
    #print(permResult)

    # send to delimiter permutations to generate the final list.
    finalStringList = delimiterPermutations(permResult, customDelim)

    if toFileName is not None:
        print("Results saved to: {}".format(toFileName))
        toFile(finalStringList)
    # for pToken in finalStringList:
        # tokenResults = supportedOutputs[outputFormat](pToken)
        # tokenResults


def permCalc(inputList):
    calcResult = 0

    loopRange = len(inputList)+1

    for i in range(1, loopRange, 1):
        calcResult += (math.factorial(len(inputList))/math.factorial((len(inputList) - i)))

    # print("The permutations should be: {}".format(calcResult))


def md5(toHash):
    resultString = hashlib.md5(toHash.encode())
    return resultString.hexdigest()


def plain(toPlain):
    return toPlain

def toFile(resultList):
    with open(toFileName, 'w') as file:
        file.writelines("%s\n" % item for item in resultList)

def sha1(toHash):
    resultString = hashlib.sha1(toHash.encode())
    return resultString.hexdigest()


def sha256(toHash):
    resultString = hashlib.sha256(toHash.encode())
    return resultString.hexdigest()


def sha512(toHash):
    resultString = hashlib.sha512(toHash.encode())
    return resultString.hexdigest()


def showHelp():
    print("Usage: \n\n"
          "TokenForcer was created in order to help web application security researchers and penetration testers"
          "help identify weak, seemingly random values that are in fact created based on known inputs,"
          "such as for used in session tokens/cookies that are used to track and identify user sessions.\n"
          "Sometimes these tokens may be a concatenation of data such as the username, password and the timestamp of when a user signed in"
          "and then hashed or encoded such as SHA1 or Base64.\n\n"
          "TokenForcer is designed to help users quickly iterate through all possible permutations and combinations of potential data"
          " used to craft such a token.\n\n"
          "Basic usage will require an text file which has each of the suspected input values "
          "used to derive the final token on separate lines, the target token you want to match "
          "(e.g the value of the session cookie), and then the encoding and/or hashing combinations "
          "used to derive the final format of the token.\n\n"
          "python3 tokenForcer.py -i input.txt -o md5,b64 -t 81DC9BDB52D04DC20036DBD8313ED055\n\n"
          "-h --help   : Displays this help and exits without doing anything else! Derp!\n"
          "-i --inputStrings    : (REQUIRED) Text file with each input parameter on a  new line\n"
          " Example: A user with the name 'Kimmi Raikkonen', login username 'kraikkonen', password of 'BW0AH' in a file called input.txt:\n"
          "     Kimmi\n"
          "     Raikkonen\n"
          "     kraikkonen\n"
          "     BW0AH\n"
          "-d --delimiter   : (OPTIONAL) specify a custom delimiter (e.g: -d -+-)\n"
          "-o --outputFormat   : Comma delimited string (NO SPACES) of supported output encodings/formats.\n"
            "   Example: --outputFormat urlEncode,b64,md5\n"
            "   The above example would urlEncode, then base64 encode then md5sum the results\n"
            "   Supported output formats: \n"
            "       * plain (plain-text, no encoding)\n"
            "       * md5\n"
            "       * sha1\n"
            "       * sha256\n"
            "       * sha512\n"
            "       * b64\n"
            "       * hex (prints hex equivalent of string. e.g: ABC = 414243)\n"
            "       * urlEncode (uses %20 to encode spaces)\n"
            "       * urlPlusEncode (Uses + instead of %20 to encode spaces)\n"
          "-t --target  : (OPTIONAL) supply the target string/token you are hoping to match with your inputs and encoding\n"\
            "   If token forcer identifies this putput of any of the combinations it tries it will print the output, the input used to achieve the matched output and then instantly quit.\n"
            "   Example: --target 81DC9BDB52D04DC20036DBD8313ED055 (md5 sum)\n"
          "-w --write   : (OPTIONAL) file to write output too, this is required if NO target parameter is provided\n"
          "-v --verbose : NOT IMPLEMENTED YET!\n\n"
          "TODO, List of features coming soon:\n"
          "* Create BurpSuite extension out of this tool for easier use!\n"
          "* timestamp iterator. Sometimes devs will append the timestamp or date when creating a cookie, instead of having to change "
            "the value in the input file and re-running token forcer multiple times.\n"
          "* delimiter permutations, combine multiple delimiters and create permutations of then when trying to crack the token\n"
          "* verbose mode\n"
          "* smart and more thorough target token detection type. Now it is simple regex and only detects the final encoding format used, e.g. base64 or md5sum\n"
          "* Comment code better\n"
          "* Implement more output format techniques (will require user feedback as to what is most popular and needed) currently thinking of addding: Octal, binary, gzip\n"
          "* More Error messages (part of verbose mode, USE COWSAY!!)\n"
          "* cooler ascii art banner!\n"
          "* the ability to save a token creation scheme (probably use a database) so you can easily craft tokens once you have figure out how it is derived!\n\n"
          "Current Version: 1.00\n\n"
          "To report bugs and create feature requests please create an issue on the github project page: https://github.com/Freakazoidile/TokenForcer\n"
          "For help you can find me on Twitter @freakazoidile https://twitter.com/freakazoidile\n\n"
          "")


def urlEncode(toEncode):
    return urllib.parse.quote(toEncode)


def urlPlusEncode(toEncode):
    return urllib.parse.quote_plus(toEncode)


if __name__ == "__main__":
    startTime = time.time()
    try:
        main()
        # print("%s seconds" % (time.time() - startTime))
    except KeyboardInterrupt:
        pass

else:
    print("failed to import")
