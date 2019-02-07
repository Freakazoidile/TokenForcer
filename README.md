# TokenForcer
Brute force weak, seemingly random values often used in session tracking such as cookies that rely on known inputs such as usernames and timestamps concatenated together and encoded

## Current Version: 1.00

```
  _____     _              _____                       
 |_   _|__ | | _____ _ __ |  ___|__  _ __ ___ ___ _ __ 
   | |/ _ \| |/ / _ \ '_ \| |_ / _ \| '__/ __/ _ \ '__|
   | | (_) |   <  __/ | | |  _| (_) | | | (_|  __/ |   
   |_|\___/|_|\_\___|_| |_|_|  \___/|_|  \___\___|_|   
```

### Why? 

I couldn't find something that did this how I wanted it done. I often got bored trying to craft and guess potential token values one by one.

TokenForcer was created in order to help web application security researchers and penetration testershelp identify weak, seemingly random values that are in fact created based on known inputs,such as for used in session tokens/cookies that are used to track and identify user sessions.

Sometimes these tokens may be a concatenation of data such as the username, password and the timestamp of when a user signed inand then hashed or encoded such as SHA1 or Base64.

### What?
TokenForcer is designed to help users quickly iterate through all possible permutations and combinations of potential data used to craft such a token.

### How Do I?
Basic usage will require an text file which has each of the suspected input values used to derive the final token on separate lines, the target token you want to match (e.g the value of the session cookie), and then the encoding and/or hashing combinations used to derive the final format of the token.

`python3 tokenForcer.py -i input.txt -o md5,b64 -t 81DC9BDB52D04DC20036DBD8313ED055`
```
-h --help   : Displays this help and exits without doing anything else! Derp!
-i --inputStrings    : (REQUIRED) Text file with each input parameter on a  new line
 Example: A user with the name 'Kimmi Raikkonen', login username 'kraikkonen', password of 'BW0AH' in a file called input.txt:
     Kimmi
     Raikkonen
     kraikkonen
     BW0AH
-d --delimiter   : (OPTIONAL) specify a custom delimiter (e.g: -d -+-)
-o --outputFormat   : Comma delimited string (NO SPACES) of supported output encodings/formats.
   Example: --outputFormat urlEncode,b64,md5
   The above example would urlEncode, then base64 encode then md5sum the results
   Supported output formats: 
       * md5
       * sha1
       * sha256
       * sha512
       * b64
       * hex (prints hex equivalent of string. e.g: ABC = 414243)
       * urlEncode (uses %20 to encode spaces)
       * urlPlusEncode (Uses + instead of %20 to encode spaces)
-t --target  : (OPTIONAL) supply the target string/token you are hoping to match with your inputs and encoding
   If token forcer identifies this putput of any of the combinations it tries it will print the output, the input used to achieve the matched output and then instantly quit.
   Example: --target 81DC9BDB52D04DC20036DBD8313ED055 (md5 sum)
-w --write   : (OPTIONAL) file to write output too, this is required if NO target parameter is provided
-v --verbose : NOT IMPLEMENTED YET!
```
### TODO, List of features coming soon:
* timestamp iterator. Sometimes devs will append the timestamp or date when creating a cookie, instead of having to change the value in the input file and re-running token forcer multiple times.
* delimiter permutations, combine multiple delimiters and create permutations of then when trying to crack the token
* verbose mode
* smart and more thorough target token detection type. Now it is simple regex and only detects the final encoding format used, e.g. base64 or md5sum
* Comment code better
* Implement more output format techniques (will require user feedback as to what is most popular and needed)
* More Error messages (part of verbose mode, USE COWSAY!!)
* cooler ascii art banner!* the ability to save a token creation scheme (probably use a database) so you can easily craft tokens once you have figure out how it is derived!


### Help I still don't get it?
To report bugs and create feature requests please create an issue on the github project page (THE PAGE YOUR ON NOW!): https://github.com/Freakazoidile/TokenForcer

For help you can find me on Twitter @freakazoidile https://twitter.com/freakazoidile
