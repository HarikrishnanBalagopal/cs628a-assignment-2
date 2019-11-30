# CS628A Assignment 2 (Programming Assignment 1)
#### This project is done as part of Programming Assignment 1 Part 3
<br/>
We are tasked with designing and implementing a secure file store using an insecure data store and a trusted key store.
<br/>
<br/>
The design for storing values in the data store is to encrypt them with AES and then calculate HMAC of the ciphertext<br/>
(Encrypt-then-MAC) scheme. This ensures we never decrypt data that has been tampered with. The location to store the<br/>
value at, the AES key and the HMAC key are all randomly generated.<br/>
<br/>
The user struct is a special case, the keys and locations of user structs are derived from the usernames and passwords.