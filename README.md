# cryptopals-node-ts

This repository contains my naive solutions to the Cryptopals Challenges written in Node.js.    

I used (and slightly modified) following implementations of SHA1 and MD4 for challenges 29 and 30:  
* https://github.com/chrisveness/crypto/blob/master/sha1.js
* http://pajhome.org.uk/crypt/md5/md5.html

## Set 1 - Basics

| Challenge                      | Status |Notes |
| -------------------------------|:----:| :-----:|
| 1. Convert hex to base64       | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set1/challenge1.ts) ||
| 2. Fixed XOR                   | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set1/challenge2.ts) ||
| 3. Single-byte XOR cipher      | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set1/challenge3.ts) ||
| 4. Detect single-character XOR | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set1/challenge4.ts) ||
| 5. Implement repeating-key XOR | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set1/challenge5.ts) ||
| 6. Break repeating-key XOR     | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set1/challenge6.ts) ||
| 7. AES in ECB mode             | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set1/challenge7.ts) ||
| 8. Detect AES in ECB mode      | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set1/challenge8.ts) ||

## Set 2 - Block crypto

| Challenge                                  | Status | Notes  |
| -------------------------------------------|:------:| :-----:|
| 9. Implement PKCS#7 padding                | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set2/challenge9.ts) ||
| 10. Implement CBC mode                     | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set2/challenge10.ts) ||
| 11. An ECB/CBC detection oracle            | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set2/challenge11.ts) ||
| 12. Byte-at-a-time ECB decryption (Simple) | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set2/challenge12.ts) ||
| 13. ECB cut-and-paste                      | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set2/challenge13.ts) ||
| 14. Byte-at-a-time ECB decryption (Harder) | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set2/challenge14.ts) ||
| 15. PKCS#7 padding validation              | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set2/challenge15.ts) ||
| 16. CBC bitflipping attacks                | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set2/challenge16.ts) ||

## Set 3 - Block & stream crypto

| Challenge                                           | Status |Notes |
| ----------------------------------------------------|:-------:| :-----:|
| 17. The CBC padding oracle                          | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set3/challenge17.ts) ||
| 18. Implement CTR, the stream cipher mode           | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set3/challenge18.ts) ||
| 19. Break fixed-nonce CTR mode using substitutions  | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set3/challenge19.ts) ||
| 20. Break fixed-nonce CTR statistically             | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set3/challenge20.ts) ||
| 21. Implement the MT19937 Mersenne Twister RNG      | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set3/challenge21.ts) ||
| 22. Crack an MT19937 seed                           | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set3/challenge22.ts) ||
| 23. Clone an MT19937 RNG from its output            | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set3/challenge23.ts) ||
| 24. Create the MT19937 stream cipher and break it   | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set3/challenge24.ts) ||

## Set 4 - Stream crypto and randomness

| Challenge                                                        | Status  |Notes |
| -----------------------------------------------------------------|:-------:| :-----:|
| 25. Break 'random access read/write' AES CTR                     | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set4/challenge25.ts) ||
| 26. CTR bitflipping                                              | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set4/challenge26.ts) ||
| 27. Recover the key from CBC with IV=Key                         | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set4/challenge27.ts) ||
| 28. Implement a SHA-1 keyed MAC                                  | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set4/challenge28.ts) ||
| 29. Break a SHA-1 keyed MAC using length extension               | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set4/challenge29.ts) ||
| 30. Break an MD4 keyed MAC using length extension                | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set4/challenge30.ts) ||
| 31. Implement and break HMAC-SHA1 with an artificial timing leak | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set4/challenge31.ts) ||
| 32. Break HMAC-SHA1 with a slightly less artificial timing leak  | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set4/challenge32.ts) |too slow?|

## Set 5 - Diffie-Hellman and friends

| Challenge                                                                         | Status  |Notes |
| ----------------------------------------------------------------------------------|:-------:| :-----:|
| 33. Implement Diffie-Hellman                                                      | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set5/challenge33.ts) ||
| 34. Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set5/challenge34.ts) ||
| 35. Implement DH with negotiated groups, and break with malicious 'g' parameters  | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set5/challenge35.ts) ||
| 36. Implement Secure Remote Password (SRP)                                        | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set5/challenge36.ts) ||
| 37. Break SRP with a zero key                                                     | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set5/challenge37-client.ts) ||
| 38. Offline dictionary attack on simplified SRP                                   | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set5/challenge38.ts) ||
| 39. Implement RSA                                                                 | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set5/challenge39.ts) ||
| 40. Implement an E=3 RSA Broadcast attack                                         | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set5/challenge40.ts) ||


## Set 6 - RSA and DSA

| Challenge                                                                         | Status  |Notes |
| ----------------------------------------------------------------------------------|:-------:| :-----:|
| 41. Implement unpadded message recovery oracle                                    | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set6/challenge41.ts)    ||
| 42. Bleichenbacher's e=3 RSA Attack                                               | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set6/challenge42.ts)    ||
| 43. DSA key recovery from nonce                                                   | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set6/challenge43.ts)    ||
| 44. DSA nonce recovery from repeated nonce                                        | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set6/challenge44.ts)    ||
| 45. DSA parameter tampering                                                       | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set6/challenge45.ts)    ||
| 46. RSA parity oracle                                                             | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set6/challenge46.ts)    ||
| 47. Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)                        | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set6/challenge47.ts)    ||
| 48. Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)                      | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set6/challenge48.ts)    ||

## Set 7 - Hashes

| Challenge                                                                         | Status  |Notes |
| ----------------------------------------------------------------------------------|:-------:| :-----:|
| 49. CBC-MAC Message Forgery                                                       | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set7/challenge49.ts)    ||
| 50. Hashing with CBC-MAC                                                          | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set7/challenge50.ts)    ||
| 51. Compression Ratio Side-Channel Attacks                                        | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set7/challenge51.ts)    ||
| 52. Iterated Hash Function Multicollisions                                        | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set7/challenge52.ts)    ||
| 53. Kelsey and Schneier's Expandable Messages                                     | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set7/challenge53.ts)    ||
| 54. Kelsey and Kohno's Nostradamus Attack                                         | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set7/challenge54.ts)    ||
| 55. MD4 Collisions                                                                | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set7/challenge55.ts)    ||
| 56. RC4 Single-Byte Biases                                                        | [:white_check_mark:](https://github.com/cgolian/matasano-cryptopals-ts/blob/dev/src/set7/challenge56.ts)    ||
