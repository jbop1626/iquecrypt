### v1.2.1 - 2018 08 13  

* Fixed a bug when the filename of an app to encrypt or decrypt was passed as a file path.  

### v1.2.0 - 2018 06 22  

* Passing in "-all" when extracting from a Virage2 dump will extract all info in one go.  

* Arguments after the mode can be passed in any order.  

* Re-organized everything  

### v1.1.0 - 2018 06 13  

* The ability to extract keys and other info from a Virage2 dump was added.  

* A new mode, "ecdh", generates the ECDH-derived AES key used to re-encrypt the title key in a game's ticket. This requires the console's ECC private key (can be extracted from a v2 dump) and the ticket's ECC public key to  be provided in separate files.  

* A tiny bit of refactoring was done.  
  

### v1.0.0 - 2018 05 21  

* Some bugs have been fixed, the code was cleaned up, and there is now more robust error checking.  
  
* The ability to encrypt (not just decrypt) content and keys with AES has been added.  
  
* Incorporates the functionality of my (now obsolete) other program iquerectool, allowing the decryption, as well as encryption (i.e. injection), of .rec files. See USAGE for how to use this (it's similar to iquerectool).  
  
* Some bugs present in iquerectool were fixed, and the code was cleaned up.  

* When decrypting or encrypting a .rec it will print the recrypt key for the provided content ID, for future reference.  

* Arguments, except for the mode and the switch following it, can now be passed in any order.  
  

### v0.1.0 - 2018 04 28

* Initial release  

* Decrypts title keys and general content (e.g. .app files) from the iQue Player if given the appropriate encryption keys and initialization vectors.  
  
* Extracts the keys and ivs from .cmd files and ticket.sys  
