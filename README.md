### iQueCrypt

This is a tool for extracting the available encryption keys and initialization vectors from an [iQue Player's](https://en.wikipedia.org/wiki/IQue_Player) ticket.sys file, from an individual title's content metadata (.cmd) file, or from the dump of a console's Virage2 EEPROM bank.  

Given the correct keys and initialization vectors, it can also be used to encrypt or decrypt content from the iQue using AES CBC. This includes .app files downloaded from the servers or found on a console, .rec files that have been re-encrypted by a specific console, and title keys.  

It can also be used to make an "injection", where a game or program (possibly homebrew) is encrypted with the key of a title already on the console. This causes the iQue to decrypt and launch the inject as if it were a legitimate application.  

Given a console's ECC private key, and an ECC public key from a game's entry in ticket.sys, iQueCrypt can generate the ECDH-derived key which is used to re-encrypt title keys in tickets. With this key a user can obtain the title keys of all games on their console.  

See [USAGE.md](/USAGE.md) for more information about the program, or [iQueBrew](http://www.iquebrew.org/) for more information about the console.  

AES implementation is from [tiny-AES](https://github.com/kokke/tiny-AES-c) by [kokke](https://github.com/kokke)  
