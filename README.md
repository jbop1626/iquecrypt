### iQueCrypt

This is a tool for extracting the available encryption keys and initialization vectors from an [iQue Player's](https://en.wikipedia.org/wiki/IQue_Player) ticket.sys file, or from an individual title's content metadata (.cmd) file.  

Given the correct keys and initialization vectors, it can also be used to decrypt content from the iQue encrypted using AES CBC.  

More functionality (including decryption of twice-encrypted title keys and .rec files) will hopefully be possible, and subsequently added, soon.  

See [USAGE.md](/USAGE.md) for more information.  

AES implementation is from [tiny-AES](https://github.com/kokke/tiny-AES-c) by [kokke](https://github.com/kokke)
