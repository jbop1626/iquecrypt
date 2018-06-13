### Usage

iquecrypt [mode]  

Possible modes: decrypt / encrypt / extract / ecdh   

#### decrypt  

Decrypts the given AES-CBC-encrypted file, using the provided key and initialization vector.  

If given an iQue .app file (e.g. downloaded content), it will decrypt using the appropriate title key and content iv, and output the result to the current directory. This option (-app) can also be used to decrypt content of any size or origin.  

If given an individual (once-encrypted) title key, it will decrypt using the iQue common key and title key iv (which can be found in the appropriate content metadata file).  

If given a re-encrypted .rec file, it will decrypt using the console's 256-byte [Virage2](http://www.iquebrew.org/index.php?title=Virage2) dump, the content iv of the title, the console's recrypt.sys file, and the content ID of the title.  

````
Usage:  
		decrypt -app [app file] -(f)key [title key] -(f)iv [content iv]  
		decrypt -tk [encrypted title key] -(f)key [common key] -(f)iv [title key iv]  
		decrypt -rec [rec file] -v2 [virage2 dump] -(f)iv [content iv] -rsys [recrypt.sys] -cid [content ID]  
		
Parameters:  	
		-app	.app file input  
		-tk	encrypted title key input  
		-rec	.rec file input  
		-key	encryption key input (in hexadecimal) on command line  
		-fkey	encryption key input from file  
		-iv	initialization vector input (in hexadecimal) on command line  
		-fiv	initialization vector input from file  
		-v2	256-byte dump of the appropriate console's Virage2  
		-rsys	recrypt list input (e.g. recrypt.sys)  
		-cid	content ID (in hexadecimal) of the title to be decrypted  
		
Example:  
		iquecrypt decrypt -app 0098967F.app -fkey title_key.bin -iv 123456789ABCDEF10111213141516171  
		Output: [dec]0098967F.app in same directory  
		
		iquecrypt decrypt -rec 0098967F.rec -v2 v2.bin -iv 123456789ABCDEF10111213141516171 -rsys recrypt.sys -cid 0098967f  
		Output: output.bin (containing decrypted contents of 0098967F.rec) in same directory  
````
	
#### encrypt  

Encrypts the given file with AES CBC encryption, using the provided key and initialization vector.  

If passed "-app" and given a plaintext file such as an N64 ROM, it will encrypt using the appropriate title key and content iv, and output the result to the current directory. This option (-app) can also be used to encrypt content of any size or origin.  

If passed "-tk" and given a plaintext title key, it will encrypt using the iQue common key and title key iv (which can be found in the appropriate content metadata file).  

If passed "-rec" and given a plaintext file such as an N64 ROM, it will encrypt the input so that it looks like a legitimate .rec to the iQue. This uses the console's 256-byte Virage2 dump, the content iv of the title, the console's recrypt.sys file, and the content ID of the title to be used as a "donor". Whatever is encrypted with this content ID will use that title's entry in ticket.sys/recrypt.sys, even if it is not the original title. This allows for "injection" of other games and custom programs. This command can be more simply performed using "-app" if the individual title's recrypt key is already known.  

````
Usage:  
		encrypt -app [app file] -(f)key [title key] -(f)iv [content iv]  
		encrypt -tk [encrypted title key] -(f)key [common key] -(f)iv [title key iv]  
		encrypt -rec [rec file] -v2 [virage2 dump] -(f)iv [content iv] -rsys [recrypt.sys] -cid [content ID]  
		
Parameters:  	
		-app	.app file input  
		-tk	title key input  
		-rec	prospective .rec file input  
		-key	encryption key input (in hexadecimal) on command line  
		-fkey	encryption key input from file  
		-iv	initialization vector input (in hexadecimal) on command line  
		-fiv	initialization vector input from file  
		-v2	256-byte dump of the appropriate console's Virage2  
		-rsys	recrypt list input (e.g. recrypt.sys)  
		-cid	content ID (in hexadecimal) of the title to be used as the host or donor for injection  
		
Example:  
		iquecrypt encrypt -app 0098967F.app -fkey title_key.bin -iv 123456789ABCDEF10111213141516171  
		Output: [dec]0098967F.app in same directory  
		
		iquecrypt encrypt -rec 0098967F.z64 -v2 v2.bin -fiv content_iv.bin -rsys recrypt.sys -cid 0098967f  
		Output: output.bin (containing encrypted contents of 0098967F.z64) in same directory  
````
		
#### extract  

Extracts information from a content metadata file, from a certain entry in a ticket.sys file, or from a Virage2 dump.  

If given a .cmd file, the encrypted title key, title key iv, and content iv will be extracted into the current directory.  

If a ticket.sys file is provided, it will also extract into the current directory the second title key iv and ECC public key contained in the ticket head.  

If given a Virage2 dump, the user will be prompted to choose (y/n) if they want to extract each of the various pieces of data it contains.  

````
Usage:  
		extract -cmd [cmd file]  
		extract -ticket [ticket file] -cid [content ID]  
		extract -v2 [virage2 dump]  
		
Parameters:  
		-cmd	.cmd file input  
		-ticket ticket file input (e.g. ticket.sys)  
		-cid	content ID (in hexadecimal) of requested entry in ticket.sys  
		-v2	Virage2 dump file input  
		
Examples:  
		iquecrypt extract -cmd 0098967F.cmd  
		Output: [cid]_title_key_enc.bin, [cid]_title_key_iv.bin, and [cid]_content_iv.bin  
		        in same directory.  
			   
		iquecrypt extract -ticket my_tickets -cid 0098967F  
		Output: [cid]_title_key_enc.bin, [cid]_title_key_iv.bin, [cid]_content_iv.bin,  
		        [cid]_title_key_iv_2.bin, and [cid]_ecc_public_key.bin in same directory.  
				
		iquecrypt extract -v2 v2.bin  
		Output: Depends on user input.  
````

#### ecdh  

Generates the ECDH-derived AES key (aka the "titlekek") used to re-encrypt the title key in a ticket entry. This requires the console's ECC private key and the ECC public key to be provided in separate files, which can be obtained using commands described above.  

Decrypting a twice-encrypted title key (e.g. using the decrypt mode with "-tk" passed) from a ticket with this key and the title key iv 2 from the ticket, and then decrypting *again* with the iQue common key and the title key iv from the cmd/ticket, will result in an app's plaintext title key.  

````
Usage:  
		ecdh -pvt [ECC priv key file] -pub [ECC pub key file]
		
Parameters:
		-pvt	ECC private key file input
		-pub	ECC public key file input

Example:
		iquecrypt ecdh -pvt 0B0E0E0F_ecc_private_key.bin -pub 0098967F_ecc_public_key.bin
		Output: ecdh_key.bin in same directory.
````
  
