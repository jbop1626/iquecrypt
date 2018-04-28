### Usage

iquecrypt [mode]  

Possible modes: decrypt / extract  

decrypt  

Decrypts the given AES-CBC-encrypted file, using the provided key and initialization vector.  

If given an iQue .app file (e.g. downloaded content), it will decrypt using the appropriate title key and content iv, and output the result to the current directory.  

If given an individual (once-encrypted) title key, it will decrypt using the iQue common key and title key iv (which can be found in the appropriate content metadata file).  

Usage:  
		* decrypt -app [app file] -(f)key [title key] -(f)iv [content iv]  
		* decrypt -tk [encrypted title key] -(f)key [common key] -(f)iv [title key iv]  
		
Parameters:  	
		* -app	.app file input  
		* -tk		encrypted title key input  
		* -key	encryption key input (in hexadecimal) on command line  
		* -fkey	encryption key input from file  
		* -iv		initialization vector input (in hexadecimal) on command line  
		* -fiv	initialization vector input from file  
		
Example:  	
		iquecrypt -app 98967F.app -fkey title_key.bin -iv 123456789ABCDEF10111213141516171  
		Output: [dec]98967F.app in same directory  
		
		
extract  

Extracts information from a content metadata file, or from a certain entry in a ticket.sys file.  

If given a .cmd file, the encrypted title key, title key iv, and content iv will be extracted into the current directory.  

If a ticket.sys file is provided, it will also extract into the current directory the second title key iv and ECC public key contained in the actual ticket entry.  

Usage:  
		extract -cmd [cmd file]  
		extract -ticket [ticket file] -cid [content id]  
		
Parameters:  
		-cmd	.cmd file input  
		-ticket ticket file input (e.g. ticket.sys)  
		-cid	content id (in hexadecimal) of requested entry in ticket.sys  
		
Examples:  
		iquecrypt extract -cmd 98967F.cmd  
		Output: [cid]_title_key_enc.bin, [cid]_title_key_iv.bin, and [cid]_content_iv.bin in same directory.  
			   
		iquecrypt extract -ticket my_tickets -cid 98967F  
		Output: [cid]_title_key_enc.bin, [cid]_title_key_iv.bin, [cid]_content_iv.bin, [cid]_title_key_iv_2.bin, and [cid]_ecc_public_key.bin in same directory.
