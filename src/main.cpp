/*
	iQueCrypt v0.1.0
	iQue Player content decrypter and key extractor.

	Copyright © 2018 Jbop (https://github.com/jbop1626)

	This file is a part of iQueCrypt.

	iQueCrypt is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	iQueCrypt is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <iostream>
#include <string>
#include "iquecrypt.hpp"

const std::string ver = "1.0.0";

int main(int argc, char * argv[]) {
	std::cout << std::endl << "iQueCrypt v" << ver << std::endl;
	std::cout << "Copyright 2018 Jbop (https://github.com/jbop1626)" << std::endl << std::endl;
	if (argc < 2) {
		argument_error();
	}
	if (std::string(argv[1]) == "decrypt" || std::string(argv[1]) == "encrypt") {
		ique_crypt(argv, argc);
	}
	else if (std::string(argv[1]) == "extract") {
		ique_extract(argv, argc);
	}
	else if (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help") {
		display_help();
	}
	else {
		argument_error();
	}
	return 0;
}
