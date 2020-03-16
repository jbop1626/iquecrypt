/*
    main.c
    Copyright © 2019, 2020 Jbop (https://github.com/jbop1626)

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
#include <string.h>

#include "io.h"
#include "crypt.h"
#include "extract.h"
#include "ecdh.h"

int main(int argc, char * argv[]) {
    int r = 0;
    if (argv[1] != NULL) {
        if (strcmp(argv[1], "decrypt") == 0 || strcmp(argv[1], "encrypt") == 0) {
            r = crypt_mode(argc, argv);
        }
        else if (strcmp(argv[1], "extract") == 0) {
            r = extract_mode(argc, argv);
        }
        else if (strcmp(argv[1], "ecdh") == 0) {
            r = ecdh_mode(argc, argv);
        }
        else if ((strcmp(argv[1], "--help") == 0) || strcmp(argv[1], "-h") == 0) {
            display_help();
            r = 1;
        }
        else {
            argument_error();
            r = 0;
        }
    }
    else {
        argument_error();
        r = 0;
    }
    // Internally, 1 = success and 0 = failure;
    // the OS generally sees the opposite.
    return !r;
}

