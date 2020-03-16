/*
    io.c
    input/output utilities
    
    Copyright © 2018, 2019, 2020 Jbop (https://github.com/jbop1626)

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
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "io.h"

static const char * version = "1.3.0";
static const char * cr_year = "2018, 2019, 2020";

void display_help(void) {
    printf("iQueCrypt v%s\nCopyright %s Jbop (https://github.com/jbop1626)\n\n\n", version, cr_year);
    printf("USAGE:\n------\n");
    printf("Decrypt:\n");
    printf("1. decrypt -app [app file] -(f)key [title key] -(f)iv [content iv] -o [output file]\n");
    printf("2. decrypt -tk [encrypted title key] -(f)key [common key] -(f)iv [title key iv] -o [output file]\n");
    printf("3. decrypt -rec [rec file] -v2 [virage2 dump] -(f)iv [content iv] -rsys [recrypt.sys] -cid [content ID] -o [output file]\n\n");
    printf("Encrypt:\n");
    printf("1. encrypt -app [app file] -(f)key [title key] -(f)iv [content iv] -o [output file]\n");
    printf("2. encrypt -tk [plaintext title key] -(f)key [common key] -(f)iv [title key iv] -o [output file]\n");
    printf("3. encrypt -rec [app file] -v2 [virage2 dump] -(f)iv [content iv] -rsys [recrypt.sys] -cid [content ID] -o [output file]\n\n");
    printf("Extract:\n");
    printf("1. extract -cmd [cmd file]\n");
    printf("2. extract -ticket [ticket file] -cid [content ID]\n");
    printf("3. extract -v2 [virage2 dump] (-all)\n\n");
    printf("ECDH:\n");
    printf("1. ecdh -pvt [ECC priv key file] -pub [ECC pub key file]\n\n");
}

void argument_error(void) {
    fprintf(stderr, "ERROR: Invalid arguments.\n");
    fprintf(stderr, "Run iquecrypt with --help or -h for usage help and other info.\n\n");
}


int open_file(FILE ** file, const char * filename, const char * mode) {
    if (file == NULL || filename == NULL || mode == NULL) {
        fprintf(stderr, "ERROR: NULL argument(s) provided to open_file(). Opening file aborted.\n");
        return 0;
    }
    if(strlen(filename) > FILENAME_MAX) {
        fprintf(stderr, "ERROR: Filename is too long. Opening file aborted.\n");
        return 0;
    }
    
    errno = 0;
    *file = fopen(filename, mode);
    if (*file == NULL) {
        perror("Error opening file for reading");
        return 0;
    }
    else {
        return 1;
    }
}

size_t read_from_file(unsigned char * data_buffer, const char * filename, size_t data_length) {
    FILE * file = NULL;
    if (!open_file(&file, filename, "rb")) {
        return 0;
    }
    
    size_t data_read_count = fread(data_buffer, sizeof(data_buffer[0]), data_length, file);
    if (ferror(file)) {
        fprintf(stderr, "Error reading from file!\n");
        data_read_count = 0;
    }    
    
    if (fclose(file) == EOF) {
        fprintf(stderr, "Error closing file!\n");
        data_read_count = 0;
    }
    
    return data_read_count;
}

int save_to_file(const unsigned char * data, const char * filename, size_t data_length) {
    FILE * file = NULL;
    if (!open_file(&file, filename, "wb")) {
        return 0;
    }
    
    size_t data_written_count = fwrite(data, sizeof(data[0]), data_length, file);
    
    if (fclose(file) == EOF) {
        fprintf(stderr, "Error closing file!\n");
        return 0;
    }
    
    return (data_written_count == data_length);
}

int get_input(char * line_buffer, int buffer_length, FILE * instream) {
    char * result = fgets(line_buffer, buffer_length, instream);
    if (result == NULL || ferror(instream)) {
        fprintf(stderr, "ERROR: Could not read input!\n");
        line_buffer[0] = '\0';
        return 0;
    }

    // If fgets returned after hitting limit, discard extra characters in instream.
    // Otherwise it returned after receiving a newline; replace it with null.
    result = (char *)memchr(line_buffer, '\n', buffer_length);
    if (result == NULL) {
        while (getc(instream) != '\n');
    }
    else {
        result[0] = '\0';
    }

    return 1;
}


