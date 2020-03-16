/*
    ecdh.c
    Routines for performing elliptic-curve Diffie-Hellman.
    After installation onto the iQue Player, a title's encryption key is itself
    encrypted with a unique key derived from ECDH between the console's unique
    ECC private key and an ECC public key in the title's ticket.
    This key is the 16 bytes starting at offset 4 in the x-coordinate of the
    resulting point.
    
    Copyright © 2020 Jbop (https://github.com/jbop1626)

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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "io.h"
#include "ecc/ecc.h"

#define OUT_KEY_SIZE 16
#define PVT_KEY_SIZE 32
#define PUB_KEY_SIZE 64


struct ecdh_args {
    int pvt_fn_i;
    int pub_fn_i;
};

static void parse_args(struct ecdh_args * a, int argc, char * argv[]) {
    int i;
    for (i = 2; i < argc; ++i) {
        if ((strcmp(argv[i], "-pvt") == 0) && (i < argc - 1)) {
            a->pvt_fn_i = i + 1;
        }
        else if ((strcmp(argv[i], "-pub") == 0) && (i < argc - 1)) {
            a->pub_fn_i = i + 1;
        }
    }
}


static void print_key(const unsigned char * out_key) {
    printf("The generated key is: ");
    int i;
    for (i = 0; i < 16; ++i) {
        printf("%02X", out_key[i]);
    }
    printf("\n");
}

static int output_key(const unsigned char * out_key) {
    if (save_to_file(out_key, "ecdh_key.bin", 16)) {
        printf("The ECDH-derived key has been generated and written to ecdh_key.bin.\n");
        print_key(out_key);
        return 1;
    }
    else {
        fprintf(stderr, "ERROR: Could not write ECDH-derived key to file!\n");
        return 0;
    }
}

static void format_key(unsigned char * out_key, const ec_point * Q) {
    int i, j;
    for (i = 1, j = 0; i < 5; ++i) {
        uint32_t limb  = Q->x[i];
        out_key[j]     = (unsigned char)((limb & 0xFF000000) >> 24);
        out_key[j + 1] = (unsigned char)((limb & 0x00FF0000) >> 16);
        out_key[j + 2] = (unsigned char)((limb & 0x0000FF00) >>  8);
        out_key[j + 3] = (unsigned char)((limb & 0x000000FF));
        j += 4;
    }
}

static int calculate_ecdh_result(unsigned char * out_key, const unsigned char * pvt_key, const unsigned char * pub_key) {
    element private_copy;
    ec_point public_copy;
    ec_point shared_secret;
    
    os_to_elem((uint8_t *)pvt_key, private_copy);
    os_to_point((uint8_t *)pub_key, &public_copy);
    
    if (!ec_point_on_curve(&public_copy)) {
        fprintf(stderr, "The ECC public key is not a valid point on the specified elliptic curve!\n");
        return 0;
    }
    else {
        ec_point_mul(private_copy, &public_copy, &shared_secret);
        format_key(out_key, &shared_secret);
        return 1;
    }
}

static int generate_ecdh_key(const char * pvt_key_filename, const char * pub_key_filename) {
    int result = 0;
    unsigned char * out_key = calloc(OUT_KEY_SIZE, sizeof(unsigned char));
    unsigned char * pvt_key = calloc(PVT_KEY_SIZE, sizeof(unsigned char));
    unsigned char * pub_key = calloc(PUB_KEY_SIZE, sizeof(unsigned char));
    if (out_key == NULL || pvt_key == NULL || pub_key == NULL) {
        fprintf(stderr, "ERROR: Could not allocate enough memory for ECC keys!\n");
    }
    else {
        size_t pvt_size = read_from_file(pvt_key, pvt_key_filename, PVT_KEY_SIZE);
        size_t pub_size = read_from_file(pub_key, pub_key_filename, PUB_KEY_SIZE);
        if (pvt_size != PVT_KEY_SIZE || pub_size != PUB_KEY_SIZE) {
            fprintf(stderr, "ERROR: An input file is not of the correct size!\n");
        }
        else if (calculate_ecdh_result(out_key, pvt_key, pub_key)) {
            result = output_key(out_key);
        }
    }
    free(out_key);
    free(pvt_key);
    free(pub_key);
    return result;
}


int ecdh_mode(int argc, char * argv[]) {
    struct ecdh_args a = { 0 };
    parse_args(&a, argc, argv);
    
    if (a.pvt_fn_i && a.pub_fn_i) {
        return generate_ecdh_key(argv[a.pvt_fn_i], argv[a.pub_fn_i]);
    }
    else {
        argument_error();
        return 0;
    }
}
