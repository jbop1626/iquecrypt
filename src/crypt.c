/*
    crypt.c
    Routines for encrypting and decrypting various iQue Player files.
    
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

#include "crypt.h"
#include "io.h"
#include "aes/aes.h"

#define AES_KEY_SIZE  0x10
#define VIRAGE2_SIZE  0x100


struct crypt_args {
    int mode;
    int app_fn_i;
    int tk_fn_i;
    int rec_fn_i;
    int key_txt_i;
    int key_fn_i;
    int iv_txt_i;
    int iv_fn_i;
    int v2_fn_i;
    int rsys_fn_i;
    int cid_i;
    int out_fn_i;
};

static void parse_args(struct crypt_args * a, int argc, char * argv[]) {
    if (strcmp(argv[1], "encrypt") == 0) {
        a->mode = 1;
    }
    else if (strcmp(argv[1], "decrypt") == 0) {
        a->mode = 0;
    }

    for (int i = 2; i < argc; ++i) {
        if ((strcmp(argv[i], "-app") == 0) && (i < argc - 1)) {
            a->app_fn_i = i + 1;
        }
        else if ((strcmp(argv[i], "-tk") == 0) && (i < argc - 1)) {
            a->tk_fn_i = i + 1;
        }
        else if ((strcmp(argv[i], "-rec") == 0) && (i < argc - 1)) {
            a->rec_fn_i = i + 1;
        }
        else if ((strcmp(argv[i], "-key") == 0) && (i < argc - 1)) {
            a->key_txt_i = i + 1;
        }
        else if ((strcmp(argv[i], "-fkey") == 0) && (i < argc - 1)) {
            a->key_fn_i = i + 1;
        }
        else if ((strcmp(argv[i], "-iv") == 0) && (i < argc - 1)) {
            a->iv_txt_i = i + 1;
        }
        else if ((strcmp(argv[i], "-fiv") == 0) && (i < argc - 1)) {
            a->iv_fn_i = i + 1;
        }
        else if ((strcmp(argv[i], "-v2") == 0) && (i < argc - 1)) {
            a->v2_fn_i = i + 1;
        }
        else if ((strcmp(argv[i], "-rsys") == 0) && (i < argc - 1)) {
            a->rsys_fn_i = i + 1;
        }
        else if ((strcmp(argv[i], "-cid") == 0) && (i < argc - 1)) {
            a->cid_i = i + 1;
        }
        else if ((strcmp(argv[i], "-o") == 0) && (i < argc - 1)) {
            a->out_fn_i = i + 1;
        }
    }
}



/*
    General formatting / I/O routines
*/
static void id_str_to_bytes(unsigned char * out_bytes, const char * id) {
    char temp[9] = { 0 };
    strcpy(temp, id);
    for (int j = 3; j >= 0; --j) {
        out_bytes[j] = (unsigned char)(strtoul(&temp[j * 2], NULL, 16) & 0xFF);
        temp[j * 2] = '\0';
    }
}

static int read_aes_token_from_file(unsigned char * token_out, const char * token_str) {
    return read_from_file(token_out, token_str, AES_KEY_SIZE) == AES_KEY_SIZE;
}

static int read_aes_token_from_string(unsigned char * token_out, const char * token_str) {
    if (strlen(token_str) != AES_KEY_SIZE * 2) {
        fprintf(stderr, "ERROR: Input key or initialization vector is an incorrect size!\n");
        fprintf(stderr, "Make sure it is in hexadecimal with all 32 digits.\n");
        return 0;
    }
    
    char temp[3] = { 0 };
    int i = 0;
    int j = 0;
    while (i < (AES_KEY_SIZE * 2)) {
        temp[0] = token_str[i];
        temp[1] = token_str[i + 1];
        token_out[j] = strtoul(temp, NULL, 16) & 0xFF;
        
        i += 2;
        j++;
    }
    
    return 1;
}

static int read_aes_token(unsigned char * token_out, const char * token_str, int is_file) {
    if (is_file) {
        return read_aes_token_from_file(token_out, token_str);
    }
    else {
        return read_aes_token_from_string(token_out, token_str);
    }
}



/*
    General encryption routines
*/
static int crypt_block(unsigned char * block, struct AES_ctx * ctx, size_t length, int encrypt) {
    if (length % 16 != 0) {
        return 0;
    }
    
    if (encrypt) {
        AES_CBC_encrypt_buffer(ctx, block, length);
    }
    else {
        AES_CBC_decrypt_buffer(ctx, block, length);
    }
    
    return 1;
}

static int crypt_data_and_save_output(unsigned char * block, struct AES_ctx * ctx, FILE * input_file, FILE * output_file, int encrypt) {
    const char * mode = encrypt ? "En" : "De";
    printf("%scrypting file...\n", mode);
    
    while (1) {
        size_t read_data = fread(block, sizeof(block[0]), 0x1000, input_file);
        if (read_data == 0) {
            if (feof(input_file)) {
                printf("Complete!\n");
                return 1;
            }
            else {
                fprintf(stderr, "Error reading from input file! Aborting...\n");
                return 0;
            }
        }
        if (!crypt_block(block, ctx, read_data, encrypt)) {
            fprintf(stderr, "ERROR: Input file is not a multiple of 16. Try padding the file and trying again!\n");
            return 0;
        }
        if (fwrite(block, sizeof(block[0]), read_data, output_file) != read_data) {
            fprintf(stderr, "Error writing to output file! Aborting...\n");
            return 0;          
        }
    }
}

static int start_crypt_process(unsigned char * block, struct AES_ctx * ctx, const char * in_fn, const char * out_fn, int encrypt) {
    FILE * input_file = NULL;
    if (!open_file(&input_file, in_fn, "rb")) {
        fprintf(stderr, "Error opening input file for AES operations!\n");
        return 0;
    }
    
    FILE * output_file = NULL;
    if (!open_file(&output_file, out_fn, "wb")) {
        fprintf(stderr, "Error opening output file for AES operations!\n");
        fclose(input_file);
        return 0;
    }
    
    int result = crypt_data_and_save_output(block, ctx, input_file, output_file, encrypt);

    if (fclose(input_file) == EOF || fclose(output_file) == EOF) {
        fprintf(stderr, "Error closing file!\n");
        result = 0;
    }
    return result;
}

static int data_crypt(const char * in_fn, const char * out_fn, const unsigned char * key, const unsigned char * iv, int encrypt) {
    int result = 0;
    
    unsigned char * block = calloc(0x1000, sizeof(unsigned char));
    struct AES_ctx * ctx = calloc(1, sizeof(struct AES_ctx));
    if (block == NULL || ctx == NULL) {
        fprintf(stderr, "ERROR: Could not allocate enough memory for AES operations!\n");
    }
    else {
        AES_init_ctx_iv(ctx, (uint8_t *)key, (uint8_t *)iv);
        result = start_crypt_process(block, ctx, in_fn, out_fn, encrypt); 
    }
    
    free(block);
    free(ctx);
    return result;
}



/*
    Operations on .app files or title keys
*/
static int app_tk(const char * in_fn, const char * out_fn, const char * key_str, int key_is_file, const char * iv_str, int iv_is_file, int encrypt) {
    int result = 0;
    
    unsigned char * key = calloc(AES_KEY_SIZE, sizeof(unsigned char));
    unsigned char * iv  = calloc(AES_KEY_SIZE, sizeof(unsigned char));
    if (key == NULL || iv == NULL) {
        fprintf(stderr, "ERROR: Could not allocate enough memory for AES key and IV!\n");
    }
    else if (read_aes_token(key, key_str, key_is_file) && read_aes_token(iv, iv_str, iv_is_file)) {
        result = data_crypt(in_fn, out_fn, key, iv, encrypt);
    }   

    free(key);
    free(iv);
    return result;
}



/*
    Operations on recrypted titles
*/
static int check_rsys_entry(unsigned char * entry, int i, const unsigned char * recrypt_list_key,
                            const unsigned char * recrypt_list_iv, const unsigned char * cid, FILE * f) {
    
    int result = 0;
    
    if (fread(entry, sizeof(entry[0]), 32, f) == 32 && !ferror(f)) {
        struct AES_ctx * ctx = calloc(1, sizeof(struct AES_ctx));
        if (ctx == NULL) {
            fprintf(stderr, "ERROR: Could not allocate memory for AES operations on the recrypt list!\n");
        }
        else {
            AES_init_ctx_iv(ctx, (uint8_t *)recrypt_list_key, (uint8_t *)recrypt_list_iv);
            AES_CBC_decrypt_buffer(ctx, (uint8_t *)entry, 32);
            
            printf("Entry #%d: %02X%02X%02X%02X, Query: %02X%02X%02X%02X\n",
                    i+1, entry[0],entry[1],entry[2],entry[3], cid[0],cid[1],cid[2],cid[3]);
                
            if (memcmp(entry, cid, 4) == 0) {
                result = 1;
                printf("Entry found!\n");
            }
            free(ctx);
        }
    }
    else {
        fprintf(stderr, "ERROR: Could not read entry from recrypt.sys!\n");
    }
    
    return result;
}

static int get_num_rsys_entries(FILE * f) {
    unsigned char num_entries = 0;
    fseek(f, 0x43, SEEK_SET);
    
    size_t data_read = fread(&num_entries, sizeof(num_entries), 1, f);
    
    if (data_read == 1 && !ferror(f)) {
        return (int)num_entries;
    }
    else {
        return -1;
    }
}

static int get_recryption_key(unsigned char * key_out, const unsigned char * recrypt_list_key,
                              const unsigned char * recrypt_list_iv, const unsigned char * cid, const char * rsys_fn) {
    FILE * rsys_file = NULL;
    if (!open_file(&rsys_file, rsys_fn, "rb")) {
        fprintf(stderr, "ERROR: Could not open recrypt.sys file!\n");
        return 0;
    }
    
    int num_entries = get_num_rsys_entries(rsys_file);
    if (num_entries == -1 || num_entries > 0xA0) {
        fprintf(stderr, "ERROR: Number of entries in recrypt.sys file might be invalid!\n");
        fclose(rsys_file);
        return 0;
    }
    
    int result = 0;
    unsigned char * entry = calloc(32, sizeof(unsigned char));
    if (entry == NULL) {
        fprintf(stderr, "ERROR: Could not allocate enough memory for recrypt.sys entry!\n");
    }
    else {
        printf("Searching recrypt.sys entries (%d total)\n", num_entries);
        for (int i = 0; i < num_entries; ++i) {
            if (check_rsys_entry(entry, i, recrypt_list_key, recrypt_list_iv, cid, rsys_file)) {
                result = 1;
                memcpy(key_out, entry+4, 16);
                printf("Key read.\n");
                break;
            }
        }
    }
    
    if (result == 0) {
        fprintf(stderr, "No matching entry in recrypt.sys was found for the given content ID!\n");
    }
    
    if (fclose(rsys_file) == EOF) {
        fprintf(stderr, "Error closing recrypt.sys file!\n");
        result = 0;
    }
    free(entry);
    return result;
}

static void create_bbid_derived_iv(unsigned char * iv_out, const unsigned char * v2) {
    unsigned long temp = (((((v2[0x94] << 8) | v2[0x95]) << 8) | v2[0x96]) << 8) | v2[0x97];
    int i = 0;
    while (i < 16) {
        iv_out[i]     = (temp >> 24) & 0xFF;
        iv_out[i + 1] = (temp >> 16) & 0xFF;
        iv_out[i + 2] = (temp >>  8) & 0xFF;
        iv_out[i + 3] = temp & 0xFF;
        i += 4;
        temp++;
    }
}

static int get_recrypt_list_key_and_iv(unsigned char * key_out, unsigned char * iv_out, const char * v2_fn) {
    int result = 0;
    unsigned char * v2 = calloc(VIRAGE2_SIZE, sizeof(unsigned char));
    if (read_from_file(v2, v2_fn, VIRAGE2_SIZE) == VIRAGE2_SIZE) {
        memcpy(key_out, v2 + 0xC8, 16);
        create_bbid_derived_iv(iv_out, v2);
        result = 1;
    }
    else {
        fprintf(stderr, "Error reading Virage2 file!\n");
    }
    free(v2);
    return result;
}

static int rec(const char * rec_fn, const char * out_fn, const char * v2_fn, const char * rsys_fn,
               const char * cid, const char * iv_str, int iv_is_file, int encrypt) {
    
    int result = 0;
    
    unsigned char * recrypt_list_key = calloc(AES_KEY_SIZE, sizeof(unsigned char));
    unsigned char * recrypt_list_iv  = calloc(AES_KEY_SIZE, sizeof(unsigned char));
    unsigned char * rec_key          = calloc(AES_KEY_SIZE, sizeof(unsigned char));
    unsigned char * rec_iv           = calloc(AES_KEY_SIZE, sizeof(unsigned char));
    if (recrypt_list_key == NULL || recrypt_list_iv == NULL || rec_key == NULL || rec_iv == NULL) {
        fprintf(stderr, "ERROR: Could not allocate enough memory for AES keys and IVs!\n");
    }
    else {
        unsigned char content_id[4] = { 0 };
        id_str_to_bytes(content_id, cid);
        if (get_recrypt_list_key_and_iv(recrypt_list_key, recrypt_list_iv, v2_fn)) {
            int a = get_recryption_key(rec_key, recrypt_list_key, recrypt_list_iv, content_id, rsys_fn);
            int b = read_aes_token(rec_iv, iv_str, iv_is_file);
            if (a && b) {
                result = data_crypt(rec_fn, out_fn, rec_key, rec_iv, encrypt);
            }
        }
        else {
            fprintf(stderr, "ERROR: Could not obtain the necessary data to decrypt the recrypt list!\n");
        }
    }
    
    free(recrypt_list_key);
    free(recrypt_list_iv);
    free(rec_key);
    free(rec_iv);
    return result;
}



int crypt_mode(int argc, char * argv[]) {
    struct crypt_args a = { 0 };
    parse_args(&a, argc, argv);
    
    if ((a.app_fn_i || a.tk_fn_i)   &&
        (a.key_fn_i || a.key_txt_i) &&
        (a.iv_fn_i  || a.iv_txt_i)  && 
         a.out_fn_i)
    {
        int in_fn_i = a.app_fn_i ? a.app_fn_i : a.tk_fn_i;
        int k_i = a.key_fn_i ? a.key_fn_i : a.key_txt_i;
        int iv_i = a.iv_fn_i ? a.iv_fn_i : a.iv_txt_i;
        int key_is_file = k_i == a.key_fn_i;
        int iv_is_file = iv_i == a.iv_fn_i;
        return app_tk(argv[in_fn_i], argv[a.out_fn_i], argv[k_i], key_is_file, argv[iv_i], iv_is_file, a.mode);
    }
    
    else if (a.rec_fn_i  &&
             a.out_fn_i  &&
             a.v2_fn_i   &&
             a.rsys_fn_i &&
             a.cid_i     &&
             (a.iv_fn_i || a.iv_txt_i))
    {
        int iv_i = a.iv_fn_i ? a.iv_fn_i : a.iv_txt_i;
        int iv_is_file = iv_i == a.iv_fn_i;
        return rec(argv[a.rec_fn_i], argv[a.out_fn_i], argv[a.v2_fn_i], argv[a.rsys_fn_i], argv[a.cid_i], argv[iv_i], iv_is_file, a.mode);
    }
    
    else {
        argument_error();
        return 0;
    }
}

