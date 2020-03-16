/*
    extract.c
    Routines for extracting keys and other data from content
    metadata files, an iQue Player's ticket.sys file, or from
    a dump of its Virage2 EEPROM.
    
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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "extract.h"
#include "io.h"

#define VIRAGE2_SIZE      0x100
#define SA_CMD_SIZE       0x1AC
#define FULL_CMD_SIZE     0x29AC
#define TICKET_ENTRY_SIZE 0x2B4C


struct extract_args {
    int cmd_fn_i;
    int tik_fn_i;
    int v2_fn_i;
    int cid_i;
    int all;
};

static void parse_args(struct extract_args * a, int argc, char * argv[]) {
    int i;
    for (i = 2; i < argc; ++i) {
        if ((strcmp(argv[i], "-cmd") == 0) && (i < argc - 1)) {
            a->cmd_fn_i = i + 1;
        }
        else if ((strcmp(argv[i], "-ticket") == 0) && (i < argc - 1)) {
            a->tik_fn_i = i + 1;
        }
        else if ((strcmp(argv[i], "-v2") == 0) && (i < argc - 1)) {
            a->v2_fn_i = i + 1;
        }
        
        if ((strcmp(argv[i], "-cid") == 0) && (i < argc - 1)) {
            a->cid_i = i + 1;
        }
        if (strcmp(argv[i], "-all") == 0) {
            a->all = 1;
        }
    }
}


static int extract_object(const unsigned char * object, size_t size, const char * id_str, const char * desc) {
    size_t str_length = strlen(id_str) + strlen(desc) + 1;
    char * filename = calloc(str_length, sizeof(char));
    if (filename != NULL) {
        strcpy(filename, id_str);
        strcat(filename, desc);
        int r = save_to_file(object, filename, size);
        free(filename);
        return r;
    }
    else {
        return 0;
    }
}

static void id_bytes_to_str(char * out_str, const unsigned char * id) {
    sprintf(out_str, "%02X%02X%02X%02X", id[0], id[1], id[2], id[3]);
}

static void id_str_to_bytes(unsigned char * out_bytes, const char * id) {
    char temp[9] = { 0 };
    strcpy(temp, id);
    for (int j = 3; j >= 0; --j) {
        out_bytes[j] = (unsigned char)(strtoul(&temp[j * 2], NULL, 16) & 0xFF);
        temp[j * 2] = '\0';
    }
}

static int is_hex(const char * str) {
    int i = 0;
    while (str[i] != '\0') {
        if (!isxdigit(str[i])) {
            return 0;
        }
        i++;
    }
    return 1;
}


/*
    Content Metadata Extraction
*/
static int extract_data_from_cmd(const unsigned char * cmd, size_t cmd_size) {
    size_t offset = (cmd_size == FULL_CMD_SIZE) ? 0x2800 : 0;
    const unsigned char * title_key_iv  = cmd + 0x14 + offset;
    const unsigned char * content_iv    = cmd + 0x38 + offset;
    const unsigned char * content_id    = cmd + 0x98 + offset;
    const unsigned char * title_key_enc = cmd + 0x9C + offset;

    char cid_str[9] = { 0 };
    id_bytes_to_str(cid_str, content_id);
    
    int a = extract_object(title_key_iv, 16, cid_str, "_title_key_iv.bin");
    int b = extract_object(content_iv, 16, cid_str, "_content_iv.bin");
    int c = extract_object(title_key_enc, 16, cid_str, "_title_key_enc.bin");
    
    if (a && b && c) {
        printf("Extraction from content metadata complete!\n");
        return 1;
    }
    else {
        fprintf(stderr, "ERROR: Unsuccessful extraction from content metadata!\n");
        return 0;
    }
}

static int extract_from_cmd_file(const char * filename) {
    unsigned char content_metadata[FULL_CMD_SIZE] = { 0 };
    size_t cmd_size = read_from_file(content_metadata, filename, FULL_CMD_SIZE);
    
    if (cmd_size != SA_CMD_SIZE && cmd_size != FULL_CMD_SIZE) {
        fprintf(stderr, "ERROR: Input file is not a content metadata file or is malformed!\n");
        return 0;
    }
    
    return extract_data_from_cmd(content_metadata, cmd_size);
}



/*
    Ticket Extraction
*/
static int get_ticket_count(unsigned char * ticket_count_out, FILE * ticket_file) {
    fseek(ticket_file, 3, SEEK_SET);
    size_t data_read = fread(ticket_count_out, sizeof(ticket_count_out[0]), 1, ticket_file);
    if (data_read != 1 || ferror(ticket_file) || feof(ticket_file)) {
        fprintf(stderr, "Error reading from ticket file!\n");
        return 0;
    }
    return 1;
}

static int find_ticket_entry(unsigned char * entry_buffer, FILE * ticket_file,
                             const unsigned char * content_id, unsigned char ticket_count) {
    int i;
    for (i = 1; i <= ticket_count; ++i) {
        size_t c = fread(entry_buffer, sizeof(entry_buffer[0]), TICKET_ENTRY_SIZE, ticket_file);
        if (c != TICKET_ENTRY_SIZE || ferror(ticket_file) || feof(ticket_file)) {
            fprintf(stderr, "Error reading from ticket file!\n");
            return 0;
        }
        else if (memcmp(entry_buffer + 0x2898, content_id, 4) == 0) {
            return 1;
        }
    }
    return 0;
}


static int get_ticket_entry(unsigned char * entry_buffer, const char * filename, const unsigned char * content_id) {
    FILE * ticket_file = NULL;
    if (!open_file(&ticket_file, filename, "rb")) {
        return 0;
    }
    
    int result = 0;
    unsigned char ticket_count = 0;
    if (get_ticket_count(&ticket_count, ticket_file)) {
        result = find_ticket_entry(entry_buffer, ticket_file, content_id, ticket_count);
    }
    else {
        result = 0;
    }
    
    if(fclose(ticket_file) == EOF) {
        fprintf(stderr, "Error closing ticket file!\n");
        result = 0;
    }
    
    return result;
}

static int extract_data_from_ticket(const unsigned char * entry) {
    const unsigned char * ticket_head_start = entry + FULL_CMD_SIZE;
    const unsigned char * content_id        = entry + 0x2898;
    const unsigned char * title_key_iv_2    = ticket_head_start + 0x10;
    const unsigned char * ecc_public_key    = ticket_head_start + 0x20;
    
    char cid_str[9] = { 0 };
    id_bytes_to_str(cid_str, content_id);
    
    int a = extract_object(title_key_iv_2, 16, cid_str, "_title_key_iv_2.bin");
    int b = extract_object(ecc_public_key, 64, cid_str, "_ecc_public_key.bin");
    
    if (a && b) {
        printf("Extraction from ticket head complete!\n");
        return 1;
    }
    else {
        fprintf(stderr, "ERROR: Unsuccessful extraction from ticket head!\n");
        return 0;
    }
}

static int extract_from_ticket_file(const char * filename, const char * cid) {
    if (strlen(cid) != 8 || !is_hex(cid)) {
        fprintf(stderr, "The provided Content ID is invalid.\n");
        fprintf(stderr, "Make sure it is in hexadecimal with all 8 digits.\n\n");
        return 0;
    }
    
    unsigned char content_id[4] = { 0 };
    id_str_to_bytes(content_id, cid);
    
    unsigned char * entry = calloc(TICKET_ENTRY_SIZE, sizeof(unsigned char));
    if (entry == NULL) {
        fprintf(stderr, "ERROR: Could not allocate enough memory for ticket entry!\n");
        return 0;
    }
    
    if (!get_ticket_entry(entry, filename, content_id)) {
        fprintf(stderr, "ERROR: Entry for %s not found in ticket file!\n", cid);
        free(entry);
        return 0;
    }
    
    printf("Entry for %s found in ticket file!\n", cid);
    
    int cmd_r = extract_data_from_cmd(entry, FULL_CMD_SIZE);
    int tkt_r = extract_data_from_ticket(entry);
    
    free(entry);
    return cmd_r && tkt_r;
}


/*
    Virage2 Dump Extraction
*/
static int confirm_v2_extraction(const char * message, int skip) {
    if (skip) {
        return 1;
    }
    
    printf("Extract %s? (y/n):", message);
    char in_buffer[64] = { 0 };
    if (get_input(in_buffer, 64, stdin)) {
        return tolower(in_buffer[0]) == 'y';
    }
    else {
        return 0;
    }
}

static int extract_v2_data(const unsigned char * v2, const char * bbid_str, int all_flag) {
    if (all_flag) {
        printf("Extracting files from Virage2 dump...\n");
    }
    if (confirm_v2_extraction("the secure kernel SHA-1 hash", all_flag)) {
        if (!extract_object(v2, 20, bbid_str, "_SK_hash.bin")) return 0;
    }
    if (confirm_v2_extraction("rom patch", all_flag)) {
        if (!extract_object(v2 + 20, 64, bbid_str, "_ROM_patch.bin")) return 0;
    }
    if (confirm_v2_extraction("the console's ECC public key", all_flag)) {
        if (!extract_object(v2 + 84, 64, bbid_str, "_ecc_public_key.bin")) return 0;
    }
    if (confirm_v2_extraction("the console's identification number", all_flag)) {
        if (!extract_object(v2 + 148, 4, bbid_str, "_BBID.bin")) return 0;
    }
    if (confirm_v2_extraction("the console's ECC private key", all_flag)) {
        if (!extract_object(v2 + 152, 32, bbid_str, "_ecc_private_key.bin")) return 0;
    }
    if (confirm_v2_extraction("the iQue common key", all_flag)) {
        if (!extract_object(v2 + 184, 16, "", "ique_common_key.bin")) return 0;
    }
    if (confirm_v2_extraction("the console's recrypt list key", all_flag)) {
        if (!extract_object(v2 + 200, 16, bbid_str, "_recrypt_list_key.bin")) return 0;
    }
    if (confirm_v2_extraction("the console's 1st unused key (appstate)", all_flag)) {
        if (!extract_object(v2 + 216, 16, bbid_str, "_appstate_key.bin")) return 0;
    }
    if (confirm_v2_extraction("the console's 2nd unused key (selfmsg)", all_flag)) {
        if (!extract_object(v2 + 232, 16, bbid_str, "_selfmsg_key.bin")) return 0;
    }
    if (confirm_v2_extraction("the Virage2 checksum for some reason", all_flag)) {
        if (!extract_object(v2 + 248, 4, bbid_str, "_v2_checksum.bin")) return 0;
    }
    if (confirm_v2_extraction("the JTAG enabler for some reason", all_flag)) {
        if (!extract_object(v2 + 252, 4, bbid_str, "_JTAG_enable.bin")) return 0;
    }
    if (all_flag) {
        printf("Extraction complete!\n");
    }
    return 1;
}

static int extract_from_virage2_file(const char * filename, int all_flag) {
    unsigned char * v2 = calloc(VIRAGE2_SIZE, sizeof(unsigned char));
    if (v2 == NULL) {
        fprintf(stderr, "ERROR: Could not allocate enough memory for Virage2 data!\n");
        return 0;
    }
    
    int result = 0;
    size_t data_read = read_from_file(v2, filename, VIRAGE2_SIZE);
    if (data_read != VIRAGE2_SIZE) {
        fprintf(stderr, "Error reading from Virage2 dump file!\n");
        result = 0;
    }
    else {
        char bbid_str[9] = { 0 };
        id_bytes_to_str(bbid_str, v2 + 148);
        if (!extract_v2_data(v2, bbid_str, all_flag)) {
            fprintf(stderr, "ERROR: Unsuccessful extraction from Virage2 dump!\n");
            result = 0;
        }
        else {
            result = 1;
        }
    }
    
    free(v2);
    return result;
}



int extract_mode(int argc, char * argv[]) {
    struct extract_args a = { 0 };
    parse_args(&a, argc, argv);
    
    if (a.cmd_fn_i) {
        return extract_from_cmd_file(argv[a.cmd_fn_i]);
    }
    else if (a.tik_fn_i && a.cid_i) {
        return extract_from_ticket_file(argv[a.tik_fn_i], argv[a.cid_i]);
    }
    else if (a.v2_fn_i) {
        return extract_from_virage2_file(argv[a.v2_fn_i], a.all);
    }
    else {
        argument_error();
    }
    return 0;
}
