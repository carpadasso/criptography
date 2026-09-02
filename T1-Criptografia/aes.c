#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT_MODE 1
#define DECRYPT_MODE 0
#define BUFFER_SIZE 4096

/* Chave AES-256: 32 bytes = 256 bits. */
const unsigned char Chave[32] = {
    0x01, 0x09, 0x11, 0x19,
    0x02, 0x0A, 0x12, 0x1A,
    0x03, 0x0B, 0x13, 0x1B,
    0x04, 0x0C, 0x14, 0x1C,
    0x05, 0x0D, 0x15, 0x1D,
    0x06, 0x0E, 0x16, 0x1E,
    0x07, 0x0F, 0x17, 0x1F,
    0x08, 0x10, 0x18, 0x20
};

/* Vetor de inicializacao do AES-CBC: 16 bytes = 128 bits. */
const unsigned char VI[16] = {
    0x10, 0x0F, 0x0E, 0x0D,
    0x0C, 0x0B, 0x0A, 0x09,
    0x08, 0x07, 0x06, 0x05,
    0x04, 0x03, 0x02, 0x01
};

static void print_openssl_error(const char *message)
{
    fprintf(stderr, "%s\n", message);
    ERR_print_errors_fp(stderr);
}

/*
 * Criptografa todo o conteudo de input usando AES-256-CBC.
 * Retorna 1 em caso de sucesso e 0 em caso de erro.
 */
int aes_encrypt(FILE *input, FILE *output)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char input_buffer[BUFFER_SIZE];
    unsigned char output_buffer[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    size_t bytes_read;
    int output_length;

    if (ctx == NULL) {
        print_openssl_error("Erro ao criar o contexto AES.");
        return 0;
    }

    /* Configura AES com chave de 256 bits no modo CBC. */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, Chave, VI) != 1) {
        print_openssl_error("Erro ao inicializar a criptografia AES.");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    while ((bytes_read = fread(input_buffer, 1, BUFFER_SIZE, input)) > 0) {
        if (EVP_EncryptUpdate(
                ctx,
                output_buffer,
                &output_length,
                input_buffer,
                (int)bytes_read) != 1) {
            print_openssl_error("Erro durante a criptografia AES.");
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }

        if (fwrite(output_buffer, 1, (size_t)output_length, output)
            != (size_t)output_length) {
            perror("Erro ao escrever o arquivo cifrado");
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
    }

    if (ferror(input)) {
        perror("Erro ao ler o arquivo de entrada");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /* Finaliza a operacao e acrescenta o padding PKCS#7 necessario. */
    if (EVP_EncryptFinal_ex(ctx, output_buffer, &output_length) != 1) {
        print_openssl_error("Erro ao finalizar a criptografia AES.");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (fwrite(output_buffer, 1, (size_t)output_length, output)
        != (size_t)output_length) {
        perror("Erro ao escrever o ultimo bloco cifrado");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

/*
 * Descriptografa todo o conteudo de input usando a mesma chave e o mesmo IV.
 * Retorna 1 em caso de sucesso e 0 em caso de erro.
 */
int aes_decrypt(FILE *input, FILE *output)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char input_buffer[BUFFER_SIZE];
    unsigned char output_buffer[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    size_t bytes_read;
    int output_length;

    if (ctx == NULL) {
        print_openssl_error("Erro ao criar o contexto AES.");
        return 0;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, Chave, VI) != 1) {
        print_openssl_error("Erro ao inicializar a descriptografia AES.");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    while ((bytes_read = fread(input_buffer, 1, BUFFER_SIZE, input)) > 0) {
        if (EVP_DecryptUpdate(
                ctx,
                output_buffer,
                &output_length,
                input_buffer,
                (int)bytes_read) != 1) {
            print_openssl_error("Erro durante a descriptografia AES.");
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }

        if (fwrite(output_buffer, 1, (size_t)output_length, output)
            != (size_t)output_length) {
            perror("Erro ao escrever o arquivo descriptografado");
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
    }

    if (ferror(input)) {
        perror("Erro ao ler o arquivo cifrado");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /*
     * Finaliza a descriptografia e valida/remove o padding.
     * Se a chave, o IV ou o arquivo estiverem incorretos, esta chamada pode falhar.
     */
    if (EVP_DecryptFinal_ex(ctx, output_buffer, &output_length) != 1) {
        fprintf(stderr,
                "Erro ao finalizar a descriptografia: chave/IV incorretos "
                "ou arquivo cifrado invalido.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (fwrite(output_buffer, 1, (size_t)output_length, output)
        != (size_t)output_length) {
        perror("Erro ao escrever o ultimo bloco descriptografado");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

static void print_usage(const char *program)
{
    fprintf(stderr,
            "Uso:\n"
            "  %s -e -i entrada.txt -o saida.aes\n"
            "  %s -d -i entrada.aes -o saida.txt\n",
            program,
            program);
}

int main(int argc, char *argv[])
{
    int opt;
    char *path_input = NULL;
    char *path_output = NULL;
    int mode = ENCRYPT_MODE;

    while ((opt = getopt(argc, argv, "edi:o:")) != -1) {
        switch (opt) {
            case 'e':
                mode = ENCRYPT_MODE;
                break;

            case 'd':
                mode = DECRYPT_MODE;
                break;

            case 'i':
                path_input = optarg;
                break;

            case 'o':
                path_output = optarg;
                break;

            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (path_input == NULL || path_output == NULL) {
        print_usage(argv[0]);
        return 1;
    }

    FILE *input = fopen(path_input, "rb");
    if (input == NULL) {
        perror("Erro ao abrir o arquivo de entrada");
        return 1;
    }

    FILE *output = fopen(path_output, "wb");
    if (output == NULL) {
        perror("Erro ao abrir o arquivo de saida");
        fclose(input);
        return 1;
    }

    clock_t start = clock();

    int success;

    if (mode == ENCRYPT_MODE) {
        success = aes_encrypt(input, output);
    } else {
        success = aes_decrypt(input, output);
    }

    clock_t end = clock();

    fclose(input);
    fclose(output);

    if (!success) {
        remove(path_output);
        return 1;
    }

    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;

    if (mode == ENCRYPT_MODE)
        printf("%.9f\n", elapsed);
    else
        printf("%.9f\n", elapsed);

    return 0;
}
