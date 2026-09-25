#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#define ENCRYPT_MODE 1
#define DECRYPT_MODE 0
#define OAEP_HASH_LEN 32  /* SHA-256 = 32 bytes */

static double agora_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

static void print_openssl_error(const char *message)
{
    fprintf(stderr, "%s\n", message);
    ERR_print_errors_fp(stderr);
}

static EVP_PKEY *load_public_key(const char *path)
{
    FILE *key_file = fopen(path, "rb");
    if (!key_file) {
        perror("Erro ao abrir a chave publica");
        return NULL;
    }

    EVP_PKEY *key = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
    fclose(key_file);

    if (!key)
        print_openssl_error("Erro ao ler a chave publica");

    return key;
}

static EVP_PKEY *load_private_key(const char *path)
{
    FILE *key_file = fopen(path, "rb");
    if (!key_file) {
        perror("Erro ao abrir a chave privada");
        return NULL;
    }

    EVP_PKEY *key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);

    if (!key)
        print_openssl_error("Erro ao ler a chave privada");

    return key;
}

static EVP_PKEY_CTX *create_rsa_context(EVP_PKEY *key, int mode)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx)
        return NULL;

    if (mode == ENCRYPT_MODE) {
        if (EVP_PKEY_encrypt_init(ctx) <= 0)
            goto error;
    } else {
        if (EVP_PKEY_decrypt_init(ctx) <= 0)
            goto error;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        goto error;

    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)
        goto error;

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0)
        goto error;

    return ctx;

error:
    print_openssl_error("Erro ao configurar RSA-OAEP");
    EVP_PKEY_CTX_free(ctx);
    return NULL;
}

static int rsa_encrypt(FILE *input, FILE *output, EVP_PKEY *key, double *tempo_ms)
{
    EVP_PKEY_CTX *ctx = create_rsa_context(key, ENCRYPT_MODE);
    *tempo_ms = 0.0;
    if (!ctx)
        return 0;

    /*
     * Um ciphertext RSA sempre tem o tamanho do modulo RSA.
     * Com OAEP/SHA-256, o maior plaintext por operacao e:
     *
     *     k - 2*hLen - 2
     *
     * em que k e o tamanho da chave em bytes e hLen = 32.
     * Para RSA-2048: 256 - 64 - 2 = 190 bytes.
     */
    size_t rsa_size = (size_t)EVP_PKEY_get_size(key);

    if (rsa_size <= 2 * OAEP_HASH_LEN + 2) {
        fprintf(stderr, "Chave RSA pequena demais para OAEP/SHA-256.\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    size_t plain_block_size = rsa_size - 2 * OAEP_HASH_LEN - 2;

    unsigned char *plain = malloc(plain_block_size);
    unsigned char *cipher = malloc(rsa_size);

    if (!plain || !cipher) {
        perror("malloc");
        free(plain);
        free(cipher);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    size_t bytes_read;

    while ((bytes_read = fread(plain, 1, plain_block_size, input)) > 0) {
        size_t cipher_len = rsa_size;

        double inicio = agora_ms();
        int ok = EVP_PKEY_encrypt(ctx, cipher, &cipher_len, plain, bytes_read);
        *tempo_ms += agora_ms() - inicio;

        if (ok <= 0) {
            print_openssl_error("Erro durante a criptografia RSA");
            free(plain);
            free(cipher);
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }

        if (fwrite(cipher, 1, cipher_len, output) != cipher_len) {
            perror("Erro ao escrever o arquivo cifrado");
            free(plain);
            free(cipher);
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }
    }

    if (ferror(input)) {
        perror("Erro ao ler o arquivo de entrada");
        free(plain);
        free(cipher);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    free(plain);
    free(cipher);
    EVP_PKEY_CTX_free(ctx);
    return 1;
}

static int rsa_decrypt(FILE *input, FILE *output, EVP_PKEY *key, double *tempo_ms)
{
    EVP_PKEY_CTX *ctx = create_rsa_context(key, DECRYPT_MODE);
    *tempo_ms = 0.0;
    if (!ctx)
        return 0;

    size_t rsa_size = (size_t)EVP_PKEY_get_size(key);

    unsigned char *cipher = malloc(rsa_size);
    unsigned char *plain = malloc(rsa_size);

    if (!cipher || !plain) {
        perror("malloc");
        free(cipher);
        free(plain);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    while (1) {
        size_t bytes_read = fread(cipher, 1, rsa_size, input);

        if (bytes_read == 0)
            break;

        /* Cada bloco cifrado RSA deve ter exatamente rsa_size bytes. */
        if (bytes_read != rsa_size) {
            fprintf(stderr, "Arquivo RSA invalido ou truncado.\n");
            free(cipher);
            free(plain);
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }

        size_t plain_len = rsa_size;

        double inicio = agora_ms();
        int ok = EVP_PKEY_decrypt(ctx, plain, &plain_len, cipher, rsa_size);
        *tempo_ms += agora_ms() - inicio;

        if (ok <= 0) {
            print_openssl_error("Erro durante a descriptografia RSA");
            free(cipher);
            free(plain);
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }

        if (fwrite(plain, 1, plain_len, output) != plain_len) {
            perror("Erro ao escrever o arquivo decriptografado");
            free(cipher);
            free(plain);
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }
    }

    if (ferror(input)) {
        perror("Erro ao ler o arquivo cifrado");
        free(cipher);
        free(plain);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    free(cipher);
    free(plain);
    EVP_PKEY_CTX_free(ctx);
    return 1;
}

static void print_usage(const char *program)
{
    printf(
        "Uso:\n"
        "  %s -e -i <entrada.txt> -k <public.pem>  -o <saida.rsa>\n"
        "  %s -d -i <entrada.rsa> -k <private.pem> -o <saida.txt>\n",
        program,
        program
    );
}

int main(int argc, char *argv[])
{
    int opt;
    int mode = -1;
    char *path_input = NULL;
    char *path_output = NULL;
    char *path_key = NULL;

    while ((opt = getopt(argc, argv, "edi:o:k:")) != -1) {
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

            case 'k':
                path_key = optarg;
                break;

            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (mode == -1 || !path_input || !path_output || !path_key) {
        print_usage(argv[0]);
        return 1;
    }

    FILE *input = fopen(path_input, "rb");
    if (!input) {
        perror("Erro ao abrir o arquivo de entrada");
        return 1;
    }

    FILE *output = fopen(path_output, "wb");
    if (!output) {
        perror("Erro ao abrir o arquivo de saida");
        fclose(input);
        return 1;
    }

    EVP_PKEY *key = NULL;

    if (mode == ENCRYPT_MODE)
        key = load_public_key(path_key);
    else
        key = load_private_key(path_key);

    if (!key) {
        fclose(input);
        fclose(output);
        remove(path_output);
        return 1;
    }

    double tempo_ms = 0.0;
    int success;

    if (mode == ENCRYPT_MODE)
        success = rsa_encrypt(input, output, key, &tempo_ms);
    else
        success = rsa_decrypt(input, output, key, &tempo_ms);

    printf("%.9f\n", tempo_ms);

    EVP_PKEY_free(key);
    fclose(input);
    fclose(output);

    if (!success) {
        remove(path_output);
        return 1;
    }

    return 0;
}
