#!/usr/bin/env bash
set -euo pipefail

RUNS="${RUNS:-100}"

if [[ $# -lt 4 || $# -gt 5 ]]; then
    echo "Uso: $0 <dataset> <imagem-chave> <public.pem> <private.pem> [saida.csv]" >&2
    echo "Exemplo: $0 input_ascii/input chave.png public.pem private.pem resultados.csv" >&2
    exit 1
fi

DATASET="$1"
IMAGEM="$2"
PUBLIC_KEY="$3"
PRIVATE_KEY="$4"
CSV="${5:-resultados.csv}"

AES="./aes"
RSA="./rsa"
IMSECRET="./ImSecret"

for programa in "$AES" "$RSA" "$IMSECRET"; do
    [[ -x "$programa" ]] || { echo "Executavel nao encontrado: $programa. Rode 'make all' primeiro." >&2; exit 1; }
done

[[ -d "$DATASET" ]] || { echo "Dataset nao encontrado: $DATASET" >&2; exit 1; }
[[ -f "$IMAGEM" ]] || { echo "Imagem-chave nao encontrada: $IMAGEM" >&2; exit 1; }
[[ -f "$PUBLIC_KEY" ]] || { echo "Chave publica nao encontrada: $PUBLIC_KEY" >&2; exit 1; }
[[ -f "$PRIVATE_KEY" ]] || { echo "Chave privada nao encontrada: $PRIVATE_KEY" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

media() {
    printf '%s\n' "$@" | awk '{s += $1} END {if (NR) printf "%.9f", s / NR; else print "0"}'
}

printf 'cenario,arquivo,tamanho_bytes,aes_encrypt_ms,aes_decrypt_ms,rsa_encrypt_ms,rsa_decrypt_ms,imsecret_encrypt_ms,imsecret_decrypt_ms\n' > "$CSV"

for cenario in scenario-01 scenario-02 scenario-03 scenario-04; do
    diretorio="$DATASET/$cenario"
    [[ -d "$diretorio" ]] || { echo "Diretorio ausente: $diretorio" >&2; exit 1; }

    for entrada in "$diretorio"/*.txt; do
        [[ -e "$entrada" ]] || continue

        arquivo=$(basename "$entrada")
        tamanho=$(stat -c '%s' "$entrada")

        aes_enc=()
        aes_dec=()
        rsa_enc=()
        rsa_dec=()
        ims_enc=()
        ims_dec=()

        aes_cifrado="$TMP/aes.enc"
        aes_decifrado="$TMP/aes.dec"
        rsa_cifrado="$TMP/rsa.enc"
        rsa_decifrado="$TMP/rsa.dec"
        ims_cifrado="$TMP/imsecret.enc"
        ims_decifrado="$TMP/imsecret.dec"

        for ((i = 0; i < RUNS; i++)); do
            aes_enc+=("$($AES -e -i "$entrada" -o "$aes_cifrado")")
            aes_dec+=("$($AES -d -i "$aes_cifrado" -o "$aes_decifrado")")
        done
        cmp -s "$entrada" "$aes_decifrado" || { echo "Falha na validacao AES: $entrada" >&2; exit 1; }

        for ((i = 0; i < RUNS; i++)); do
            rsa_enc+=("$($RSA -e -i "$entrada" -k "$PUBLIC_KEY" -o "$rsa_cifrado")")
            rsa_dec+=("$($RSA -d -i "$rsa_cifrado" -k "$PRIVATE_KEY" -o "$rsa_decifrado")")
        done
        cmp -s "$entrada" "$rsa_decifrado" || { echo "Falha na validacao RSA: $entrada" >&2; exit 1; }

        for ((i = 0; i < RUNS; i++)); do
            ims_enc+=("$($IMSECRET encrypt "$IMAGEM" "$entrada" "$ims_cifrado")")
            ims_dec+=("$($IMSECRET decrypt "$IMAGEM" "$ims_cifrado" "$ims_decifrado")")
        done
        cmp -s "$entrada" "$ims_decifrado" || { echo "Falha na validacao ImSecret: $entrada" >&2; exit 1; }

        media_aes_enc=$(media "${aes_enc[@]}")
        media_aes_dec=$(media "${aes_dec[@]}")
        media_rsa_enc=$(media "${rsa_enc[@]}")
        media_rsa_dec=$(media "${rsa_dec[@]}")
        media_ims_enc=$(media "${ims_enc[@]}")
        media_ims_dec=$(media "${ims_dec[@]}")

        printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
            "$cenario" "$arquivo" "$tamanho" \
            "$media_aes_enc" "$media_aes_dec" \
            "$media_rsa_enc" "$media_rsa_dec" \
            "$media_ims_enc" "$media_ims_dec" >> "$CSV"

        echo "$cenario/$arquivo concluido" >&2
    done
done

echo "CSV gerado em: $CSV" >&2
