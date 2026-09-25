#include <opencv2/opencv.hpp>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <string>

using namespace std;

/* Constantes 
 * ASCII_INICIO: Primeiro caractere imprimível da tabela ASCII;
 * ASCII_TOTAL: Qntd. de caracteres imprimíveis da tabela ASCII;
 * BLOCO: Tamanho do bloco de cifragem/decifragem. */
const int ASCII_INICIO  = 32;
const int ASCII_TOTAL   = 95;
const int BLOCO         = 64;
int REPRESENTACAO       = 0;

/* Tabelas
 * F1: Uma tabela que converte (CARACTERE, PIXEL) -> PIXEL 
 * F2: Uma tabela que converte (PIXEL, PIXEL) -> CARACTERE
 * INVs: Mesmas tabelas F1 e F2, mas invertidas */
unsigned char f1[ASCII_TOTAL][256];
unsigned char f2[256][256];

unsigned char invF1[256][256];
unsigned char invF2[ASCII_TOTAL][256];


/* - - - - - - - - - - - - - - - - - - -
 * Funções Auxiliares
 * - - - - - - - - - - - - - - - - - - - */

int mdc(int a, int b) {
    while (b != 0) {
        int resto = a % b;
        a = b;
        b = resto;
    }
    return a;
}

/* Descobre um multiplicador que é coprimo do tamanho */
int multiplicador(unsigned int seed, int tamanho) {
    if (tamanho <= 1) return 0;

    int a = seed % tamanho;
    if (a == 0) a = 1;

    while (mdc(a, tamanho) != 1) a = (a + 1) % tamanho;
    return a;
}

/* Faz a permutação de uma posição de um índice via fórmula
 *                  (a * i + b) mod n
 **/
int permutar(int posicao, int tamanho, int a, int b) {
    if (tamanho <= 1) return 0;
    return (static_cast<long long>(a) * posicao + b) % tamanho;
}

/* Função que recebe um vetor e embaralha os seus elementos. */
void embaralhar(int *valores, int tamanho) {
    for (int i = tamanho - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int aux = valores[i];
        valores[i] = valores[j];
        valores[j] = aux;
    }
}

/* Função de criação das tabelas de cifra/decifra.
 * Ela preenche as tabelas F1 e F2, além de INVs 
 * Modo de Criação atual:
 * - Para cada coluna na tabela F1 (NumCols = 256):
 *   EMBARALHE OS 95 NÚMEROS INTERMEDIÁRIOS
 * - Para cada coluna na tabela F2 (NumCols = 256):
 *   EMBARALHE OS 95 CARACTERES DE SAÍDA */
void criarTabelas(unsigned int seed) {
    srand(seed);

    int intermediarios[256];
    int caracteres[ASCII_TOTAL];

    for (int k = 0; k < 256; k++) {
        for (int i = 0; i < 256; i++)
            intermediarios[i] = i;
        for (int i = 0; i < ASCII_TOTAL; i++)
            caracteres[i] = i;

        embaralhar(intermediarios, 256);
        embaralhar(caracteres, ASCII_TOTAL);

        for (int i = 0; i < ASCII_TOTAL; i++) {
            int num_intermediario = intermediarios[i];
            int caractere_saida = caracteres[i];

            f1[i][k] = num_intermediario;
            f2[num_intermediario][k] = caractere_saida;
            invF1[num_intermediario][k] = i;
            invF2[caractere_saida][k] = num_intermediario;
        }
    }
}

/* Retorna o valor do pixel em um determinado patch da imagem */
unsigned char pixel_patch(const cv::Mat &imagem, int patch, int posicao) {
    int x, y, patch_x, patch_y;
    int patches_linha;

    patches_linha = (imagem.cols + 7) / 8;
    patch_x = patch % patches_linha;
    patch_y = patch / patches_linha;
    x = patch_x * 8 + posicao % 8;
    y = patch_y * 8 + posicao / 8;
    

    if (y >= imagem.rows || x >= imagem.cols)
        return 255;
    return imagem.at<unsigned char>(y, x);
}

string ler_arquivo(const string &caminho) {
    ifstream arquivo(caminho, ios_base::binary);
    return string((istreambuf_iterator<char>(arquivo)), istreambuf_iterator<char>());
}


/* - - - - - - - - - - - - - - - - - - -
 * Funções da Criptografia
 * - - - - - - - - - - - - - - - - - - - */

/* Funções de codificação e decodificação dos caracteres '\n' e '\r' para caracteres ASCII
 * Isso é necessário para não aumentar o tamanho da tabela, nem entregar espaços no texto cifrado... */
string codificar(const string &texto) {
    string resultado;

    for (char c : texto) {
        if (c == '\n') resultado += "\\x0A";
        else if (c == '\r') resultado += "\\x0D";
        else resultado += c;
    }

    return resultado;
}

string decodificar(const string &texto) {
    string resultado;

    for (int i = 0; i < (int)texto.size(); i++) {
        if (i + 3 < (int)texto.size() && texto.substr(i, 4) == "\\x0A") {
            resultado += '\n';
            i += 3;
        } else if (i + 3 < (int)texto.size() && texto.substr(i, 4) == "\\x0D") {
            resultado += '\r';
            i += 3;
        } else {
            resultado += texto[i];
        }
    }

    return resultado;
}


/* Função de Cifra
 * 1) Faz a conversão dos '\n' e '\r' para um caractere de controle na forma hexadecimal
 * 2) Preenche as tabelas F1 e F2
 * 3) Gera os multiplicadores + deslocamentos para permutar os blocos de texto e os patches
 * 4) Para cada bloco de texto:
 *    - Permuta o bloco de texto
 *    - Permuta o patch correspondente
 *    - Para cada valor correspondente F1(caractere TEXTO, pixel CHAVE), joga numa representação intermediária
 *    - Para cada valor correspondente F2(pixel RI, pixel CHAVE), gera um caractere de saída
 *    - Coloca o caractere correspondente no texto cifrado
 * 5) Escreve o texto cifrado completo no arquivo de saída + seed de geração + tamanho
 */
void cifrar(const cv::Mat &imagem, const string &entrada, const string &saida) {
    string texto = codificar(ler_arquivo(entrada));
    int tamanho  = texto.size();

    unsigned int nonce = rand();
    criarTabelas(nonce);

    int num_blocos    = (texto.size() + BLOCO - 1) / BLOCO;
    int patches_linha = (imagem.cols + 7) / 8;
    int num_patches   = ((imagem.rows + 7) / 8) * patches_linha;

    texto.resize(num_blocos * BLOCO, '@');
    string cifra(num_blocos * BLOCO, ' ');
    unsigned char* rep = new unsigned char[num_blocos * BLOCO];

    unsigned int seed_texto = nonce ^ 0x11111111u;
    unsigned int seed_patch = nonce ^ 0x22222222u;

    int mult_texto   = multiplicador(seed_texto, num_blocos);
    int desloc_texto = num_blocos > 1 ? (seed_texto / 256) % num_blocos : 0;
    int mult_patch   = multiplicador(seed_patch, num_patches);
    int desloc_patch = num_patches > 1 ? (seed_patch / 256) % num_patches : 0;

    for (int bloco = 0; bloco < num_blocos; bloco++) {
        int bloco_texto = permutar(bloco, num_blocos, mult_texto, desloc_texto);
        int ind_patch   = bloco % num_patches;
        int patch       = permutar(ind_patch, num_patches, mult_patch, desloc_patch);

        for (int i = 0; i < BLOCO; i++) {
            unsigned char t = texto[bloco_texto * BLOCO + i] - ASCII_INICIO;
            unsigned char k = pixel_patch(imagem, patch, i);
            unsigned char r = f1[t][k];
            rep[bloco * BLOCO + i] = r;
            cifra[bloco * BLOCO + i] = char(f2[r][k] + ASCII_INICIO);
        }
    }

    /* Escrita do arquivo codificado */
    ofstream arquivo(saida, ios_base::binary);
    arquivo << nonce << "|" << tamanho << "|" << cifra;

    /* Se a flag estiver habilitada, gera uma imagem dessa representação intermediária */
    if (REPRESENTACAO == 1){
        int linhas = (num_blocos + patches_linha - 1) / patches_linha;
        cv::Mat intermediaria(linhas * 8, patches_linha * 8, CV_8UC1, cv::Scalar(255));

        for (int bloco = 0; bloco < num_blocos; bloco++) {
            for (int i = 0; i < BLOCO; i++) {
                int y = (bloco / patches_linha) * 8 + i / 8;
                int x = (bloco % patches_linha) * 8 + i % 8;
                intermediaria.at<unsigned char>(y, x) = rep[bloco * BLOCO + i];
            }
        }

        cv::imwrite(saida + "_rep.png", intermediaria);
        delete[] rep;
    }
}

/* Função de Decifra 
 * 1) Lê do arquivo de entrada seed + tamanho + texto cifrado 
 * 2) Cria as tabelas inversas de F1 e F2 pela seed
 * 4) Gera os mesmos multiplicadores e deslocamentos usados nas permutações dos blocos de texto e patches
 * 5) Para cada bloco da cifra: 
 *    - Determina, por permutação, a posição original do bloco de texto 
 *    - Determina, por permutação, qual patch da imagem foi usado
 *    - Para cada uma das 64 posições do bloco: 
 *       - Obtém o caractere cifrado C e o pixel correspondente da chave K 
 *       - Gera o valor da representação intermediária InvF2(caractere CIFRA, pixel CHAVE) 
 *       - Gera o caractere original InvF1(pixel RI, pixel CHAVE) e coloca no texto decifrado
 * 6) Remove o preenchimento do último bloco usando o tamanho original codificado
 * 7) Converte os caracteres "\x0A" e "\x0D" novamente para '\n' e '\r' 
 * 8) Escreve o texto decifrado no arquivo de saída
*/
void decifrar(const cv::Mat &imagem, const string &entrada, const string &saida) {
    ifstream arquivo(entrada, ios::binary);

    string seed_arquivo, tam_arquivo;
    getline(arquivo, seed_arquivo, '|');
    getline(arquivo, tam_arquivo, '|');

    unsigned int nonce = stoul(seed_arquivo);
    int tamanho = stoi(tam_arquivo);
    string cifra((istreambuf_iterator<char>(arquivo)), istreambuf_iterator<char>());

    criarTabelas(nonce);

    int num_blocos = cifra.size() / BLOCO;
    int num_patches = ((imagem.rows + 7) / 8) * ((imagem.cols + 7) / 8);
    string texto(num_blocos * BLOCO, ' ');

    unsigned int seed_texto = nonce ^ 0x11111111u;
    unsigned int seed_patch = nonce ^ 0x22222222u;
    int mult_texto   = multiplicador(seed_texto, num_blocos);
    int desloc_texto = num_blocos > 1 ? (seed_texto / 256) % num_blocos : 0;
    int mult_patch   = multiplicador(seed_patch, num_patches);
    int desloc_patch = num_patches > 1 ? (seed_patch / 256) % num_patches : 0;

    for (int bloco = 0; bloco < num_blocos; bloco++) {
        int bloco_texto = permutar(bloco, num_blocos, mult_texto, desloc_texto);
        int ind_patch   = bloco % num_patches;
        int patch       = permutar(ind_patch, num_patches, mult_patch, desloc_patch);

        for (int i = 0; i < BLOCO; i++) {
            unsigned char c = cifra[bloco * BLOCO + i] - ASCII_INICIO;
            unsigned char k = pixel_patch(imagem, patch, i);
            unsigned char r = invF2[c][k];
            texto[bloco_texto * BLOCO + i] = char(invF1[r][k] + ASCII_INICIO);
        }
    }

    texto.resize(tamanho);
    texto = decodificar(texto);

    /* Escrita do arquivo decodificado */
    ofstream resultado(saida, ios_base::binary);
    resultado.write(texto.data(), texto.size());
}


int main(int argc, char** argv) {
    if (argc < 5 || argc > 6) {
        cout << "Uso: ./ImSecret --cifra|--decifra [--rep] <chave.img> <entrada.txt> <saida.txt>\n";
        return 1;
    }

    string flag_rep  = argv[2];

    cv::Mat imagem;
    if (flag_rep == "--rep"){
        imagem = cv::imread(argv[3], cv::IMREAD_GRAYSCALE);
    }
    else {
        imagem = cv::imread(argv[2], cv::IMREAD_GRAYSCALE);
    }

    if (imagem.empty()) {
        cout << "Erro ao abrir a imagem.\n";
        return 1;
    }

    string flag_modo = argv[1];

    auto inicio = chrono::steady_clock::now();

    if (flag_modo == "--cifra"){
        if (flag_rep == "--rep"){
            REPRESENTACAO = 1;
            cifrar(imagem, argv[4], argv[5]);
        }
        else {
            cifrar(imagem, argv[3], argv[4]);
        }
    }
    else if (flag_modo == "--decifra")
        decifrar(imagem, argv[3], argv[4]);
    else {
        cout << "Uso: ./ImSecret --cifra|--decifra <chave.img> <entrada.txt> <saida.txt>\n";
        return 1;
    }

    double tempo = chrono::duration<double, milli>(chrono::steady_clock::now() - inicio).count();
    cout << fixed << setprecision(9) << tempo << "\n";

    return 0;
}
