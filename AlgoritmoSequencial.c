#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <string.h>
#include "timer.h"

#define MAX 10
#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

typedef unsigned char byte;
// Conjunto de caracteres possíveis na senha (maiúsculas, minúsculas e dígitos)
char letters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";

/*
 * Função auxiliar para imprimir o hash MD5 em formato hexadecimal.
 */
void print_digest(const byte *hash){
    int x;
    for(x = 0; x < MD5_DIGEST_LENGTH; x++)
        printf("%02x", hash[x]);
    printf("\n");
}

/*
 * Função recursiva que gera todas as combinações possíveis de caracteres.
 * A cada combinação completa, calcula o MD5 da string gerada e compara
 * com o hash alvo fornecido na entrada.
 */
void iterate(const byte *hash1, char *str, int idx, int len, int *ok) {
    int c;
    int letters_len = (int) strlen(letters);

    // Se já encontrou a senha correta, interrompe a recursão
    if (*ok) return;

    // Caso ainda não tenha atingido o tamanho desejado da senha
    if (idx < (len - 1)) {
        // Percorre todos os caracteres possíveis para a posição atual
        for (c = 0; c < letters_len && *ok == 0; ++c) {
            str[idx] = letters[c];
            // Chamada recursiva para preencher a próxima posição
            iterate(hash1, str, idx + 1, len, ok);
        }
    } else {
        // Última posição da string: gera todas as combinações e compara os hashes
        for (c = 0; c < letters_len && *ok == 0; ++c) {
            str[idx] = letters[c];

            unsigned char hash2[MD5_DIGEST_LENGTH];

            // Cria um contexto de digest (estrutura de cálculo do MD5)
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            if (!ctx) {
                fprintf(stderr, "Erro: EVP_MD_CTX_new falhou\n");
                exit(1);
            }

            // Inicializa o contexto para o algoritmo MD5, insere a string e finaliza o cálculo
            if (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1 ||
                EVP_DigestUpdate(ctx, str, (size_t)len) != 1 ||
                EVP_DigestFinal_ex(ctx, hash2, NULL) != 1) {
                EVP_MD_CTX_free(ctx);
                fprintf(stderr, "Erro ao calcular MD5\n");
                exit(1);
            }
            EVP_MD_CTX_free(ctx);

            // Compara o hash gerado com o hash alvo
            if (memcmp(hash1, hash2, MD5_DIGEST_LENGTH) == 0) {
                str[len] = '\0'; // Garante terminação correta da string
                printf("Senha encontrada: %s\n", str);
                *ok = 1;
            }
        }
    }
}

/*
 * Converte uma string hexadecimal (32 caracteres) em um vetor de bytes (16 bytes).
 * Exemplo: "5d41402abc4b2a76b9719d911017c592" -> {0x5d, 0x41, 0x40, 0x2a, ...}
 */
void strHex_to_byte(const char *str, byte *hash){
    const char *pos = str;
    int i;
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        if (sscanf(pos, "%2hhx", &hash[i]) != 1) {
            fprintf(stderr, "Erro: entrada hexadecimal inválida na posição %d\n", i);
            exit(1);
        }
        pos += 2;
    }
}

/*
 * Função principal: lê o hash MD5 de entrada, converte-o em bytes e tenta encontrar
 * a senha original testando todas as combinações possíveis de caracteres (força bruta).
 */
int main(int argc, char **argv) {
    double start, end, delta; //calculo de tempo
   // clock_t start, end;
   // double cpu_time_used;
    //start = clock();
    char str[MAX+1];
    int lenMax = MAX;
    int len;
    int ok = 0;
    char hash1_str[2*MD5_DIGEST_LENGTH+1];
    byte hash1[MD5_DIGEST_LENGTH]; // Hash da senha alvo

    //verificação dos dados de entrada
    if(argc<2){
        puts("ERRO: a entrada deve conter: Nome do Programa - hash da senha\n");
        return 1;
    }

    if(strlen(argv[1]) != 2*MD5_DIGEST_LENGTH){
        puts("ERRO: o hash deve ter exatamente 32 caracteres hexadecimais\n");
        return 1;
    }

    GET_TIME(start); //começa a contagem de tempo

    //recebimento dos dados
    strncpy(hash1_str, argv[1], sizeof(hash1_str));
    hash1_str[sizeof(hash1_str)] = '\0';

    // Converte o hash de string hexadecimal para bytes
    strHex_to_byte(hash1_str, hash1);

    

    // Tenta todas as combinações possíveis de tamanhos de senha (de 1 a 10)
    for (len = 1; len <= lenMax && !ok; len++) {
        memset(str, 0, sizeof(str));
        str[len] = '\0'; // Garante terminação
        iterate(hash1, str, 0, len, &ok);
    }

    // Se nenhuma senha foi encontrada
    if (!ok) {
        printf("Senha não encontrada.\n");
    }
    GET_TIME(end); //termina a contagem de tempo
    
    delta = end - start; // calcula o tempo que foi gasto
    //Cálculo do tempo
    printf("TEMPO: %lf\n", delta);

    return 0;
}