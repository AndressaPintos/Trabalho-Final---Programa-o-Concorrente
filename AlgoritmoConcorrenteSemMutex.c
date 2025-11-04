#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "timer.h"

#define MAX 10
#define MD5_DIGEST_LENGTH 16
#define LOG //comentar para retirar os logs


typedef unsigned char byte;

//Variáveis globais
byte hashSenha[MD5_DIGEST_LENGTH]; //recebe o hash original
//pthread_mutex_t mutex; //mutex para exclusao mutua da variável encontrado
int encontrado = 0; // flag atômica compartilhada entre threads

/* Conjunto de caracteres possíveis na senha (maiúsculas, minúsculas e dígitos) */
char letras[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";

/* Estrutura de argumentos para cada thread */
typedef struct {
    int inicioVet;      // índice inicial no array letras para a posição 0
    int fimVet;        // índice final
 } arg_t;


/* 
Parâmetros:
Um ponteiro para o hash original, a quantidade de caracteres da senha atual e um vetor de 16 bytes 
que irá receber o hash gerado.

Funcionamento:
Ela cria um contexto OpenSSL, i.e, é como se ele criasse um escopo temporário no qual executa o algoritmo MD5, advindo da
bilbioteca openssl/evp.h. Dentro desse escopo, ele processa nossa senha atual e devolve o hash correspondente
*/
static void CalcularMD5(const char *HashSenha, size_t TamSenhaAtual, byte saida[MD5_DIGEST_LENGTH]) {
    EVP_MD_CTX *contexto = EVP_MD_CTX_new();
    if (!contexto) {
        fprintf(stderr, "Erro: falha na criação de contexto EVP_MD_CTX\n");
        exit(1);
    }
    if (EVP_DigestInit_ex(contexto, EVP_md5(), NULL) != 1 ||
        EVP_DigestUpdate(contexto, HashSenha, TamSenhaAtual) != 1 ||
        EVP_DigestFinal_ex(contexto, saida, NULL) != 1) {
        EVP_MD_CTX_free(contexto);
        fprintf(stderr, "Erro ao calcular MD5\n");
        exit(1);
    }
    EVP_MD_CTX_free(contexto);
}

/* 
Parâmetros:
um ponteiro hash original, um ponteiro que vai armazenar as senhas canditadatas, indice da posição que vamos preencher (começa
segunda posição),
qauntidade de caracteres da senha e uma flag que indica se a senha já foi encontrada ou não.

Funcionamento
Primeiro ele verifica se a senha já foi encontrada. Se foi, ele retorna.

Senão, ele vê se já preencheu todas as posições da nova senha, com excessão da última posição.
Caso não tennha prenchido, ele inicia um loop e preenche.

Quando chega na última posição, ele a preenche, calcula o hash da senha e compara com o hash original.
Se forem iguais, muda a flag para 1 e fim do programa. Testa todas as letras e combinações.
*/
void iterate_recursive(char *str, int posAtual, int TamSenhaAtual) {
    int i;
    int qtdeLetras = (int) strlen(letras);

    if(encontrado) 
        return; 

    if (posAtual < (TamSenhaAtual - 1)) {
        for (i = 0; i < qtdeLetras && !encontrado; i++) {
            str[posAtual] = letras[i];
            iterate_recursive(str, posAtual + 1, TamSenhaAtual);
        }
    } else {
        for (i = 0; i < qtdeLetras && !encontrado; i++) {
            str[posAtual] = letras[i];
            byte hash2[MD5_DIGEST_LENGTH];
            CalcularMD5(str, (size_t)TamSenhaAtual, hash2);
            if (memcmp(hashSenha, hash2, MD5_DIGEST_LENGTH) == 0) {//comparar os hashes
                str[TamSenhaAtual] = '\0';
               // pthread_mutex_lock(&mutex);
                if (encontrado == 0) { // Verificação final (duplo cheque)
                    str[TamSenhaAtual] = '\0';
                    printf("Senha encontrada: %s\n", str);
                    encontrado = 1; //
                }
                //    pthread_mutex_unlock(&mutex);
                return;
            }
        }
    }
}

/* 
Função das threads

Funcionamento:
Cada thread irá gerar suas senhas e testá-las, respeitando o bloco definido no começo
*/
void *buscarSenha(void *argp) {
    arg_t *arg = (arg_t*)argp;
    //int qtdeLetras = (int) strlen(letras);

    // buffer local por thread
    char local_str[MAX + 1]; // +1 porque entra o \0 também
    memset(local_str, 0, sizeof(local_str)); //seta um valor na memória para evitar que fique algum lixo

    //passa por todos os tamanhos de senha

    for (int tam=1; tam <= MAX && !encontrado; ++tam){
        local_str[tam] = '\0';//adiciona o \0 para indicar o fim da string
        for (int i = arg->inicioVet; i < arg->fimVet && !encontrado; i++) {
            local_str[0] = letras[i];
            // Caso a senha só tennha 1 caracter, temos um loop simples; caso contrário, fixamos posição 1 e recursamos.
            if (tam == 1) {
                // somente calcular MD5 e comparar
                byte hash2[MD5_DIGEST_LENGTH];
                CalcularMD5(local_str, 1, hash2);
                if (memcmp(hashSenha, hash2, MD5_DIGEST_LENGTH) == 0) {
                 //   pthread_mutex_lock(&mutex);
                    if (encontrado == 0) { // Duplo cheque 
                        local_str[1] = '\0';
                        printf("Senha encontrada: %s\n", local_str);
                        encontrado = 1; // ESCRITA COM MUTEX
                    }
                  //  pthread_mutex_unlock(&mutex);
                    break;
                }
            } else {
                // completar recursivamente a partir da posição 2
                iterate_recursive(local_str, 1, tam);
            }
        }
        if (encontrado)
             break;
    }

    return NULL;
}

/* Converte string hex (32 chars) para bytes (16 bytes) */
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

int main(int argc, char **argv) {
    double start, end, delta; //calculo de tempo
    char hashString[2*MD5_DIGEST_LENGTH+1];
   // pthread_mutex_init(&mutex, NULL);
   

    //verificação dos dados de entrada
    if(argc<3){
        puts("ERRO: a entrada deve conter: Nome do Programa - hash da senha - Número de threads\n");
        return 1;
    }

    int nthreads = atoi(argv[2]);

    if(strlen(argv[1]) != 2*MD5_DIGEST_LENGTH){
        puts("ERRO: o hash deve ter exatamente 32 caracteres hexadecimais\n");
        return 1;
    }
    else if(nthreads <= 0){
        puts("ERRO: Número de threads deve ser maior do que zero\n");
        return 1;
    }

    GET_TIME(start); //começa a contagem de tempo

    //recebimento dos dados
    strncpy(hashString, argv[1], sizeof(hashString));
    hashString[sizeof(hashString)-1] = '\0';
    strHex_to_byte(hashString, hashSenha);
    

    #ifdef LOG
        puts("------Iniciando Programa------\n");
        printf("Número de threads: %d\nHash procurado: %s\n",nthreads,hashString);

    #endif

   
    int qtdeLetras = (int) strlen(letras);
    // Divide blocos de letras que cada thread processará baseado na quantidade de letras
    int blocoGeral = qtdeLetras / nthreads;
    int resto = qtdeLetras % nthreads;
    int id = 0;

    //criação das threads 
    pthread_t *threads = malloc(sizeof(pthread_t) * nthreads);
    arg_t *args = malloc(sizeof(arg_t) * nthreads);


    //inicialização das threads
    for (int i = 0; i < nthreads; i++) {
        int bloco = blocoGeral + (i < resto ? 1 : 0);//redistribuir as letras que sobraram
        int inicioVet = id;
        int fimVet = inicioVet + bloco;
        if (inicioVet >= qtdeLetras) {
            puts("thread está sem trabalho por não haver bloco de letras");
            inicioVet = fimVet = qtdeLetras;
        }

        
        //args[i].TamSenhaAtual = tam;
        args[i].inicioVet = inicioVet;
        args[i].fimVet = fimVet;

        id = fimVet;

        // Se o bloco está vazio, não cria thread (evita criar threads inúteis)
        if (inicioVet < fimVet) {
            if (pthread_create(&threads[i], NULL, buscarSenha, &args[i]) != 0) {
                fprintf(stderr, "Erro ao criar thread %d\n", i);
                exit(1);
               }
        } else {
            // marca thread inválida como zero (não será joinada)
            threads[i] = 0;
        }
    }

    // aguarda todas as threads com bloco válido
    for (int j = 0; j < nthreads; j++) {
        if (threads[j]) pthread_join(threads[j], NULL);
    }

    free(threads);
    free(args);
    

    if (!encontrado) {
        printf("Senha não encontrada.\n");
    }

    GET_TIME(end); //termina a contagem de tempo
    
    delta = end - start; // calcula o tempo que foi gasto
    //Cálculo do tempo
    printf("TEMPO: %lf\n", delta);

    //pthread_mutex_destroy(&mutex);

    return 1;
}