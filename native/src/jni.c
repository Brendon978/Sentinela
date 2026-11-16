/* Ponte JNI entre o Kotlin (com.brendon978.sentinela.motor.Motor) e o motor em C.
 * Contrato C3 do plano. Só compila no Android (o CMake tira este arquivo dos testes no PC). */
#include <arpa/inet.h>
#include <jni.h>
#include <stdlib.h>
#include <string.h>

#include "bytes.h"
#include "sentinela.h"
#include "sn_dissecar.h"
#include "sn_pcap.h"

#define FN(nome) Java_com_brendon978_sentinela_motor_Motor_##nome

enum { BUF_EVENTOS = 256 * 1024 };

/* "10.111.0.53" ou "fd00:5e:1::53" -> sn_endereco. 0 se ok. */
static int texto_para_endereco(const char *s, sn_endereco *e) {
    memset(e, 0, sizeof *e);
    if (inet_pton(AF_INET, s, e->ip) == 1) {
        e->versao = 4;
        return 0;
    }
    if (inet_pton(AF_INET6, s, e->ip) == 1) {
        e->versao = 6;
        return 0;
    }
    return -1;
}

/* Lê até `max` endereços de um String[] do Kotlin. Devolve quantos válidos leu. */
static int le_enderecos(JNIEnv *env, jobjectArray arr, sn_endereco *dst, int max) {
    if (!arr)
        return 0;
    jsize n = (*env)->GetArrayLength(env, arr);
    int k = 0;
    for (jsize i = 0; i < n && k < max; i++) {
        jstring js = (jstring)(*env)->GetObjectArrayElement(env, arr, i);
        if (!js)
            continue;
        const char *s = (*env)->GetStringUTFChars(env, js, NULL);
        if (s && texto_para_endereco(s, &dst[k]) == 0)
            k++;
        if (s)
            (*env)->ReleaseStringUTFChars(env, js, s);
        (*env)->DeleteLocalRef(env, js);
    }
    return k;
}

/* Lê os DNS reais (porta 53) direto no vetor de destino. */
static int le_servidores(JNIEnv *env, jobjectArray arr, sn_servidor *dst, int max) {
    sn_endereco e[SN_MAX_DNS_REAIS];
    int n = le_enderecos(env, arr, e, max < SN_MAX_DNS_REAIS ? max : SN_MAX_DNS_REAIS);
    for (int i = 0; i < n; i++) {
        dst[i].endereco = e[i];
        dst[i].porta = 53;
    }
    return n;
}

JNIEXPORT jlong JNICALL FN(criar)(JNIEnv *env, jobject self, jstring pcap, jobjectArray virtuais,
                                  jobjectArray reais, jboolean forcar_tcp) {
    (void)self;
    sn_config c;
    memset(&c, 0, sizeof c);
    c.n_dns_virtual = le_enderecos(env, virtuais, c.dns_virtual, 2);
    c.n_dns_real = le_servidores(env, reais, c.dns_real, SN_MAX_DNS_REAIS);
    c.forcar_tcp = forcar_tcp ? 1 : 0;
    const char *caminho = pcap ? (*env)->GetStringUTFChars(env, pcap, NULL) : NULL;
    c.caminho_pcap = caminho;
    sn_motor *m = sn_motor_criar(&c); /* copia o que precisa; o caminho pode ser liberado */
    if (caminho)
        (*env)->ReleaseStringUTFChars(env, pcap, caminho);
    return (jlong)(intptr_t)m;
}

JNIEXPORT jint JNICALL FN(rodar)(JNIEnv *env, jobject self, jlong h, jint fd) {
    (void)env;
    (void)self;
    return sn_motor_rodar((sn_motor *)(intptr_t)h, fd);
}

JNIEXPORT void JNICALL FN(parar)(JNIEnv *env, jobject self, jlong h) {
    (void)env;
    (void)self;
    sn_motor_parar((sn_motor *)(intptr_t)h);
}

JNIEXPORT jbyteArray JNICALL FN(eventos)(JNIEnv *env, jobject self, jlong h) {
    (void)self;
    uint8_t *buf = malloc(BUF_EVENTOS);
    if (!buf)
        return (*env)->NewByteArray(env, 0);
    size_t n = sn_motor_eventos((sn_motor *)(intptr_t)h, buf, BUF_EVENTOS);
    jbyteArray arr = (*env)->NewByteArray(env, (jsize)n);
    if (arr && n)
        (*env)->SetByteArrayRegion(env, arr, 0, (jsize)n, (const jbyte *)buf);
    free(buf);
    return arr;
}

JNIEXPORT void JNICALL FN(trocarDns)(JNIEnv *env, jobject self, jlong h, jobjectArray reais) {
    (void)self;
    sn_servidor s[SN_MAX_DNS_REAIS];
    int n = le_servidores(env, reais, s, SN_MAX_DNS_REAIS);
    sn_motor_trocar_dns((sn_motor *)(intptr_t)h, s, n);
}

JNIEXPORT void JNICALL FN(encerrar)(JNIEnv *env, jobject self, jlong h) {
    (void)env;
    (void)self;
    sn_motor_encerrar((sn_motor *)(intptr_t)h);
}

JNIEXPORT void JNICALL FN(destruir)(JNIEnv *env, jobject self, jlong h) {
    (void)env;
    (void)self;
    sn_motor_destruir((sn_motor *)(intptr_t)h);
}

/* ---------------------------------------------------------------- Tarefa 12 */

JNIEXPORT jstring JNICALL FN(dissecar)(JNIEnv *env, jobject self, jbyteArray pacote) {
    (void)self;
    jsize n = (*env)->GetArrayLength(env, pacote);
    jbyte *p = (*env)->GetByteArrayElements(env, pacote, NULL);
    char *saida = malloc(32768);
    jstring r;
    if (p && saida) {
        sn_dissecar((const uint8_t *)p, (size_t)n, saida, 32768);
        r = (*env)->NewStringUTF(env, saida);
    } else {
        r = (*env)->NewStringUTF(env, "");
    }
    if (p)
        (*env)->ReleaseByteArrayElements(env, pacote, p, JNI_ABORT);
    free(saida);
    return r;
}

typedef struct {
    JNIEnv *env;
    jobjectArray arr;
    jsize n, cap;
} coleta_jni;

/* Cada pacote vira um byte[]: 8 bytes do carimbo (us, little-endian) + o pacote. */
static int coleta_pacote(void *ctx, uint64_t quando_us, const uint8_t *p, size_t n) {
    coleta_jni *c = ctx;
    if (c->n >= c->cap)
        return 1;
    jbyteArray b = (*c->env)->NewByteArray(c->env, (jsize)(n + 8));
    if (!b)
        return 1;
    uint8_t q[8];
    put_le64(q, quando_us);
    (*c->env)->SetByteArrayRegion(c->env, b, 0, 8, (const jbyte *)q);
    (*c->env)->SetByteArrayRegion(c->env, b, 8, (jsize)n, (const jbyte *)p);
    (*c->env)->SetObjectArrayElement(c->env, c->arr, c->n++, b);
    (*c->env)->DeleteLocalRef(c->env, b);
    return 0;
}

JNIEXPORT jobjectArray JNICALL FN(lerPacotes)(JNIEnv *env, jobject self, jstring caminho, jint proto,
                                              jstring ip_origem, jint porta_origem, jstring ip_destino,
                                              jint porta_destino, jlong desde_us, jlong ate_us, jint max) {
    (void)self;
    jclass cls = (*env)->FindClass(env, "[B");
    sn_tupla t;
    memset(&t, 0, sizeof t);
    sn_endereco eo, ed;
    const char *so = (*env)->GetStringUTFChars(env, ip_origem, NULL);
    const char *sd = (*env)->GetStringUTFChars(env, ip_destino, NULL);
    int ok = so && sd && texto_para_endereco(so, &eo) == 0 && texto_para_endereco(sd, &ed) == 0;
    if (so) (*env)->ReleaseStringUTFChars(env, ip_origem, so);
    if (sd) (*env)->ReleaseStringUTFChars(env, ip_destino, sd);
    if (!ok || max <= 0)
        return (*env)->NewObjectArray(env, 0, cls, NULL);
    t.versao = eo.versao;
    t.protocolo = (uint8_t)proto;
    memcpy(t.ip_origem, eo.ip, 16);
    memcpy(t.ip_destino, ed.ip, 16);
    t.porta_origem = (uint16_t)porta_origem;
    t.porta_destino = (uint16_t)porta_destino;

    /* lê numa lista do tamanho máximo e devolve só o que veio */
    coleta_jni c = {env, (*env)->NewObjectArray(env, max, cls, NULL), 0, max};
    const char *cam = (*env)->GetStringUTFChars(env, caminho, NULL);
    if (cam && c.arr)
        sn_pcap_ler_fluxo(cam, &t, (uint64_t)desde_us, (uint64_t)ate_us, (size_t)max, coleta_pacote, &c);
    if (cam)
        (*env)->ReleaseStringUTFChars(env, caminho, cam);
    jobjectArray r = (*env)->NewObjectArray(env, c.n, cls, NULL);
    for (jsize i = 0; r && i < c.n; i++) {
        jobject e = (*env)->GetObjectArrayElement(env, c.arr, i);
        (*env)->SetObjectArrayElement(env, r, i, e);
        (*env)->DeleteLocalRef(env, e);
    }
    return r;
}
