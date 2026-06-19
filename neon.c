/*
 * neon.c — N.E.O.N. TUI
 *
 * Build (Developer Command Prompt for VS):
 *   cl /utf-8 /O2 /W3 /nologo neon.c ^
 *      advapi32.lib iphlpapi.lib version.lib ws2_32.lib user32.lib ^
 *      /Fe:neon.exe
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winver.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

/* ── Layout ──────────────────────────────────────────────────────────────── */

#define TITULO   "N.E.O.N."
#define COLUNAS  55
#define LINHAS   34
#define LARGURA_INTERNA (COLUNAS - 2)

/* BTL + BH + " " + TITULO + " " + N*BH + BTR = 13 + N = COLUNAS */
#define TRACOS_BORDA_TOPO (COLUNAS - 13)

/* ── Colors ──────────────────────────────────────────────────────────────── */

#define RST      "\033[0m"
#define BOLD     "\033[1m"
#define COR_VERDE   "\033[38;2;80;200;120m"
#define COR_VERMELHO  "\033[38;2;232;90;90m"
#define COR_CINZA  "\033[38;2;220;220;220m"
#define COR_AMARELO "\033[38;2;230;200;90m"
#define COR_BORDA "\033[38;2;100;160;220m"
#define COR_GUIA "\033[38;2;60;60;70m"
#define COR_SEPARADOR  "\033[38;2;70;80;95m"

/* ── Box-drawing ─────────────────────────────────────────────────────────── */

#define BH  "\xe2\x94\x80"
#define BV  "\xe2\x94\x82"
#define BTL "\xe2\x94\x8c"
#define BTR "\xe2\x94\x90"
#define BBL "\xe2\x94\x94"
#define BBR "\xe2\x94\x98"

/* ── Types ───────────────────────────────────────────────────────────────── */

typedef enum {
    ENTROU_ACTIVE_DIRECTORY,
    ENTROU_AZURE_AD,
    ENTROU_INTUNE_AZURE_AD,
    ENTROU_INTUNE_SOMENTE,
    ENTROU_SEM_GERENCIA,
} TipoEntrada;

typedef struct {
    /* atualizado a cada segundo */
    char     hora[16];
    char     data[16];
    double   cpuPorcentagem;
    double   memTotalMb;
    double   memDisponivelMb;
    int      firewall;
    int      proxy;
    int      acessoInterno;
    TipoEntrada tipoEntrada;
    char     tempoAtivo[32];
    /* coletado uma vez no início */
    char     fabricante[256];
    char     sistemaOperacional[256];
    char     usuario[128];
    char     nomeHost[128];
    char     adaptadorRede[128];
    char     descricaoRede[256];
    char     macRede[32];
    char     cpu[256];
    int      fortiTelemetria;
    char     fortClient[64];
    char     crowdStrike[64];
    char     netskope[64];
    char     kace[64];
    char     lumu[64];
    char     winApp[64];
} Snapshot;

/* ── String utilities ────────────────────────────────────────────────────── */

static void copiaSegura(char *destino, int tam, const char *origem)
{
    if (tam <= 0) return;
    strncpy(destino, origem, tam - 1);
    destino[tam - 1] = '\0';
}

static void aparaEspacos(char *txt)
{
    int tamanho = (int)strlen(txt);
    while (tamanho > 0 && (unsigned char)txt[tamanho - 1] <= ' ') txt[--tamanho] = '\0';
    char *ptr = txt;
    while ((unsigned char)*ptr <= ' ' && *ptr) ptr++;
    if (ptr != txt) memmove(txt, ptr, strlen(ptr) + 1);
}

static void removeTrecho(char *txt, const char *trecho)
{
    size_t tamTrecho = strlen(trecho);
    char *achou;
    while ((achou = strstr(txt, trecho)) != NULL)
        memmove(achou, achou + tamTrecho, strlen(achou + tamTrecho) + 1);
}

static void substituiTrecho(char *txt, const char *de, const char *para)
{
    size_t tamDe = strlen(de), tamPara = strlen(para);
    char *ptr = txt;
    while ((ptr = strstr(ptr, de)) != NULL) {
        memmove(ptr + tamPara, ptr + tamDe, strlen(ptr + tamDe) + 1);
        memcpy(ptr, para, tamPara);
        ptr += tamPara;
    }
}

static void juntaEspacos(char *txt)
{
    char *origem = txt, *destino = txt;
    while (*origem) {
        *destino++ = *origem;
        if (*origem == ' ')
            while (origem[1] == ' ') origem++;
        origem++;
    }
    *destino = '\0';
}

/* ── Registry ────────────────────────────────────────────────────────────── */

static int lerRegistroTexto(const char *caminho, const char *nome, char *saida, DWORD tamanho)
{
    HKEY  chave;
    DWORD tipo = REG_SZ, cb = tamanho;
    int   sucesso = 0;
    saida[0] = '\0';
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, caminho, 0, KEY_READ, &chave) == ERROR_SUCCESS) {
        sucesso = (RegQueryValueExA(chave, nome, NULL, &tipo, (LPBYTE)saida, &cb) == ERROR_SUCCESS);
        RegCloseKey(chave);
    }
    saida[tamanho - 1] = '\0';
    return sucesso;
}

static DWORD lerRegistroNumero(const char *caminho, const char *nome, DWORD padrao)
{
    HKEY  chave;
    DWORD valor = padrao, tipo = REG_DWORD, cb = sizeof(DWORD);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, caminho, 0, KEY_READ, &chave) == ERROR_SUCCESS) {
        RegQueryValueExA(chave, nome, NULL, &tipo, (LPBYTE)&valor, &cb);
        RegCloseKey(chave);
    }
    return valor;
}

static int existeChaveRegistro(const char *caminho)
{
    HKEY chave;
    int  ok = (RegOpenKeyExA(HKEY_LOCAL_MACHINE, caminho, 0, KEY_READ, &chave) == ERROR_SUCCESS);
    if (ok) RegCloseKey(chave);
    return ok;
}

static int lerRegistroTextoUsuario(const char *caminho, const char *nome, char *saida, DWORD tamanho)
{
    HKEY  chave;
    DWORD tipo = REG_SZ, cb = tamanho;
    int   sucesso = 0;
    saida[0] = '\0';
    if (RegOpenKeyExA(HKEY_CURRENT_USER, caminho, 0, KEY_READ, &chave) == ERROR_SUCCESS) {
        sucesso = (RegQueryValueExA(chave, nome, NULL, &tipo, (LPBYTE)saida, &cb) == ERROR_SUCCESS);
        RegCloseKey(chave);
    }
    saida[tamanho - 1] = '\0';
    return sucesso;
}

/* ── Display width & leader dots ─────────────────────────────────────────── */

static int larguraTela(const char *txt)
{
    int largura = 0;
    const unsigned char *ptr = (const unsigned char *)txt;
    while (*ptr) {
        unsigned int codePoint;
        int qtdBytes;
        if      (*ptr < 0x80) { codePoint = *ptr;        qtdBytes = 1; }
        else if (*ptr < 0xE0) { codePoint = *ptr & 0x1F; qtdBytes = 2; }
        else if (*ptr < 0xF0) { codePoint = *ptr & 0x0F; qtdBytes = 3; }
        else                  { codePoint = *ptr & 0x07; qtdBytes = 4; }
        for (int i = 1; i < qtdBytes && ptr[i]; i++)
            codePoint = (codePoint << 6) | (ptr[i] & 0x3F);
        ptr += qtdBytes;

        // checa se é um caractere "largo" (CJK, emoji, etc)
        int ehLargo = (codePoint >= 0x1100) && (
            codePoint <= 0x115F                        ||
            (codePoint >= 0x2E80 && codePoint <= 0x303E)      ||
            (codePoint >= 0x3040 && codePoint <= 0x33FF)      ||
            (codePoint >= 0x3400 && codePoint <= 0xA4CF)      ||
            (codePoint >= 0xAC00 && codePoint <= 0xD7FF)      ||
            (codePoint >= 0xF900 && codePoint <= 0xFAFF)      ||
            (codePoint >= 0xFE30 && codePoint <= 0xFE6F)      ||
            (codePoint >= 0xFF01 && codePoint <= 0xFF60)      ||
            (codePoint >= 0x1F000 && codePoint <= 0x1FFFF)    ||
            (codePoint >= 0x20000 && codePoint <= 0x2FFFD)
        );
        largura += ehLargo ? 2 : 1;
    }
    return largura;
}

static void criaPontosGuia(char *saida, int tamanho, int colunas)
{
    int pos = 0;
    for (int i = 0; i < colunas && pos + 3 < tamanho; i++) {
        if (i % 2 == 0) { saida[pos++] = '\xC2'; saida[pos++] = '\xB7'; }
        else            { saida[pos++] = ' '; }
    }
    saida[pos] = '\0';
}

/* ── Line buffer ─────────────────────────────────────────────────────────── */

#define TAMANHO_MAX_LINHA 1024

static char linhaAtual[TAMANHO_MAX_LINHA];
static int  larguraAtual;

static void iniciaLinha(void)
{
    linhaAtual[0] = '\0';
    larguraAtual  = 0;
}

static void adicionaNaLinha(const char *cor, const char *texto)
{
    size_t espacoLivre = TAMANHO_MAX_LINHA - strlen(linhaAtual) - 1;
    if (cor && cor[0]) {
        strncat(linhaAtual, cor, espacoLivre);
        espacoLivre = TAMANHO_MAX_LINHA - strlen(linhaAtual) - 1;
    }
    strncat(linhaAtual, texto, espacoLivre);
    larguraAtual += larguraTela(texto);
}

static void imprimeLinha(void)
{
    int preenchimento = LARGURA_INTERNA - larguraAtual;
    if (preenchimento < 0) preenchimento = 0;
    printf(COR_BORDA BV RST "%s%*s" COR_BORDA BV RST "\n", linhaAtual, preenchimento, "");
}

/* ── Line primitives ─────────────────────────────────────────────────────── */

static void linhaChaveValor(const char *corRotulo, const char *rotulo,
                    const char *corValor, const char *valor)
{
    int largRotulo  = larguraTela(rotulo);
    int largValor  = larguraTela(valor);
    int espaco = LARGURA_INTERNA - largRotulo - largValor;

    iniciaLinha();
    adicionaNaLinha(corRotulo, rotulo);

    if (espaco <= 2) {
        char espacos[8] = "";
        int  n = espaco > 0 ? espaco : 0;
        memset(espacos, ' ', n); espacos[n] = '\0';
        adicionaNaLinha(RST, espacos);
    } else {
        char pontos[256];
        criaPontosGuia(pontos, sizeof(pontos), espaco - 2);
        adicionaNaLinha(RST,      " ");
        adicionaNaLinha(COR_GUIA, pontos);
        adicionaNaLinha(RST,      " ");
    }

    adicionaNaLinha(corValor, valor);
    imprimeLinha();
}

static void linhaCentralizada(const char *cor, int negrito, const char *texto)
{
    int largTexto = larguraTela(texto);
    int esquerda  = (LARGURA_INTERNA - largTexto) / 2;
    if (esquerda < 0) esquerda = 0;

    iniciaLinha();
    for (int i = 0; i < esquerda; i++)
        strncat(linhaAtual, " ", TAMANHO_MAX_LINHA - strlen(linhaAtual) - 1);
    larguraAtual += esquerda;
    if (negrito) strncat(linhaAtual, BOLD,  TAMANHO_MAX_LINHA - strlen(linhaAtual) - 1);
    strncat(linhaAtual, cor, TAMANHO_MAX_LINHA - strlen(linhaAtual) - 1);
    strncat(linhaAtual, texto,  TAMANHO_MAX_LINHA - strlen(linhaAtual) - 1);
    strncat(linhaAtual, RST,   TAMANHO_MAX_LINHA - strlen(linhaAtual) - 1);
    larguraAtual += largTexto;
    imprimeLinha();
}

static void linhaDivisoria(void)
{
    char tracos[LARGURA_INTERNA * 3 + 4];
    tracos[0] = '\0';
    for (int i = 0; i < LARGURA_INTERNA; i++) strcat(tracos, BH);
    iniciaLinha();
    adicionaNaLinha(COR_SEPARADOR, tracos);
    imprimeLinha();
}

/* ── CPU line (wraps to two lines when name is long) ─────────────────────── */

static void linhaCpu(const char *bruto)
{
    char cpu[256];
    copiaSegura(cpu, sizeof(cpu), bruto);
    removeTrecho(cpu, "(R)");
    removeTrecho(cpu, "(TM)");
    removeTrecho(cpu, "(tm)");
    removeTrecho(cpu, "@");
    substituiTrecho(cpu, "th Gen", "\xC2\xBA" "Gen");
    juntaEspacos(cpu);
    aparaEspacos(cpu);

    if (4 + 2 + larguraTela(cpu) <= LARGURA_INTERNA) {
        linhaChaveValor(COR_CINZA, "CPU:", COR_CINZA, cpu);
        return;
    }

    /* distribui as palavras entre duas linhas; o rótulo "CPU:" ocupa 4 colunas */
    int  orcamento = LARGURA_INTERNA - 4 - 4;
    char primeira[128] = "", segunda[128] = "", temp[256];
    copiaSegura(temp, sizeof(temp), cpu);

    char *palavra = strtok(temp, " ");
    while (palavra) {
        int atual = (int)strlen(primeira);
        int necessario = atual ? (int)strlen(palavra) + 1 : (int)strlen(palavra);
        if (atual + necessario <= orcamento) {
            if (atual) strcat(primeira, " ");
            strcat(primeira, palavra);
        } else {
            if (strlen(segunda)) strcat(segunda, " ");
            strcat(segunda, palavra);
        }
        palavra = strtok(NULL, " ");
    }

    linhaChaveValor(COR_CINZA, "CPU:", COR_CINZA, primeira);

    int largSegunda = larguraTela(segunda);
    int preench = LARGURA_INTERNA - largSegunda;
    if (preench < 0) preench = 0;
    iniciaLinha();
    for (int i = 0; i < preench; i++)
        strncat(linhaAtual, " ", TAMANHO_MAX_LINHA - strlen(linhaAtual) - 1);
    larguraAtual += preench;
    adicionaNaLinha(COR_CINZA, segunda);
    imprimeLinha();
}

/* ── Borders ─────────────────────────────────────────────────────────────── */

static void desenhaBordaTopo(void)
{
    printf(COR_BORDA BTL BH " " COR_VERDE BOLD TITULO RST COR_BORDA " ");
    for (int i = 0; i < TRACOS_BORDA_TOPO; i++) printf(BH);
    printf(BTR RST "\n");
}

static void desenhaBordaBaixo(void)
{
    printf(COR_BORDA BBL);
    for (int i = 0; i < LARGURA_INTERNA; i++) printf(BH);
    printf(BBR RST);  /* sem newline — mantém a borda de topo na tela */
}

/* ── Data collection ─────────────────────────────────────────────────────── */

static void coletaSO(char *saida, int tam)
{
    const char *CHAVE_REG = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    char nome[256] = {0}, versao[32] = {0}, build[16] = {0};

    lerRegistroTexto(CHAVE_REG, "ProductName",    nome,  sizeof(nome));
    if (!lerRegistroTexto(CHAVE_REG, "DisplayVersion", versao, sizeof(versao)))
        lerRegistroTexto(CHAVE_REG, "ReleaseId",  versao,   sizeof(versao));
    lerRegistroTexto(CHAVE_REG, "CurrentBuild",   build, sizeof(build));

    /* o registro ainda fala "Windows 10" a partir do build 22000+ */
    if (atoi(build) >= 22000) {
        char *p = strstr(nome, "Windows 10");
        if (p) { p[8] = '1'; p[9] = '1'; }
    }
    removeTrecho(nome, "Single Language");
    removeTrecho(nome, "Multi Language");
    aparaEspacos(nome);

    if (versao[0]) snprintf(saida, tam, "%s (%s)", nome, versao);
    else           copiaSegura(saida, tam, nome);
}

static void coletaFabricante(char *saida, int tam)
{
    const char *CHAVE_BIOS = "HARDWARE\\DESCRIPTION\\System\\BIOS";
    char fab[128] = {0}, prod[128] = {0};
    lerRegistroTexto(CHAVE_BIOS, "SystemManufacturer", fab, sizeof(fab));
    lerRegistroTexto(CHAVE_BIOS, "SystemProductName",  prod, sizeof(prod));
    aparaEspacos(fab); aparaEspacos(prod);
    snprintf(saida, tam, "%s %s", fab, prod);
    aparaEspacos(saida);
}

static void coletaVersaoArquivo(const wchar_t *caminho, char *saida, int tam)
{
    DWORD identificador = 0;
    DWORD tamanho = GetFileVersionInfoSizeW(caminho, &identificador);
    if (!tamanho) { copiaSegura(saida, tam, "Não Instalado"); return; }

    BYTE *buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, tamanho);
    if (!buffer) { copiaSegura(saida, tam, "Não Instalado"); return; }

    VS_FIXEDFILEINFO *infoFixa = NULL;
    UINT              tamInfo = 0;
    if (GetFileVersionInfoW(caminho, identificador, tamanho, buffer)
        && VerQueryValueW(buffer, L"\\", (LPVOID *)&infoFixa, &tamInfo) && infoFixa)
    {
        snprintf(saida, tam, "%u.%u.%u.%u",
                 HIWORD(infoFixa->dwFileVersionMS), LOWORD(infoFixa->dwFileVersionMS),
                 HIWORD(infoFixa->dwFileVersionLS), LOWORD(infoFixa->dwFileVersionLS));
    } else {
        copiaSegura(saida, tam, "Não Instalado");
    }
    HeapFree(GetProcessHeap(), 0, buffer);
}

static int adaptadorEhVirtual(const char *descricao)
{
    // lista de fabricantes/tipos de adaptador virtual pra ignorar na busca
    static const char *IGNORAR[] = {
        "Virtual", "Hyper-V", "VMware", "VirtualBox",
        "vEthernet", "Loopback", "WAN Miniport", "Bluetooth",
        "Pseudo", "Tunnel", "6to4",
    };
    for (int i = 0; i < (int)(sizeof(IGNORAR) / sizeof(IGNORAR[0])); i++)
        if (strstr(descricao, IGNORAR[i])) return 1;
    return 0;
}

static void preencheDoAdaptador(IP_ADAPTER_ADDRESSES *adapt,
                               char *nome, int tamNome,
                               char *descricao, int tamDescricao,
                               char *mac,  int tamMac)
{
    WideCharToMultiByte(CP_UTF8, 0, adapt->FriendlyName, -1, nome, tamNome, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, adapt->Description,  -1, descricao, tamDescricao, NULL, NULL);
    int pos = 0;
    for (DWORD i = 0; i < adapt->PhysicalAddressLength && pos < tamMac - 3; i++) {
        if (i) mac[pos++] = '-';
        pos += snprintf(mac + pos, tamMac - pos, "%02X",
                        (unsigned)adapt->PhysicalAddress[i]);
    }
}

static void coletaAdaptadorRede(char *nome, int tamNome,
                                 char *descricao, int tamDescricao,
                                 char *mac,  int tamMac)
{
    copiaSegura(nome, tamNome, "Desconhecido");
    copiaSegura(descricao, tamDescricao, "Desconhecido");
    copiaSegura(mac,  tamMac,  "Desconhecido");

    DWORD indiceMelhor = 0;
    GetBestInterface((IPAddr)0x08080808, &indiceMelhor);

    ULONG tamanho = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &tamanho);
    if (!tamanho) return;

    IP_ADAPTER_ADDRESSES *buffer = (IP_ADAPTER_ADDRESSES *)
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, tamanho);
    if (!buffer) return;

    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, buffer, &tamanho) == NO_ERROR) {
        IP_ADAPTER_ADDRESSES *encontrado = NULL;
        IP_ADAPTER_ADDRESSES *alternativo = NULL;
        char tmp[256];

        for (IP_ADAPTER_ADDRESSES *atual = buffer; atual; atual = atual->Next) {
            if (atual->PhysicalAddressLength == 0) continue;

            int todoZero = 1;
            for (DWORD i = 0; i < atual->PhysicalAddressLength; i++)
                if (atual->PhysicalAddress[i]) { todoZero = 0; break; }
            if (todoZero) continue;

            WideCharToMultiByte(CP_UTF8, 0, atual->Description, -1,
                                tmp, sizeof(tmp), NULL, NULL);

            if (indiceMelhor && (atual->IfIndex == indiceMelhor || atual->Ipv6IfIndex == indiceMelhor)) {
                encontrado = atual;
                break;
            }

            if (!alternativo                                   &&
                atual->OperStatus == IfOperStatusUp            &&
                atual->IfType     != IF_TYPE_SOFTWARE_LOOPBACK &&
                !adaptadorEhVirtual(tmp))
            {
                alternativo = atual;
            }
        }

        IP_ADAPTER_ADDRESSES *usar = encontrado ? encontrado : alternativo;
        if (usar) preencheDoAdaptador(usar, nome, tamNome, descricao, tamDescricao, mac, tamMac);
    }
    HeapFree(GetProcessHeap(), 0, buffer);
}

static int coletaFortiTelemetria(void)
{
    char valor[128] = {0};
    if (!lerRegistroTexto("SOFTWARE\\Fortinet\\FortiClient\\FA_ESNAC", "fgt_name",
                 valor, sizeof(valor)))
        return 0;
    aparaEspacos(valor);
    return valor[0] != '\0';
}

static void coletaWindowsApp(char *saida, int tam)
{
    static const char *CHAVES_APPX[] = {
        "AppXm7b9qra8695twjc0nsqazthqtkq1695h",
        "AppXx14gqdzftxx71f107x2zvs21g17wak54",
        "AppX3vv3ea3hm91j5w2j1483ppc3fdf8n8eg",
    };
    copiaSegura(saida, tam, "Não Instalado");

    for (int i = 0; i < (int)(sizeof(CHAVES_APPX) / sizeof(CHAVES_APPX[0])); i++) {
        char caminho[256], pacote[256] = {0};
        snprintf(caminho, sizeof(caminho),
                 "Software\\Classes\\%s\\Shell\\open", CHAVES_APPX[i]);
        if (!lerRegistroTextoUsuario(caminho, "PackageId", pacote, sizeof(pacote))) continue;

        char *p = strchr(pacote, '_');
        if (!p) continue;
        char *q = strchr(p + 1, '_');
        if (q) *q = '\0';
        copiaSegura(saida, tam, p + 1);
        return;
    }
}

/* ── Network probe (background thread) ───────────────────────────────────── */

#define HOST_TESTE        "intranet.com.br"
#define INTERVALO_TESTE_MS 30000

static volatile long acessoInternoGlobal = 0;

static int testaConexaoTcp(const char *host, unsigned short porta)
{
    char strPorta[8];
    snprintf(strPorta, sizeof(strPorta), "%u", (unsigned)porta);

    struct addrinfo dicas, *resultado = NULL;
    memset(&dicas, 0, sizeof(dicas));
    dicas.ai_family   = AF_UNSPEC;
    dicas.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, strPorta, &dicas, &resultado) != 0 || !resultado) return 0;

    SOCKET soquete = socket(resultado->ai_family, SOCK_STREAM, resultado->ai_protocol);
    if (soquete == INVALID_SOCKET) { freeaddrinfo(resultado); return 0; }

    u_long modoNaoBloqueante = 1;
    ioctlsocket(soquete, FIONBIO, &modoNaoBloqueante);
    connect(soquete, resultado->ai_addr, (int)resultado->ai_addrlen);
    freeaddrinfo(resultado);

    fd_set fdsEscrita, fdsErro;
    FD_ZERO(&fdsEscrita); FD_SET(soquete, &fdsEscrita);
    FD_ZERO(&fdsErro); FD_SET(soquete, &fdsErro);
    struct timeval tempoLimite = { 3, 0 };
    int resp = select(0, NULL, &fdsEscrita, &fdsErro, &tempoLimite);
    int conectou = (resp > 0 && FD_ISSET(soquete, &fdsEscrita) && !FD_ISSET(soquete, &fdsErro));
    closesocket(soquete);
    return conectou;
}

static DWORD WINAPI threadTesteRede(LPVOID naoUsado)
{
    (void)naoUsado;
    for (;;) {
        int conectou = testaConexaoTcp(HOST_TESTE, 443) || testaConexaoTcp(HOST_TESTE, 80);
        InterlockedExchange(&acessoInternoGlobal, conectou ? 1 : 0);
        Sleep(INTERVALO_TESTE_MS);
    }
    return 0;
}

/* ── Dynamic collectors (called every second) ────────────────────────────── */

static ULONGLONG cpuOciosoAnterior  = 0;
static ULONGLONG cpuTotalAnterior   = 0;
static double    cpuPorcentagemGlobal = 0.0;

static double coletaUsoCpu(void)
{
    FILETIME tempoOcioso, tempoKernel, tempoUsuario;
    if (!GetSystemTimes(&tempoOcioso, &tempoKernel, &tempoUsuario))
        return cpuPorcentagemGlobal;

    ULONGLONG ocioso = ((ULONGLONG)tempoOcioso.dwHighDateTime   << 32) | tempoOcioso.dwLowDateTime;
    ULONGLONG kernel  = ((ULONGLONG)tempoKernel.dwHighDateTime  << 32) | tempoKernel.dwLowDateTime;
    ULONGLONG usuario = ((ULONGLONG)tempoUsuario.dwHighDateTime << 32) | tempoUsuario.dwLowDateTime;
    ULONGLONG total   = kernel + usuario;

    ULONGLONG diffOcioso = ocioso - cpuOciosoAnterior;
    ULONGLONG diffTotal  = total  - cpuTotalAnterior;
    cpuOciosoAnterior = ocioso;
    cpuTotalAnterior  = total;

    if (diffTotal > 0)
        cpuPorcentagemGlobal = (1.0 - (double)diffOcioso / (double)diffTotal) * 100.0;

    return cpuPorcentagemGlobal;
}

static void coletaMemoria(double *totalMb, double *disponivelMb)
{
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status)) {
        *totalMb      = (double)status.ullTotalPhys / (1024.0 * 1024.0);
        *disponivelMb = (double)status.ullAvailPhys / (1024.0 * 1024.0);
    } else {
        *totalMb = *disponivelMb = 0.0;
    }
}

static void coletaTempoAtivo(char *saida, int tam)
{
    ULONGLONG segundos = GetTickCount64() / 1000ULL;
    snprintf(saida, tam, "%02llud %02lluh %02llum %02llus",
             (unsigned long long)(segundos / 86400ULL),
             (unsigned long long)((segundos % 86400ULL) / 3600ULL),
             (unsigned long long)((segundos % 3600ULL)  / 60ULL),
             (unsigned long long)(segundos % 60ULL));
}

static int coletaFirewall(void)
{
    static const char *PERFIS[] = {
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile",
    };
    for (int i = 0; i < (int)(sizeof(PERFIS) / sizeof(PERFIS[0])); i++)
        if (lerRegistroNumero(PERFIS[i], "EnableFirewall", 0)) return 1;
    return 0;
}

static int coletaProxy(void)
{
    HKEY  chave;
    DWORD valor = 0, tipo = REG_DWORD, cb = sizeof(DWORD);
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                      0, KEY_READ, &chave) == ERROR_SUCCESS) {
        RegQueryValueExA(chave, "ProxyEnable", NULL, &tipo, (LPBYTE)&valor, &cb);
        RegCloseKey(chave);
    }
    return (int)valor;
}

static int estaEntradoAzureAd(void)
{
    HKEY chave;
    const char *CAMINHO =
        "SYSTEM\\CurrentControlSet\\Control\\CloudDomainJoin\\JoinInfo";
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, CAMINHO, 0, KEY_READ, &chave) != ERROR_SUCCESS)
        return 0;
    char  subChave[128]; DWORD tamanho = sizeof(subChave);
    int   achou = (RegEnumKeyExA(chave, 0, subChave, &tamanho,
                                 NULL, NULL, NULL, NULL) == ERROR_SUCCESS);
    RegCloseKey(chave);
    return achou;
}

static TipoEntrada resolveTipoEntrada(void)
{
    /* o Netlogon grava o nome do domínio aqui quando a máquina está no AD — mesma fonte que o NetGetJoinInformation usa */
    char dominio[256] = {0};
    lerRegistroTexto("SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
            "Domain", dominio, sizeof(dominio));
    aparaEspacos(dominio);
    if (dominio[0]) return ENTROU_ACTIVE_DIRECTORY;

    /* AAD e Intune podem existir independente de um domínio tradicional */
    int temIntune = existeChaveRegistro(
        "SYSTEM\\CurrentControlSet\\Services\\IntuneManagementExtension");
    int temAad = estaEntradoAzureAd();

    if (temIntune && temAad) return ENTROU_INTUNE_AZURE_AD;
    if (temIntune)           return ENTROU_INTUNE_SOMENTE;
    if (temAad)              return ENTROU_AZURE_AD;
    return ENTROU_SEM_GERENCIA;
}

static const char *rotuloEntrada(TipoEntrada t)
{
    // switch simples só pra mapear o enum no texto que aparece na tela
    switch (t) {
        case ENTROU_ACTIVE_DIRECTORY: return "ACTIVE DIRECTORY";
        case ENTROU_AZURE_AD:         return "AZURE AD";
        case ENTROU_INTUNE_AZURE_AD:  return "INTUNE + AZURE AD";
        case ENTROU_INTUNE_SOMENTE:   return "INTUNE + (sem AZURE AD)";
        default:                      return "N\xC3\x83O GERENCIADA";
    }
}

static int entradaEhGerenciada(TipoEntrada t) { return t != ENTROU_SEM_GERENCIA; }

/* ── Render sections ─────────────────────────────────────────────────────── */

static void desenhaIdentidade(const Snapshot *s)
{
    const char *arquitetura = (sizeof(void *) == 8) ? "x86_64" : "x86";
    char soComArquitetura[300];
    snprintf(soComArquitetura, sizeof(soComArquitetura), "%s [%s]", s->sistemaOperacional, arquitetura);

    linhaDivisoria();
    linhaChaveValor(COR_CINZA, "FABRICANTE:",      COR_CINZA, s->fabricante);
    linhaChaveValor(COR_CINZA, "S.O.:",            COR_CINZA, soComArquitetura);
    linhaChaveValor(COR_CINZA, "USU\xC3\x81RIO:", COR_CINZA, s->usuario);
    linhaChaveValor(COR_CINZA, "HOSTNAME:",        COR_CINZA, s->nomeHost);
}

static void desenhaRede(const Snapshot *s)
{
    linhaDivisoria();
    linhaChaveValor(COR_CINZA, "ADAPTADOR:",                   COR_CINZA, s->adaptadorRede);
    linhaChaveValor(COR_CINZA, "DESCRI\xC3\x87\xC3\x83O:",    COR_CINZA, s->descricaoRede);
    linhaChaveValor(COR_CINZA, "MAC:",                         COR_CINZA, s->macRede);
}

static void desenhaCpu(const Snapshot *s)
{
    char textoPct[16];
    snprintf(textoPct, sizeof(textoPct), "%.2f%%", s->cpuPorcentagem);
    const char *corPct = s->cpuPorcentagem >= 90.0 ? COR_VERMELHO :
                            s->cpuPorcentagem >= 50.0 ? COR_AMARELO : COR_CINZA;

    linhaDivisoria();
    linhaCpu(s->cpu);
    linhaChaveValor(COR_CINZA, "USO CPU:", corPct, textoPct);
}

static void desenhaMemoria(const Snapshot *s)
{
    double pctUsado = (s->memTotalMb > 0.0)
                      ? (1.0 - s->memDisponivelMb / s->memTotalMb) * 100.0
                      : 0.0;
    const char *corMem = pctUsado >= 90.0 ? COR_VERMELHO :
                       pctUsado >= 70.0 ? COR_AMARELO : COR_CINZA;

    char strTotal[24], strDisponivel[24], strUsado[16];
    snprintf(strTotal, sizeof(strTotal), "%.2f MB", s->memTotalMb);
    snprintf(strDisponivel, sizeof(strDisponivel), "%.2f MB", s->memDisponivelMb);
    snprintf(strUsado,  sizeof(strUsado),  "%.2f%%",  pctUsado);

    linhaDivisoria();
    linhaChaveValor(COR_CINZA, "RAM:",       COR_CINZA, strTotal);
    linhaChaveValor(COR_CINZA, "RAM DISP.:", COR_CINZA, strDisponivel);
    linhaChaveValor(COR_CINZA, "USO RAM:",   corMem,   strUsado);
}

static void desenhaAgentes(const Snapshot *s)
{
    static const char *NAO_INSTALADO = "N\xC3\xA3o Instalado";

    linhaDivisoria();
    linhaChaveValor(COR_VERDE, "Firewall:", COR_CINZA,
            s->firewall ? "Ativado" : "Desativado");

    /* FortiClient precisa de tratamento separado: só fica verde quando a telemetria está ativa */
    {
        int instalado = strcmp(s->fortClient, NAO_INSTALADO) != 0;
        int tudoOk    = instalado && s->fortiTelemetria;
        const char *corLabel = tudoOk ? COR_VERDE : COR_VERMELHO;
        const char *valorMostrado = (instalado && !s->fortiTelemetria)
                          ? "Sem Telemetria" : s->fortClient;
        linhaChaveValor(corLabel, "FortiClient:", COR_CINZA, valorMostrado);
    }

    // monta a listinha de agentes pra não ficar repetindo o mesmo bloco de código
    struct { const char *rotulo; const char *versao; } listaAgentes[] = {
        { "CrowdStrike:", s->crowdStrike },
        { "Netskope:",    s->netskope    },
        { "KACE:",        s->kace        },
        { "Lumu:",        s->lumu        },
        { "Windows App:", s->winApp },
    };
    for (int i = 0; i < (int)(sizeof(listaAgentes) / sizeof(listaAgentes[0])); i++) {
        const char *cor = strcmp(listaAgentes[i].versao, NAO_INSTALADO) != 0 ? COR_VERDE : COR_VERMELHO;
        linhaChaveValor(cor, listaAgentes[i].rotulo, COR_CINZA, listaAgentes[i].versao);
    }
}

static void desenhaStatus(const Snapshot *s)
{
    linhaDivisoria();
    linhaChaveValor(COR_CINZA, "EM ATIVIDADE:", COR_CINZA, s->tempoAtivo);

    linhaDivisoria();
    linhaCentralizada(entradaEhGerenciada(s->tipoEntrada) ? COR_VERDE : COR_VERMELHO,
                  1, rotuloEntrada(s->tipoEntrada));
    linhaCentralizada(s->proxy ? COR_VERDE : COR_VERMELHO, 1,
                  s->proxy ? "PROXY ATIVO" : "PROXY INATIVO");
    linhaCentralizada(s->acessoInterno ? COR_VERDE : COR_VERMELHO, 1,
                  s->acessoInterno ? "ACESSO A REDE INTERNA" : "SEM ACESSO A REDE INTERNA");
}

static void desenhaTudo(const Snapshot *s)
{
    desenhaBordaTopo();
    linhaCentralizada(COR_CINZA, 1, s->hora);
    linhaCentralizada(COR_CINZA, 1, s->data);
    desenhaIdentidade(s);
    desenhaRede(s);
    desenhaCpu(s);
    desenhaMemoria(s);
    desenhaAgentes(s);
    desenhaStatus(s);
    desenhaBordaBaixo();
    fflush(stdout);
}

/* ── Console setup ───────────────────────────────────────────────────────── */

static void ajustaTamanhoConsole(HANDLE handleSaida)
{
    /* a WinAPI exige encolher a janela antes de reduzir o buffer */
    SMALL_RECT minusculo = { 0, 0, 0, 0 };
    SetConsoleWindowInfo(handleSaida, TRUE, &minusculo);

    COORD buffer = { (SHORT)COLUNAS, (SHORT)LINHAS };
    SetConsoleScreenBufferSize(handleSaida, buffer);

    SMALL_RECT janela = { 0, 0, COLUNAS - 1, LINHAS - 1 };
    SetConsoleWindowInfo(handleSaida, TRUE, &janela);
}

static void travaJanela(void)
{
    Sleep(150);
    HWND hwnd = FindWindowA(NULL, TITULO);
    if (!hwnd) return;

    LONG estilo = GetWindowLongW(hwnd, GWL_STYLE);
    estilo &= ~(WS_MAXIMIZEBOX | WS_SIZEBOX);
    SetWindowLongW(hwnd, GWL_STYLE, estilo);
    SetWindowPos(hwnd, NULL, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);

    HINSTANCE modulo = GetModuleHandleW(NULL);
    HICON iconeGrande = (HICON)LoadImageW(modulo, MAKEINTRESOURCEW(1),
                                    IMAGE_ICON, 0,  0,  LR_DEFAULTSIZE);
    HICON iconePequeno = (HICON)LoadImageW(modulo, MAKEINTRESOURCEW(1),
                                    IMAGE_ICON, 16, 16, 0);
    if (iconeGrande)   SendMessageW(hwnd, WM_SETICON, ICON_BIG,   (LPARAM)iconeGrande);
    if (iconePequeno)  SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)iconePequeno);
}

static BOOL WINAPI tratadorCtrl(DWORD evento)
{
    if (evento == CTRL_C_EVENT || evento == CTRL_BREAK_EVENT) {
        printf("\x1B[?25h" RST "\n");
        ExitProcess(0);
    }
    return FALSE;
}

/* ── PTY / conhost detection ─────────────────────────────────────────────── */

static int variavelAmbienteExiste(const char *nome)
{
    char tmp[4];
    DWORD r = GetEnvironmentVariableA(nome, tmp, sizeof(tmp));
    return r > 0 || (r == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER);
}

static void garanteConhostProprio(void)
{
    int precisa = 0;

    if (variavelAmbienteExiste("WT_SESSION"))   precisa = 1;  /* Windows Terminal */
    if (variavelAmbienteExiste("TERM_PROGRAM")) precisa = 1;  /* VS Code, etc.    */

    if (!precisa) {
        DWORD pids[32];
        if (GetConsoleProcessList(pids, 32) > 1) precisa = 1;
    }

    if (!precisa) return;

    /* remove as marcações pra o processo filho não tentar respawnar de novo */
    SetEnvironmentVariableA("WT_SESSION",   NULL);
    SetEnvironmentVariableA("TERM_PROGRAM", NULL);

    char proprioCaminho[MAX_PATH], dirSistema[MAX_PATH], comando[MAX_PATH * 2 + 64];
    GetModuleFileNameA(NULL, proprioCaminho, MAX_PATH);
    GetSystemDirectoryA(dirSistema,  MAX_PATH);
    snprintf(comando, sizeof(comando), "\"%s\\conhost.exe\" -- \"%s\"", dirSistema, proprioCaminho);

    STARTUPINFOA        infoInicio;
    PROCESS_INFORMATION infoProcesso;
    memset(&infoInicio, 0, sizeof(infoInicio)); infoInicio.cb = sizeof(infoInicio);
    memset(&infoProcesso, 0, sizeof(infoProcesso));
    CreateProcessA(NULL, comando, NULL, NULL, FALSE, 0, NULL, NULL, &infoInicio, &infoProcesso);
    if (infoProcesso.hProcess) CloseHandle(infoProcesso.hProcess);
    if (infoProcesso.hThread)  CloseHandle(infoProcesso.hThread);
    ExitProcess(0);
}

/* ── Static data init ────────────────────────────────────────────────────── */

static void inicializaSnapshot(Snapshot *s)
{
    memset(s, 0, sizeof(*s));

    coletaSO(s->sistemaOperacional, sizeof(s->sistemaOperacional));
    coletaFabricante(s->fabricante, sizeof(s->fabricante));
    GetEnvironmentVariableA("USERNAME",     s->usuario,     sizeof(s->usuario));
    GetEnvironmentVariableA("COMPUTERNAME", s->nomeHost, sizeof(s->nomeHost));
    lerRegistroTexto("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
            "ProcessorNameString", s->cpu, sizeof(s->cpu));
    aparaEspacos(s->cpu);

    s->fortiTelemetria = coletaFortiTelemetria();
    coletaVersaoArquivo(L"C:\\Program Files\\Fortinet\\FortiClient\\FortiClient.exe",
                     s->fortClient, sizeof(s->fortClient));
    coletaVersaoArquivo(L"C:\\Program Files\\CrowdStrike\\CSFalconService.exe",
                     s->crowdStrike, sizeof(s->crowdStrike));
    coletaVersaoArquivo(L"C:\\Program Files\\Netskope\\EPDLP\\EPDLP.exe",
                     s->netskope,    sizeof(s->netskope));
    coletaVersaoArquivo(L"C:\\Program Files (x86)\\Quest\\KACE\\AMPTools.exe",
                     s->kace,        sizeof(s->kace));
    coletaVersaoArquivo(L"C:\\Program Files (x86)\\Lumu\\Agent\\lumu-windows-agent.exe",
                     s->lumu,        sizeof(s->lumu));
    coletaWindowsApp(s->winApp, sizeof(s->winApp));
    coletaAdaptadorRede(s->adaptadorRede,     sizeof(s->adaptadorRede),
                        s->descricaoRede, sizeof(s->descricaoRede),
                        s->macRede,         sizeof(s->macRede));
    s->tipoEntrada = resolveTipoEntrada();
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    garanteConhostProprio();

    WSADATA dadosWsa;
    WSAStartup(MAKEWORD(2, 2), &dadosWsa);

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitleA(TITULO);

    HANDLE handleSaida = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  modoConsole = 0;
    GetConsoleMode(handleSaida, &modoConsole);
    SetConsoleMode(handleSaida, modoConsole | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    ajustaTamanhoConsole(handleSaida);

    SetConsoleCtrlHandler(tratadorCtrl, TRUE);
    printf("\x1B[?25l");

    travaJanela();
    coletaUsoCpu();  /* só pra "semear" o delta — a primeira chamada sempre retorna 0 */

    Snapshot snapshotAtual;
    inicializaSnapshot(&snapshotAtual);
    CreateThread(NULL, 0, threadTesteRede, NULL, 0, NULL);

    printf("\x1B[2J\x1B[H");
    for (;;) {
        SYSTEMTIME horarioLocal;
        GetLocalTime(&horarioLocal);
        snprintf(snapshotAtual.hora, sizeof(snapshotAtual.hora), "%02u:%02u:%02u",
                 horarioLocal.wHour, horarioLocal.wMinute, horarioLocal.wSecond);
        snprintf(snapshotAtual.data, sizeof(snapshotAtual.data), "%02u/%02u/%04u",
                 horarioLocal.wDay, horarioLocal.wMonth, horarioLocal.wYear);

        snapshotAtual.cpuPorcentagem = coletaUsoCpu();
        coletaMemoria(&snapshotAtual.memTotalMb, &snapshotAtual.memDisponivelMb);
        snapshotAtual.firewall       = coletaFirewall();
        snapshotAtual.proxy          = coletaProxy();
        snapshotAtual.acessoInterno  = (int)InterlockedCompareExchange(&acessoInternoGlobal, 0, 0);
        coletaTempoAtivo(snapshotAtual.tempoAtivo, sizeof(snapshotAtual.tempoAtivo));

        printf("\x1B[H");
        desenhaTudo(&snapshotAtual);
        Sleep(1000);
    }
}
