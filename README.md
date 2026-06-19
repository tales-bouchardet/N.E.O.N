# N.E.O.N.

Dashboard de terminal pra Windows, em C puro (WinAPI, sem libs externas). Mostra SO, usuário, rede, CPU, RAM, se os agentes de segurança tão instalados (FortiClient, CrowdStrike, Netskope, KACE, Lumu), domínio/Azure AD/Intune, proxy etc. Atualiza a cada segundo.

## Build

```bat
cl /utf-8 /O2 /W3 /nologo neon.c ^
   advapi32.lib iphlpapi.lib version.lib ws2_32.lib user32.lib ^
   /Fe:neon.exe
```

## Usar

Roda o `neon.exe`. Ctrl+C pra sair.

## Bugs

- Teste de rede interna só atualiza a cada 30s, então se a rede cair/voltar a tela demora pra refletir.
- Se a máquina entrou no domínio há pouco tempo, a detecção de AD pode falhar e mostrar "não gerenciada" sem motivo real.
- A checagem dos agentes assume os caminhos padrão de instalação. Se alguém instalar em outro drive/pasta, mostra "Não Instalado" mesmo tendo.
- Quase não tem tratamento de erro pra registro/rede — se algo falha, geralmente vira 0 ou "Desconhecido" e segue, sem avisar.

## Resumo

Um arquivo só, `neon.c`. Lê registro do Windows, GetSystemTimes, GetAdaptersAddresses etc. Uma thread fica testando TCP num host fixo pra ver se tem rede interna. E tem aquele truque de relançar dentro do conhost pra conseguir redimensionar a janela direito.

<img width="439" height="575" alt="image" src="https://github.com/user-attachments/assets/ebfc9e2d-8692-4784-b602-0be811eca46d" />
