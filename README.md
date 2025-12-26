# windows-taskkill-investigation
The script relies on Windows Security Event ID 4688. On some Windows editions (e.g. Home), this event may not be available even with auditpol enabled.
Descrição do Projeto

Este script realiza investigação de execuções do utilitário taskkill.exe em sistemas Windows, utilizando logs nativos do sistema operacional e correlação básica com conexões de rede ativas.

O objetivo é identificar possíveis abusos do taskkill, técnica frequentemente usada em:

evasão de EDR/antivírus

interrupção de processos de segurança

ações maliciosas pós-exploração

abuso administrativo ou uso indevido de LOLBins (Living off the Land Binaries)

O que o código faz, na prática
1️⃣ Análise do Windows Security Event Log

O script acessa o Windows Security Log e busca eventos de criação de processo (Event ID 4688) ocorridos nas últimas 6 horas.

Para cada evento encontrado, ele:

Verifica se o processo criado foi taskkill.exe

Extrai informações relevantes do evento, como:

Nome da máquina

Usuário responsável pela execução

Data e hora

Processo criado

Linha de comando completa

Processo pai (quem iniciou o taskkill)

Esses dados são fundamentais em investigações forenses e monitoramento de segurança, pois permitem entender quem executou, quando executou e como executou o comando.

2️⃣ Extração do processo alvo

A partir da linha de comando, o script tenta identificar qual processo foi encerrado, analisando os parâmetros mais comuns do taskkill:

/pid → encerramento por ID do processo

/im → encerramento por nome da imagem

Essa extração é feita em modo best effort, suficiente para threat hunting e análise inicial.

3️⃣ Enumeração de conexões de rede ativas

Além da análise de logs, o script também verifica conexões de rede ativas no momento da execução, usando a biblioteca psutil.

Ele:

Lista conexões IPv4/IPv6 ativas

Ignora endereços privados (10.x.x.x, 192.168.x.x, 172.x.x.x)

Exibe conexões externas associadas a um PID local

Essa etapa permite correlação entre atividade suspeita no host e comunicação externa, algo comum em investigações de incidentes.

Observações importantes

O script deve ser executado como Administrador

Depende da auditoria de Process Creation (Event ID 4688) estar habilitada

Em algumas edições do Windows, esse evento pode não estar disponível

O parsing dos logs depende da estrutura padrão do Windows Event Log
