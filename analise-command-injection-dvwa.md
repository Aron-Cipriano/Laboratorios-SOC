# 🔍 Análise de Log: Tentativa de Command Injection (DVWA)

> **Plataforma:** LetsDefend  
> **Tipo de Ataque:** Command Injection  
> **Aplicação Alvo:** DVWA (Damn Vulnerable Web Application)  
> **Data dos Eventos:** 01/Mar/2022  

---

## 📌 Contexto

Durante a inspeção de logs de tráfego web, foi identificada uma sequência de requisições `POST` suspeitas direcionadas a um servidor hospedando a aplicação **Damn Vulnerable Web Application (DVWA)**. Todo o tráfego originou-se de um único endereço IP interno, indicando uma sessão de ataque concentrada e deliberada.

---

## 🗃️ Log Analisado

```text
192.168.31.156 - - [01/Mar/2022:09:03:33 -0800] "POST /dvwa/vulnerabilities/exec/?q=1.1.1.1;ls HTTP/1.1" 200 4477
192.168.31.156 - - [01/Mar/2022:09:03:50 -0800] "POST /dvwa/vulnerabilities/exec/?q=1.1.1.1;whoami HTTP/1.1" 200 4477
192.168.31.156 - - [01/Mar/2022:09:04:00 -0800] "POST /dvwa/vulnerabilities/exec/?q=1.1.1.1;dir HTTP/1.1" 200 4477
192.168.31.156 - - [01/Mar/2022:09:04:45 -0800] "POST /dvwa/vulnerabilities/exec/?q=1.1.1.1&&ls HTTP/1.1" 200 4477
192.168.31.156 - - [01/Mar/2022:09:04:56 -0800] "POST /dvwa/vulnerabilities/exec/?q=1.1.1.1&&dir HTTP/1.1" 200 4477
192.168.31.156 - - [01/Mar/2022:09:05:41 -0800] "POST /dvwa/vulnerabilities/exec/?q=1.1.1.1;pwd HTTP/1.1" 200 4477
```

---

## 🧩 Decomposição dos Campos de Log

| Campo | Descrição |
|---|---|
| `192.168.31.156` | IP de origem do atacante (rede interna) |
| `[01/Mar/2022:09:03:33 -0800]` | Timestamp do evento (fuso horário UTC-8) |
| `POST` | Método HTTP utilizado |
| `/dvwa/vulnerabilities/exec/` | Endpoint vulnerável — módulo de execução de comandos do DVWA |
| `?q=1.1.1.1;<comando>` | Payload do ataque — injeção de comandos via parâmetro `q` |
| `HTTP/1.1` | Versão do protocolo |
| `200` | Código de resposta HTTP — requisição processada com **sucesso** |
| `4477` | Tamanho da resposta em bytes |

---

## ⚔️ Análise dos Payloads

O atacante explorou o endpoint `/dvwa/vulnerabilities/exec/`, que aceita um endereço IP como entrada e executa um `ping` no servidor. A vulnerabilidade ocorre porque a aplicação **não sanitiza** o parâmetro `q`, permitindo que comandos adicionais sejam encadeados.

### Operadores de Encadeamento Utilizados

| Operador | Comportamento | Exemplo no Log |
|---|---|---|
| `;` (semicolon) | Executa o segundo comando **independente** do resultado do primeiro | `1.1.1.1;whoami` |
| `&&` (AND lógico) | Executa o segundo comando **somente se** o primeiro for bem-sucedido | `1.1.1.1&&ls` |

### Comandos Injetados e seu Propósito

| Payload | Comando | Objetivo |
|---|---|---|
| `1.1.1.1;ls` | `ls` | Listar arquivos/diretórios no sistema (Linux) |
| `1.1.1.1;whoami` | `whoami` | Identificar o **usuário** sob o qual o servidor web está rodando |
| `1.1.1.1;dir` | `dir` | Listar diretórios (equivalente Windows — testando compatibilidade do SO) |
| `1.1.1.1&&ls` | `ls` | Repetição com operador diferente para contornar possíveis filtros |
| `1.1.1.1&&dir` | `dir` | Repetição com operador diferente |
| `1.1.1.1;pwd` | `pwd` | Identificar o **diretório de trabalho atual** do processo (Linux) |

---

## 🎯 Objetivo do Atacante: Reconhecimento (Reconnaissance)

A sequência de comandos indica que o atacante estava na fase de **reconhecimento de ambiente**, coletando informações do sistema antes de uma possível escalada do ataque. Os objetivos específicos foram:

- **Identificar o sistema operacional** — a utilização tanto de `ls`/`pwd` (Linux) quanto de `dir` (Windows) indica que o atacante sondou qual SO estava presente.
- **Mapear a estrutura de diretórios** — via `ls` e `dir`.
- **Descobrir o contexto de execução** — via `whoami`, para saber se o processo tem privilégios elevados.
- **Confirmar o diretório raiz da aplicação** — via `pwd`.

---

## 🚨 Indicadores de Comprometimento (IOCs)

| Tipo | Valor |
|---|---|
| IP Origem | `192.168.31.156` |
| Endpoint Alvo | `/dvwa/vulnerabilities/exec/` |
| User-Agent | Firefox (conforme log original) |
| Códigos HTTP | `200 OK` em todas as requisições |
| Período do Ataque | `09:03:33` – `09:05:41` (aprox. 2 minutos) |

> ⚠️ O código de resposta `200 OK` em **todas** as requisições confirma que os comandos foram **executados com sucesso** pelo servidor — não houve bloqueio ou sanitização.

---

## 🛡️ Vulnerabilidade Explorada

**CWE-78 — Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)**

A aplicação passa o input do usuário diretamente para uma função de execução de sistema (`exec`, `system`, `shell_exec`, etc.) sem validação ou sanitização adequada.

**Exemplo conceitual do código vulnerável (PHP):**
```php
// ❌ VULNERÁVEL
$output = shell_exec("ping -c 1 " . $_POST['q']);
echo $output;
```

**Correção recomendada:**
```php
// ✅ SEGURO
$ip = filter_var($_POST['q'], FILTER_VALIDATE_IP);
if ($ip) {
    $output = shell_exec("ping -c 1 " . escapeshellarg($ip));
    echo $output;
} else {
    echo "Input inválido.";
}
```

---

## 🔐 Recomendações de Mitigação

1. **Validar e sanitizar entradas** — aceitar apenas o formato esperado (ex.: somente endereços IP válidos via regex ou `FILTER_VALIDATE_IP`).
2. **Usar `escapeshellarg()`** — escapar argumentos antes de passá-los ao shell.
3. **Evitar chamadas diretas ao shell** — substituir por bibliotecas nativas da linguagem quando possível.
4. **Implementar WAF (Web Application Firewall)** — bloquear payloads com operadores de shell (`;`, `&&`, `|`, `` ` ``).
5. **Seguir o Princípio do Menor Privilégio** — o processo do servidor web não deve rodar como `root`.
6. **Monitorar logs ativamente** — alertar para padrões de requisições com caracteres especiais no parâmetro de entrada.

---

## 📚 Referências

- [OWASP - Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [DVWA - Damn Vulnerable Web Application](https://github.com/digininja/DVWA)
- [LetsDefend - Plataforma de Treinamento SOC](https://letsdefend.io/)

---

*Documento produzido como registro de exercício prático de análise de logs na plataforma LetsDefend.*
