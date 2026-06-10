# 🔍 Análise de Log: Exploração de IDOR (Insecure Direct Object Reference)

> **Plataforma:** LetsDefend  
> **Tipo de Ataque:** IDOR — Insecure Direct Object Reference  
> **Aplicação Alvo:** DVWA (Damn Vulnerable Web Application)  
> **Data dos Eventos:** 01/Mar/2022  

---

## 📌 Contexto

Durante o monitoramento de um ambiente simulado no DVWA, o endereço IP `192.168.31.174` realizou uma autenticação legítima seguida de uma série de requisições sequenciais atípicas ao endpoint de informações de usuários. O padrão de acesso incremental aos IDs entrega claramente a intenção do atacante: enumerar e extrair dados de todos os perfis cadastrados na aplicação.

---

## 🗃️ Log Analisado

```text

<img width="1405" height="798" alt="image" src="https://github.com/user-attachments/assets/4f3bd885-03aa-47b9-b62b-d7ab6046622b" />

192.168.31.174 - - [01/Mar/2022:11:42:16 -0800] "POST /dvwa/login.php HTTP/1.1" 302 -
192.168.31.174 - - [01/Mar/2022:11:42:32 -0800] "GET /dvwa/get_user_info/?id=1 HTTP/1.1" 200 1050
192.168.31.174 - - [01/Mar/2022:11:42:33 -0800] "GET /dvwa/get_user_info/?id=2 HTTP/1.1" 200 978
192.168.31.174 - - [01/Mar/2022:11:42:35 -0800] "GET /dvwa/get_user_info/?id=3 HTTP/1.1" 200 1242
192.168.31.174 - - [01/Mar/2022:11:42:36 -0800] "GET /dvwa/get_user_info/?id=4 HTTP/1.1" 200 1021
192.168.31.174 - - [01/Mar/2022:11:42:37 -0800] "GET /dvwa/get_user_info/?id=5 HTTP/1.1" 200 771
192.168.31.174 - - [01/Mar/2022:11:42:45 -0800] "GET /dvwa/get_user_info/?id=6 HTTP/1.1" 200 928
192.168.31.174 - - [01/Mar/2022:11:42:46 -0800] "GET /dvwa/get_user_info/?id=7 HTTP/1.1" 200 1837
192.168.31.174 - - [01/Mar/2022:11:42:51 -0800] "GET /dvwa/get_user_info/?id=8 HTTP/1.1" 200 1423
```

---

## 🧩 Decomposição dos Campos de Log

| Campo | Descrição |
|---|---|
| `192.168.31.174` | IP de origem do atacante (rede interna) |
| `[01/Mar/2022:11:42:xx -0800]` | Timestamp dos eventos (fuso UTC-8) |
| `POST` / `GET` | Métodos HTTP utilizados |
| `/dvwa/login.php` | Endpoint de autenticação |
| `/dvwa/get_user_info/` | Endpoint vulnerável — consulta de perfis de usuários |
| `?id=1` ... `?id=8` | Query parameter manipulado incrementalmente |
| `302` | Redirecionamento após login bem-sucedido |
| `200` | Requisição processada com sucesso |
| `1050`, `978`, `1242`... | Tamanho da resposta em bytes — **varia a cada ID** |

---

## ⚔️ Linha do Tempo do Ataque

### Fase 1 — Autenticação (Linha 219)

O atacante realiza um `POST` em `/dvwa/login.php` e recebe o código `302` (redirecionamento), confirmando que o **login foi efetuado com sucesso** antes do início da exploração.

### Fase 2 — Enumeração por IDOR (Linhas 226 a 233)

Uma vez autenticado, o atacante acessa o endpoint `/dvwa/get_user_info/` e começa a modificar **incrementalmente** o parâmetro `?id` na URL:

| Requisição | Parâmetro | Resposta | Bytes Retornados |
|---|---|---|---|
| GET | `?id=1` | 200 OK | 1050 |
| GET | `?id=2` | 200 OK | 978 |
| GET | `?id=3` | 200 OK | 1242 |
| GET | `?id=4` | 200 OK | 1021 |
| GET | `?id=5` | 200 OK | 771 |
| GET | `?id=6` | 200 OK | 928 |
| GET | `?id=7` | 200 OK | 1837 |
| GET | `?id=8` | 200 OK | 1423 |

A sequência ocorreu em apenas **19 segundos** (11:42:32 → 11:42:51), o que indica acesso automatizado ou deliberadamente rápido.

---

## 🎯 Evidência de Sucesso: Variação no Tamanho da Resposta

Este é o indicador mais importante do log. Diferente do exercício anterior (Command Injection), onde **todos os tamanhos eram idênticos** (4477 bytes) indicando resposta genérica, aqui os bytes retornados **variam significativamente** a cada requisição:

> Tamanhos idênticos = página de erro estática (sem dados reais)  
> **Tamanhos variáveis = dados reais de usuários diferentes sendo entregues**

A variação de bytes prova que o backend buscou e renderizou informações distintas do banco de dados para cada ID — nomes, e-mails e demais atributos de perfis de usuários reais. Isso confirma que houve **Data Exfiltration** (vazamento de dados).

---

## 🚨 Indicadores de Comprometimento (IOCs)

| Tipo | Valor |
|---|---|
| IP Origem | `192.168.31.174` |
| Endpoint Autenticação | `/dvwa/login.php` |
| Endpoint Explorado | `/dvwa/get_user_info/` |
| Parâmetro Manipulado | `?id=` (valores 1 a 8) |
| Códigos HTTP | `302` (login) + `200` (todas as consultas) |
| Período do Ataque | `11:42:16` – `11:42:51` (35 segundos no total) |
| Evidência de Exfiltração | Variação no payload: 771 a 1837 bytes |

---

## 🛡️ Vulnerabilidade Explorada

**CWE-639 — Authorization Bypass Through User-Controlled Key**  
(Subclasse de IDOR — Insecure Direct Object Reference)

A aplicação expõe uma **chave primária sequencial e previsível** (`?id=1, 2, 3...`) diretamente na URL, e **não valida** se o usuário autenticado tem permissão para acessar o recurso solicitado. O sistema confia cegamente que o usuário só pedirá IDs que lhe pertencem.

**Exemplo conceitual do código vulnerável (PHP):**
```php
// ❌ VULNERÁVEL — sem verificação de autorização
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = $id";
$result = $db->query($query);
echo json_encode($result);
```

**Correção recomendada:**
```php
// ✅ SEGURO — valida se o ID pertence ao usuário da sessão
$id = intval($_GET['id']);
$session_user_id = $_SESSION['user_id'];

if ($id !== $session_user_id) {
    http_response_code(403);
    echo json_encode(["error" => "Acesso negado."]);
    exit;
}

$query = "SELECT * FROM users WHERE id = ?";
// ... executa com prepared statement
```

---

## 🔐 Recomendações de Mitigação

1. **Nunca expor chaves primárias sequenciais na URL** — usar identificadores opacos como UUIDs (`/get_user_info/?id=a3f8c2d1-...`).
2. **Validar autorização no backend a cada requisição** — garantir que o usuário A não possa acessar recursos do usuário B.
3. **Implementar controle de acesso baseado em sessão** — comparar o ID solicitado com o ID da sessão autenticada.
4. **Usar Prepared Statements** — prevenir SQL Injection secundário no mesmo endpoint.
5. **Rate limiting** — bloquear ou alertar para enumerações rápidas e sequenciais do mesmo IP.
6. **Monitoramento de padrão sequencial** — regras de SIEM para detectar acesso incremental a parâmetros numéricos em curto intervalo de tempo.

---

## 🔄 Comparativo com o Exercício Anterior

| Aspecto | Command Injection (Ex. 01) | IDOR (Ex. 02) |
|---|---|---|
| Método HTTP | POST | GET |
| Vetor de ataque | Corpo da requisição | Query parameter na URL |
| Autenticação prévia | Não necessária | Sim (login legítimo) |
| Código de resposta | 200 | 200 |
| Tamanho das respostas | **Idêntico** (4477 bytes) | **Variável** (771–1837 bytes) |
| Confirmação de sucesso | Código 200 | Variação no payload |
| Objetivo | Reconhecimento do sistema | Exfiltração de dados de usuários |

---

## 📚 Referências

- [OWASP - Insecure Direct Object Reference](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [PortSwigger - IDOR](https://portswigger.net/web-security/access-control/idor)
- [DVWA - Damn Vulnerable Web Application](https://github.com/digininja/DVWA)
- [LetsDefend - Plataforma de Treinamento SOC](https://letsdefend.io/)

---

*Documento produzido como registro de exercício prático de análise de logs na plataforma LetsDefend.*
