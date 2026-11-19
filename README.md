# Login seguro (PHP + Doctrine ORM + SQLite 3)

Port do `login_seguro.py` para uma página web.

```
public/            <- DocumentRoot (única pasta exposta)
  login.html       formulário: Usuário, Senha, botão "Acessar"
  login.css
  login.js         envia o JSON via fetch e mostra mensagens/contagem de espera
  login.php        endpoint de login (POST JSON)
src/
  Config.php                 constantes (tentativas, atrasos, parâmetros do Argon2id)
  Entrada.php                normalização NFKC, validação e política de senha
  Senhas.php                 Argon2id, rehash e hash falso
  Banco.php                  pasta/arquivo privados, EntityManager e DDL com CHECKs
  LimitadorTentativas.php    atraso crescente e bloqueio (por IP e por usuário)
  Usuarios.php               cadastro, busca e autenticação (Doctrine ORM)
  Entity/Usuario.php         entidade da tabela tbUsuarios
tests/teste_unitario.php     testes das funções puras (sem Doctrine)
```

## Rodar

```bash
# se você tinha uma versão anterior: apague as pastas/arquivos gerados por ela
rm -rf vendor composer.lock

composer install
php -S 127.0.0.1:8000 -t public      # só para desenvolvimento
# abra http://127.0.0.1:8000/login.html
```

No Windows/XAMPP: apague a pasta `vendor` e o `composer.lock`, rode `composer install` e aponte o
servidor para a pasta `public/` (ou acesse `http://localhost/login_seguro_php/public/login.html`).

Requisitos: PHP >= 8.2 (testado com 8.3 e com o Doctrine ORM 3.8 / DBAL 4.6) com `intl`,
`mbstring`, `pdo_sqlite` e Argon2id (`php -r 'var_dump(defined("PASSWORD_ARGON2ID"));'` deve
imprimir `true`). Testes das funções puras: `php tests/teste_unitario.php`.

### Erros corrigidos em relação à versão anterior

1. `Symfony LazyGhost is not available...` (ORMInvalidArgumentException, HTTP 500 em todo login):
   o Doctrine ORM 3.x exige proxies preguiçosos para criar o `EntityManager`. Agora `Banco.php`
   ativa os *native lazy objects* no PHP 8.4+ e, no PHP < 8.4, usa o `symfony/var-exporter` 7
   (adicionado ao `composer.json`) com uma pasta privada de proxies.
2. `composer.json` agora fixa `symfony/*` em 7.x, que funciona do PHP 8.2 ao 8.4+; sem isso o
   Composer podia escolher pacotes que exigem PHP >= 8.4.1.
3. `public/.htaccess` ganhou `Require all granted`: sem ele, o `Require all denied` da raiz
   bloqueava (403) também `login.html` e `login.php` no Apache.

## Variáveis de ambiente

| Variável | Efeito |
|---|---|
| `LOGIN_SEGURO_DIR` | pasta do banco, das sessões e do hash falso (padrão `~/.login_seguro`; deve ser gravável pelo usuário do servidor web e ficar fora de `public/`) |
| `SENHA_INICIAL_TESTE` | senha do usuário de teste inicial |
| `LOGIN_SEGURO_DEBUG=1` | grava o erro completo no `error_log` do servidor (nunca no navegador) |

## Equivalência com o projeto Python

| Python | PHP |
|---|---|
| Argon2id `t=3, m=65536, p=4` | `password_hash(..., PASSWORD_ARGON2ID, Config::ARGON2)` (hashes compatíveis nos dois sentidos) |
| `HASH_FALSO` para igualar o tempo | `Senhas::hashFalso()` (guardado em `hash_falso.txt`, modo 0600) |
| NFKC + strip + minúsculas, regex `[a-z0-9_.-]{1,100}` | `Entrada` (usa `\z`, pois `$` aceitaria `\n` final) |
| Política de senha só no cadastro | `Entrada::motivoSenhaFraca()` + `Usuarios::cadastrar()` |
| CHECKs do SQLite (nome, hash `$argon2id$*`, boolean) | DDL em `Banco::criarTabelas()` (o Doctrine não expressa CHECK) |
| `foreign_keys = ON`, pasta 0700, banco 0600, `umask(0o077)` | iguais |
| Mensagem única para qualquer falha | `Falha de login: Usuário ou senha inválidos.` |
| Só o tipo do erro é exibido | `Erro inesperado (Tipo).` |
| 10 tentativas, atraso 1, 2, 4, 8, 16, 30 s | `LimitadorTentativas` (veja abaixo) |
| Log desativado | continua sem log de tentativas |

## O que muda por ser web

- **Atraso/limite**: em vez de `sleep()` (que prenderia um processo), o servidor recusa
  (HTTP 429) tentativas feitas antes do fim do atraso; o `login.js` mostra a contagem.
  O limite é por usuário (10) e por IP (30); ao esgotar, bloqueio de 15 min (`Config`).
  A tentativa é contada *antes* de verificar a senha, então requisições paralelas não
  furam o limite. Atrás de proxy reverso, `REMOTE_ADDR` será o IP do proxy: ajuste
  `login.php` para usar o IP real **somente** de um proxy confiável.
- **Sessão**: no sucesso é criada uma sessão (cookie `HttpOnly`, `SameSite=Strict`,
  `Secure` em HTTPS, id regenerado), gravada em `LOGIN_SEGURO_DIR/sessoes`.
- **CSRF**: exige `Content-Type: application/json`, confere `Origin` com o `Host`.
- **Cabeçalhos/CSP**: enviados por `login.php`, por `public/.htaccess` (Apache) e por
  `<meta>` no `login.html`. Em produção use HTTPS e HSTS.
- Memória: cada verificação usa 64 MiB (Argon2); o limitador também protege o servidor.
