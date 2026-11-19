<?php
declare(strict_types=1);

/**
 * Endpoint de login (POST JSON {"usuario": "...", "senha": "..."}).
 * Responde sempre JSON. Mesma mensagem para qualquer falha de credencial.
 */

// Arquivos novos (banco, sessões, hash falso) já nascem acessíveis só ao dono
umask(0077);

error_reporting(E_ALL & ~E_DEPRECATED & ~E_USER_DEPRECATED);
ini_set('display_errors', '0');
// Stack traces sem argumentos: senhas nunca aparecem em traces nem em logs
ini_set('zend.exception_ignore_args', '1');
set_error_handler(static function (int $n, string $msg, string $arq, int $lin): bool {
    if (!(error_reporting() & $n)) {
        return false;
    }
    throw new ErrorException($msg, 0, $n, $arq, $lin);
});

use App\Config;
use App\Banco;
use App\Entrada;
use App\ErroDeConfiguracao;
use App\LimitadorTentativas;
use App\Usuarios;

function responder(int $status, array $dados, array $cabecalhos = []): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    foreach ($cabecalhos as $nome => $valor) {
        header("{$nome}: {$valor}");
    }
    echo json_encode($dados, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

$autoload = dirname(__DIR__) . '/vendor/autoload.php';
if (!is_file($autoload)) {
    responder(500, ['ok' => false, 'mensagem' => 'Erro de configuração: dependências não instaladas (rode "composer install").']);
}
require $autoload;

header('Cache-Control: no-store');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");
header('X-Frame-Options: DENY');

const MSG_FALHA = 'Falha de login: Usuário ou senha inválidos.';

$em = null;
try {
    // ---- Método, tipo de conteúdo e origem (defesa contra CSRF) -----------------------------
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        responder(405, ['ok' => false, 'mensagem' => 'Método não permitido.'], ['Allow' => 'POST']);
    }
    $tipo = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
    if ($tipo !== 'application/json') {
        responder(415, ['ok' => false, 'mensagem' => 'Requisição inválida.']);
    }
    $origem = $_SERVER['HTTP_ORIGIN'] ?? null;
    if ($origem !== null) {
        $hostOrigem = parse_url($origem, PHP_URL_HOST);
        $portaOrigem = parse_url($origem, PHP_URL_PORT);
        $esperado = (string) ($_SERVER['HTTP_HOST'] ?? '');
        $recebido = is_string($hostOrigem) ? $hostOrigem . ($portaOrigem ? ':' . $portaOrigem : '') : '';
        if ($recebido === '' || strcasecmp($recebido, $esperado) !== 0) {
            responder(403, ['ok' => false, 'mensagem' => 'Origem não permitida.']);
        }
    }

    // ---- Corpo da requisição ------------------------------------------------------------------
    $corpo = (string) file_get_contents('php://input', false, null, 0, Config::CORPO_MAX + 1);
    if (strlen($corpo) > Config::CORPO_MAX) {
        responder(413, ['ok' => false, 'mensagem' => 'Requisição grande demais.']);
    }
    try {
        $dados = json_decode($corpo, true, 4, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        responder(400, ['ok' => false, 'mensagem' => 'Requisição inválida.']);
    }
    if (!is_array($dados) || !is_string($dados['usuario'] ?? null) || !is_string($dados['senha'] ?? null)) {
        responder(400, ['ok' => false, 'mensagem' => 'Requisição inválida.']);
    }

    // ---- Normalização -------------------------------------------------------------------------
    $usuario = Entrada::normalizarUsuario($dados['usuario']);
    $senha = Entrada::normalizarSenha($dados['senha']);
    unset($dados, $corpo);

    // ---- Banco e limite de tentativas ---------------------------------------------------------
    $em = Banco::criarEntityManager();
    Usuarios::prepararBanco($em);

    $chaveIp = 'ip:' . ($_SERVER['REMOTE_ADDR'] ?? 'desconhecido');
    $chaveUsuario = 'usr:' . Entrada::impressao($usuario);
    $limitador = new LimitadorTentativas($em->getConnection()->getNativeConnection());
    $limite = $limitador->iniciarTentativa([
        $chaveIp => Config::MAX_TENTATIVAS_IP,
        $chaveUsuario => Config::MAX_TENTATIVAS,
    ]);
    if (!$limite['permitido']) {
        responder(
            429,
            [
                'ok' => false,
                'mensagem' => $limite['bloqueado']
                    ? 'Número máximo de tentativas atingido.'
                    : 'Muitas tentativas em sequência.',
                'aguarde' => $limite['espera'],
                'bloqueado' => $limite['bloqueado'],
            ],
            ['Retry-After' => (string) $limite['espera']]
        );
    }

    // ---- Autenticação -------------------------------------------------------------------------
    $nomeUsuario = (new Usuarios($em))->tentarLogin($usuario, $senha);
    unset($senha);

    if ($nomeUsuario === null) {
        responder(401, [
            'ok' => false,
            'mensagem' => MSG_FALHA, // a mesma para qualquer erro
            'aguarde' => $limite['espera'],
            'bloqueado' => $limite['bloqueado'],
        ]);
    }

    $limitador->registrarSucesso($chaveUsuario, $chaveIp);

    // ---- Sessão (só após o sucesso) -----------------------------------------------------------
    $pastaSessoes = Config::pastaDados() . '/sessoes';
    Banco::prepararPastaPrivada($pastaSessoes);
    $https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.gc_probability', '1');
    ini_set('session.gc_divisor', '100');
    ini_set('session.gc_maxlifetime', '28800');
    session_save_path($pastaSessoes);
    session_name('LOGINSID');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $https,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
    session_regenerate_id(true); // novo identificador a cada login (evita fixação de sessão)
    $_SESSION = ['usuario' => $nomeUsuario, 'login_em' => time()];
    session_write_close();

    responder(200, [
        'ok' => true,
        'usuario' => $nomeUsuario,
        'mensagem' => "Bem vindo ao sistema, {$nomeUsuario}.",
    ]);
} catch (ErroDeConfiguracao $erro) { // mensagem controlada, segura para exibir
    responder(500, ['ok' => false, 'mensagem' => 'Erro de configuração: ' . $erro->getMessage()]);
} catch (Throwable $erro) {
    if (Config::modoDepuracao()) {
        error_log((string) $erro); // completo, mas só no log do servidor
    }
    // Só o TIPO do erro é exibido: a mensagem pode conter consultas, nomes e hashes
    responder(500, [
        'ok' => false,
        'mensagem' => 'Erro inesperado (' . (new ReflectionClass($erro))->getShortName() . ').',
    ]);
} finally {
    if ($em !== null) {
        try {
            $em->getConnection()->close();
        } catch (Throwable) {
        }
    }
}
