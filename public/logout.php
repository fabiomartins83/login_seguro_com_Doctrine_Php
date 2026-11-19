<?php
declare(strict_types=1);

/** Encerra a sessão criada por login.php (POST). Mesmas defesas de origem e método do login. */

umask(0077);
ini_set('display_errors', '0');

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

function responder(int $status, array $dados, array $cabecalhos = []): never
{
    http_response_code($status);
    foreach ($cabecalhos as $nome => $valor) {
        header("{$nome}: {$valor}");
    }
    echo json_encode($dados, JSON_UNESCAPED_UNICODE);
    exit;
}

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
    $recebido = is_string($hostOrigem) ? $hostOrigem . ($portaOrigem ? ':' . $portaOrigem : '') : '';
    if ($recebido === '' || strcasecmp($recebido, (string) ($_SERVER['HTTP_HOST'] ?? '')) !== 0) {
        responder(403, ['ok' => false, 'mensagem' => 'Origem não permitida.']);
    }
}

require dirname(__DIR__) . '/vendor/autoload.php';

try {
    $https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    $parametros = [
        'lifetime' => 0, 'path' => '/', 'secure' => $https, 'httponly' => true, 'samesite' => 'Strict',
    ];
    session_save_path(App\Config::pastaDados() . '/sessoes'); // mesma pasta usada no login
    session_name('LOGINSID');
    session_set_cookie_params($parametros);

    if (isset($_COOKIE['LOGINSID'])) {
        ini_set('session.use_strict_mode', '1');
        session_start();
        $_SESSION = [];
        session_destroy(); // apaga o arquivo da sessão no servidor
        // Expira o cookie no navegador
        setcookie('LOGINSID', '', [
            'expires' => time() - 3600, 'path' => '/', 'secure' => $https,
            'httponly' => true, 'samesite' => 'Strict',
        ]);
    }
} catch (Throwable) {
    responder(500, ['ok' => false, 'mensagem' => 'Erro inesperado.']);
}

responder(200, ['ok' => true, 'mensagem' => 'Sessão encerrada.']);
