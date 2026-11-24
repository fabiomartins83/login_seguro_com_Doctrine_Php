<?php
declare(strict_types=1);

/**
 * Front controller: o Apache (via .htaccess) envia para cá toda URL que não seja
 * um arquivo real de public/. Para criar uma rota nova, adicione uma linha abaixo.
 */

// O roteador não depende do Composer: a rota "/" funciona mesmo antes do "composer install"
require dirname(__DIR__) . '/src/Roteador.php';

use App\Roteador;

/** Entrega um arquivo estático de public/ (somente os que a rota nomeia explicitamente). */
function servirHtml(string $arquivo): never
{
    $caminho = __DIR__ . '/' . $arquivo;
    if (!is_file($caminho)) {
        http_response_code(500);
        header('Content-Type: text/plain; charset=utf-8');
        echo 'Erro de configuração: arquivo da página não encontrado.';
        exit;
    }
    header('Content-Type: text/html; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-cache');
    readfile($caminho);
    exit;
}

// Subpasta de instalação (ex.: "/login_seguro"), deduzida do caminho deste script
$base = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/');
$caminhoUrl = (string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
// Projeto aberto pela raiz (.htaccess da raiz reescreve para public/): a URL não contém "/public"
if (str_ends_with($base, '/public') && !str_starts_with($caminhoUrl, $base)) {
    $base = substr($base, 0, -strlen('/public'));
}

$roteador = new Roteador();
$roteador->get('/', static fn () => servirHtml('login.html'));

$roteador->despachar(
    $_SERVER['REQUEST_METHOD'] ?? 'GET',
    $_SERVER['REQUEST_URI'] ?? '/',
    $base
);
