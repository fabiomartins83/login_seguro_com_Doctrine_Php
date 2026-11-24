<?php
declare(strict_types=1);

namespace App;

/**
 * Roteador mínimo: associa (método + caminho) a uma função.
 * Sem dependências externas. Funciona na raiz do domínio ou em subpasta (ex.: /login_seguro/).
 */
final class Roteador
{
    /** @var array<string, array<string, callable>> caminho => [método => manipulador] */
    private array $rotas = [];

    public function get(string $caminho, callable $manipulador): self
    {
        return $this->adicionar('GET', $caminho, $manipulador);
    }

    public function post(string $caminho, callable $manipulador): self
    {
        return $this->adicionar('POST', $caminho, $manipulador);
    }

    public function adicionar(string $metodo, string $caminho, callable $manipulador): self
    {
        $this->rotas[self::normalizar($caminho)][strtoupper($metodo)] = $manipulador;
        return $this;
    }

    /**
     * @param string $uri   REQUEST_URI (com ou sem query string)
     * @param string $base  Subpasta onde o site está (ex.: "/login_seguro"); '' na raiz
     */
    public function despachar(string $metodo, string $uri, string $base = ''): void
    {
        $caminho = (string) (parse_url($uri, PHP_URL_PATH) ?? '/');
        $caminho = rawurldecode($caminho);
        if ($base !== '' && str_starts_with($caminho, $base)) {
            $caminho = substr($caminho, strlen($base));
        }
        $caminho = self::normalizar($caminho);
        $metodo = strtoupper($metodo);
        if ($metodo === 'HEAD') {
            $metodo = 'GET';
        }

        if (!isset($this->rotas[$caminho])) {
            self::erro(404, 'Página não encontrada.');
        }
        if (!isset($this->rotas[$caminho][$metodo])) {
            header('Allow: ' . implode(', ', array_keys($this->rotas[$caminho])));
            self::erro(405, 'Método não permitido.');
        }
        ($this->rotas[$caminho][$metodo])();
    }

    /** "/", "", "//x/" => "/" , "/x" */
    private static function normalizar(string $caminho): string
    {
        $caminho = '/' . trim($caminho, '/');
        return $caminho;
    }

    private static function erro(int $status, string $mensagem): never
    {
        http_response_code($status);
        header('Content-Type: text/plain; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        echo $mensagem;
        exit;
    }
}
