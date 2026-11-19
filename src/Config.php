<?php
declare(strict_types=1);

namespace App;

/** Configuração central (equivalente à seção "Configuração" do projeto Python). */
final class Config
{
    /** Tentativas por usuário antes do bloqueio (MAX_TENTATIVAS do original). */
    public const MAX_TENTATIVAS = 10;
    /** Tentativas por IP antes do bloqueio (mais alto: um IP pode ser um NAT compartilhado). */
    public const MAX_TENTATIVAS_IP = 30;
    public const TAMANHO_MAX = 100;
    /** Política de cadastro (não vale para a tentativa de login). */
    public const TAMANHO_MIN_SENHA = 10;

    /** Atraso crescente entre tentativas falhas, em segundos: 1, 2, 4, 8, 16, 30, 30... */
    public const ATRASO_BASE = 1;
    public const ATRASO_MAX = 30;

    /** Bloqueio ao esgotar as tentativas e janela de esquecimento das falhas (segundos). */
    public const BLOQUEIO_SEGUNDOS = 900;
    public const JANELA_SEGUNDOS = 900;

    /** Parâmetros do Argon2id definidos explicitamente (os mesmos do projeto Python). */
    public const ARGON2 = ['memory_cost' => 65536, 'time_cost' => 3, 'threads' => 4];

    /** Tamanho máximo do corpo da requisição (bytes). */
    public const CORPO_MAX = 4096;

    /**
     * Pasta privada para banco e arquivos auxiliares, FORA da pasta pública.
     * Pode ser trocada pela variável de ambiente LOGIN_SEGURO_DIR.
     */
    public static function pastaDados(): string
    {
        $env = getenv('LOGIN_SEGURO_DIR');
        if (is_string($env) && $env !== '') {
            return rtrim($env, '/\\');
        }
        $home = getenv('HOME');
        if (is_string($home) && $home !== '') {
            return rtrim($home, '/\\') . '/.login_seguro';
        }
        return dirname(__DIR__) . '/var/dados';
    }

    /** Em true, erros inesperados vão (completos) para o error_log do servidor; nunca para o cliente. */
    public static function modoDepuracao(): bool
    {
        return getenv('LOGIN_SEGURO_DEBUG') === '1';
    }

    /** Atraso após a n-ésima falha: dobra a cada falha, até o limite ATRASO_MAX. */
    public static function calcularAtraso(int $falhas): int
    {
        return (int) min(self::ATRASO_BASE * (2 ** max($falhas - 1, 0)), self::ATRASO_MAX);
    }
}
