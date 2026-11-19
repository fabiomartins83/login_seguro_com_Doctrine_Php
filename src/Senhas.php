<?php
declare(strict_types=1);

namespace App;

/** Hash Argon2id e verificação, com hash falso para igualar o tempo de resposta. */
final class Senhas
{
    public static function garantirSuporte(): void
    {
        if (!defined('PASSWORD_ARGON2ID')) {
            throw new ErroDeConfiguracao('Este PHP não foi compilado com suporte a Argon2id.');
        }
    }

    public static function hash(string $senha): string
    {
        self::garantirSuporte();
        return password_hash($senha, PASSWORD_ARGON2ID, Config::ARGON2);
    }

    /** True se a senha confere; False se errada ou se o hash estiver corrompido. */
    public static function verificar(string $hashSalvo, string $senha): bool
    {
        return password_verify($senha, $hashSalvo);
    }

    /** True se os parâmetros do Argon2 mudaram desde que o hash foi gravado. */
    public static function precisaNovoHash(string $hashSalvo): bool
    {
        return password_needs_rehash($hashSalvo, PASSWORD_ARGON2ID, Config::ARGON2);
    }

    /**
     * Hash de uma senha aleatória descartada, usado quando o usuário não existe (ou está
     * inativo) para que o tempo de resposta seja o mesmo nos dois casos. Como cada requisição
     * PHP é um processo novo, ele é gerado uma vez e guardado na pasta privada (modo 0600).
     */
    public static function hashFalso(): string
    {
        $arquivo = Config::pastaDados() . '/hash_falso.txt';
        $hash = is_file($arquivo) ? trim((string) @file_get_contents($arquivo)) : '';
        if ($hash !== '' && !str_starts_with($hash, '$argon2id$')) {
            $hash = '';
        }
        if ($hash === '' || self::precisaNovoHash($hash)) {
            $hash = self::hash(bin2hex(random_bytes(16)));
            $tmp = $arquivo . '.' . bin2hex(random_bytes(4)) . '.tmp';
            if (@file_put_contents($tmp, $hash . "\n", LOCK_EX) !== false) {
                @chmod($tmp, 0600);
                if (!@rename($tmp, $arquivo)) {
                    @unlink($tmp);
                }
            }
        }
        return $hash;
    }
}
