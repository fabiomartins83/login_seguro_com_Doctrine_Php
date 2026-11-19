<?php
declare(strict_types=1);

namespace App;

/** Normalização e validação de entrada, e política de senha (só no cadastro). */
final class Entrada
{
    /** Lista pequena e local de senhas muito comuns (não substitui uma checagem de vazamentos). */
    private const SENHAS_COMUNS = [
        'password', 'password1', 'password12', 'password123', 'passw0rd123',
        '1234567890', '12345678910', '123456789012', '123456789a', 'a123456789',
        '0123456789', '9876543210', '0987654321', '1111111111', '0000000000',
        'qwertyuiop', 'qwerty12345', 'qwerty123456', '1q2w3e4r5t', '1qaz2wsx3edc',
        'abcdefghij', 'abc1234567', 'iloveyou123', 'letmein1234', 'welcome1234',
        'admin12345', 'administrator', 'senha12345', 'senha123456', 'mudar12345',
        'brasil12345',
    ];

    private const SEQUENCIAS = ['0123456789', 'abcdefghijklmnopqrstuvwxyz', 'qwertyuiopasdfghjklzxcvbnm'];

    /** NFKC unifica formas equivalentes (ex.: largura total). Texto inválido vira ''. */
    private static function nfkc(string $texto): string
    {
        $n = \Normalizer::normalize($texto, \Normalizer::FORM_KC);
        return $n === false ? '' : $n;
    }

    /** NFKC; depois strip e minúsculas. */
    public static function normalizarUsuario(string $texto): string
    {
        $t = self::nfkc($texto);
        // Mesmas bordas que o str.strip() do Python: espaços Unicode + separadores C0 (0x1C-0x1F)
        $t = preg_replace('/^[\s\x{1C}-\x{1F}]+|[\s\x{1C}-\x{1F}]+\z/u', '', $t) ?? '';
        return mb_strtolower($t, 'UTF-8');
    }

    /** Só NFKC, sem strip: preserva espaços intencionais nas bordas. */
    public static function normalizarSenha(string $texto): string
    {
        return self::nfkc($texto);
    }

    /** Só caracteres permitidos e tamanho limitado (espera texto já normalizado). */
    public static function usuarioValido(string $texto): bool
    {
        // \z (e não $): o $ do PCRE aceitaria um "\n" no final
        return preg_match('/^[a-z0-9_.-]{1,' . Config::TAMANHO_MAX . '}\z/', $texto) === 1;
    }

    /** Validação de FORMATO, usada no login; a força da senha é checada só no cadastro. */
    public static function senhaValida(string $texto): bool
    {
        $n = mb_strlen($texto, 'UTF-8');
        return $n > 0 && $n <= Config::TAMANHO_MAX;
    }

    /** Retorna o motivo da recusa ou null se a senha for aceitável (só no CADASTRO). */
    public static function motivoSenhaFraca(string $senha, string $nome): ?string
    {
        $minusculas = mb_convert_case($senha, MB_CASE_FOLD, 'UTF-8'); // equivalente ao casefold()
        if (mb_strlen($senha, 'UTF-8') < Config::TAMANHO_MIN_SENHA) {
            return 'use pelo menos ' . Config::TAMANHO_MIN_SENHA . ' caracteres.';
        }
        if (in_array($minusculas, self::SENHAS_COMUNS, true)) {
            return 'essa senha é muito comum.';
        }
        if (count(array_unique(mb_str_split($senha, 1, 'UTF-8'))) < 5) {
            return 'use mais caracteres diferentes.';
        }
        foreach (self::SEQUENCIAS as $seq) {
            if (str_contains($seq, $minusculas) || str_contains(strrev($seq), $minusculas)) {
                return 'não use sequências como 1234567890 ou abcdefghij.';
            }
        }
        if (mb_strlen($nome, 'UTF-8') >= 3 && str_contains($minusculas, $nome)) {
            return 'a senha não pode conter o nome de usuário.';
        }
        return null;
    }

    /** Identificador curto e irreversível do texto digitado (usado como chave do limitador). */
    public static function impressao(string $texto): string
    {
        return hash('sha256', mb_substr($texto, 0, Config::TAMANHO_MAX, 'UTF-8'));
    }
}
