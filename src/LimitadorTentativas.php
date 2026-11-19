<?php
declare(strict_types=1);

namespace App;

/**
 * Limite de tentativas com atraso crescente (1, 2, 4, 8, 16, 30, 30... s) e bloqueio ao
 * esgotar o máximo. No terminal o atraso era um sleep(); no servidor, dormir prende um
 * worker, então o atraso vira uma regra: tentativas antes de "liberado_em" são recusadas.
 *
 * A tentativa é CONTADA ANTES de a senha ser verificada (e devolvida se der certo). Assim,
 * requisições paralelas não furam o limite enquanto o Argon2 ainda está calculando.
 */
final class LimitadorTentativas
{
    public function __construct(private readonly \PDO $pdo)
    {
    }

    /**
     * @param array<string,int> $limites chave => máximo de tentativas daquela chave
     * @return array{permitido:bool, espera:int, bloqueado:bool}
     *         espera: segundos até a próxima tentativa; bloqueado: máximo esgotado
     */
    public function iniciarTentativa(array $limites, ?int $agora = null): array
    {
        $agora ??= time();
        $this->pdo->exec('BEGIN IMMEDIATE');
        try {
            // Limpa registros vencidos (mantém a tabela pequena)
            $limpa = $this->pdo->prepare(
                'DELETE FROM tbTentativas WHERE ultima_falha + :janela <= :agora AND liberado_em <= :agora'
            );
            $this->executar($limpa, [':janela' => Config::JANELA_SEGUNDOS, ':agora' => $agora]);

            $atuais = [];
            $recusa = 0;
            $esgotado = false;
            foreach ($limites as $chave => $maximo) {
                $linha = $this->ler((string) $chave);
                $atuais[$chave] = $linha;
                if ($linha !== null && $linha['liberado_em'] > $agora) {
                    $recusa = max($recusa, $linha['liberado_em'] - $agora);
                    $esgotado = $esgotado || $linha['falhas'] >= $maximo;
                }
            }
            if ($recusa > 0) {
                $this->pdo->exec('COMMIT');
                return ['permitido' => false, 'espera' => $recusa, 'bloqueado' => $esgotado];
            }

            $espera = 0;
            $bloqueado = false;
            $grava = $this->pdo->prepare(
                'INSERT INTO tbTentativas (chave, falhas, ultima_falha, liberado_em)
                 VALUES (:chave, :falhas, :agora, :liberado)
                 ON CONFLICT(chave) DO UPDATE SET falhas = excluded.falhas,
                     ultima_falha = excluded.ultima_falha, liberado_em = excluded.liberado_em'
            );
            foreach ($limites as $chave => $maximo) {
                $falhas = ($atuais[$chave]['falhas'] ?? 0) + 1;
                $esgota = $falhas >= $maximo;
                $atraso = $esgota ? Config::BLOQUEIO_SEGUNDOS : Config::calcularAtraso($falhas);
                $this->executar($grava, [
                    ':chave' => (string) $chave,
                    ':falhas' => $falhas,
                    ':agora' => $agora,
                    ':liberado' => $agora + $atraso,
                ]);
                $espera = max($espera, $atraso);
                $bloqueado = $bloqueado || $esgota;
            }
            $this->pdo->exec('COMMIT');
            return ['permitido' => true, 'espera' => $espera, 'bloqueado' => $bloqueado];
        } catch (\Throwable $e) {
            $this->rollback();
            throw $e;
        }
    }

    /**
     * Login correto: zera o contador do usuário e devolve a tentativa gasta ao IP
     * (o IP não é zerado de vez, para um login válido não "lavar" tentativas de adivinhação).
     */
    public function registrarSucesso(string $chaveUsuario, string $chaveIp, ?int $agora = null): void
    {
        $agora ??= time();
        $this->pdo->exec('BEGIN IMMEDIATE');
        try {
            $this->executar($this->pdo->prepare('DELETE FROM tbTentativas WHERE chave = ?'), [$chaveUsuario]);
            $this->executar(
                $this->pdo->prepare('UPDATE tbTentativas SET falhas = MAX(falhas - 1, 0), liberado_em = ? WHERE chave = ?'),
                [$agora, $chaveIp]
            );
            $this->executar(
                $this->pdo->prepare('DELETE FROM tbTentativas WHERE chave = ? AND falhas <= 0'),
                [$chaveIp]
            );
            $this->pdo->exec('COMMIT');
        } catch (\Throwable $e) {
            $this->rollback();
            throw $e;
        }
    }

    /**
     * Executa com tipos explícitos. O execute([...]) do PDO envia tudo como TEXTO, e no
     * SQLite um texto é sempre "maior" que um número quando não há afinidade de coluna
     * (ex.: `ultima_falha + :janela <= :agora`), o que apagaria todos os registros.
     *
     * @param array<string,int|string>|list<int|string> $params
     */
    private function executar(\PDOStatement $st, array $params): void
    {
        foreach ($params as $chave => $valor) {
            $st->bindValue(
                is_int($chave) ? $chave + 1 : $chave,
                $valor,
                is_int($valor) ? \PDO::PARAM_INT : \PDO::PARAM_STR
            );
        }
        $st->execute();
    }

    /** @return array{falhas:int, ultima_falha:int, liberado_em:int}|null */
    private function ler(string $chave): ?array
    {
        $st = $this->pdo->prepare('SELECT falhas, ultima_falha, liberado_em FROM tbTentativas WHERE chave = ?');
        $this->executar($st, [$chave]);
        $linha = $st->fetch(\PDO::FETCH_ASSOC);
        if ($linha === false) {
            return null;
        }
        return [
            'falhas' => (int) $linha['falhas'],
            'ultima_falha' => (int) $linha['ultima_falha'],
            'liberado_em' => (int) $linha['liberado_em'],
        ];
    }

    private function rollback(): void
    {
        try {
            $this->pdo->exec('ROLLBACK');
        } catch (\Throwable) {
            // sem transação aberta
        }
    }
}
