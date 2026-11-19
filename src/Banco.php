<?php
declare(strict_types=1);

namespace App;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/** Pasta/arquivo privados, conexão SQLite e DDL (com as CHECK constraints do original). */
final class Banco
{
    public static function caminho(): string
    {
        return Config::pastaDados() . '/sistema.db';
    }

    /** chmod explícito: o umask só vale para arquivos NOVOS. Sem efeito em Windows. */
    public static function restringirPermissao(string $caminho, int $modo): void
    {
        @chmod($caminho, $modo);
    }

    /** Cria a pasta (acesso só do dono) e recusa pastas dentro da área pública do site. */
    public static function prepararPastaPrivada(string $pasta): void
    {
        if (!is_dir($pasta) && !@mkdir($pasta, 0700, true) && !is_dir($pasta)) {
            throw new ErroDeConfiguracao(
                'Não foi possível criar a pasta de dados. Defina LOGIN_SEGURO_DIR com uma pasta gravável.'
            );
        }
        self::restringirPermissao($pasta, 0700);

        $real = realpath($pasta);
        $publica = realpath(dirname(__DIR__) . '/public');
        if ($real !== false && $publica !== false
            && ($real === $publica || str_starts_with($real, $publica . DIRECTORY_SEPARATOR))) {
            throw new ErroDeConfiguracao('A pasta de dados não pode ficar dentro da pasta pública do site.');
        }
        if (!is_writable($pasta)) {
            throw new ErroDeConfiguracao('A pasta de dados não é gravável pelo servidor web.');
        }
    }

    /**
     * Cria o EntityManager (Doctrine ORM) sobre SQLite 3, com chaves estrangeiras ativadas.
     * Pasta e arquivo do banco ficam acessíveis só ao dono.
     */
    public static function criarEntityManager(): EntityManager
    {
        $caminho = self::caminho();
        self::prepararPastaPrivada(dirname($caminho));

        // Cria o arquivo já com permissão 600 (um arquivo vazio é um banco SQLite válido)
        // e corrige a permissão de um banco que já existia com acesso mais aberto
        $h = @fopen($caminho, 'c');
        if ($h === false) {
            throw new ErroDeConfiguracao('Não foi possível abrir o arquivo do banco de dados.');
        }
        fclose($h);
        self::restringirPermissao($caminho, 0600);

        $conexao = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'path' => $caminho]);
        $conexao->executeStatement('PRAGMA foreign_keys = ON');
        $conexao->executeStatement('PRAGMA busy_timeout = 5000');

        $caminhos = [__DIR__ . '/Entity'];
        $cache = new ArrayAdapter(); // sem escrita de cache em disco
        $config = method_exists(ORMSetup::class, 'createAttributeMetadataConfig')
            ? ORMSetup::createAttributeMetadataConfig($caminhos, false, null, $cache)
            : ORMSetup::createAttributeMetadataConfiguration($caminhos, false, null, $cache);

        // Proxies preguiçosos (obrigatórios para criar o EntityManager no ORM 3.x):
        //  - PHP >= 8.4: objetos preguiçosos nativos do PHP (symfony/var-exporter 8 não gera mais proxies);
        //  - PHP < 8.4: proxies do symfony/var-exporter 6.4/7, que precisam de uma pasta privada.
        if (PHP_VERSION_ID >= 80400 && method_exists($config, 'enableNativeLazyObjects')) {
            $config->enableNativeLazyObjects(true);
        } else {
            $pastaProxies = Config::pastaDados() . '/proxies';
            self::prepararPastaPrivada($pastaProxies);
            $config->setProxyDir($pastaProxies);
            $config->setProxyNamespace('App\\Proxies');
            $config->setAutoGenerateProxyClasses(false); // a entidade nunca é carregada por proxy
        }

        return new EntityManager($conexao, $config);
    }

    /**
     * Cria as tabelas se ainda não existirem. O Doctrine não expressa CHECK constraints
     * nos mapeamentos, então o DDL é escrito à mão (mesmas regras do original em SQLAlchemy).
     */
    public static function criarTabelas(Connection $conexao): void
    {
        $conexao->executeStatement(<<<'SQL'
CREATE TABLE IF NOT EXISTS tbUsuarios (
    id INTEGER PRIMARY KEY NOT NULL,
    nome_usuario TEXT NOT NULL UNIQUE,
    senha_usuario TEXT NOT NULL,
    Inativo BOOLEAN NOT NULL DEFAULT 0,
    CONSTRAINT ck_inativo_booleano CHECK (Inativo IN (0, 1)),
    CONSTRAINT ck_nome_tamanho CHECK (length(nome_usuario) BETWEEN 1 AND 100),
    CONSTRAINT ck_nome_caracteres CHECK (nome_usuario NOT GLOB '*[^a-z0-9_.-]*'),
    CONSTRAINT ck_senha_argon2id CHECK (senha_usuario GLOB '$argon2id$*')
)
SQL);

        // Controle de tentativas (equivalente web do laço de tentativas com atraso crescente)
        $conexao->executeStatement(<<<'SQL'
CREATE TABLE IF NOT EXISTS tbTentativas (
    chave TEXT PRIMARY KEY NOT NULL,
    falhas INTEGER NOT NULL,
    ultima_falha INTEGER NOT NULL,
    liberado_em INTEGER NOT NULL
)
SQL);
    }
}
