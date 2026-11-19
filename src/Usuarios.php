<?php
declare(strict_types=1);

namespace App;

use App\Entity\Usuario;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Doctrine\ORM\EntityManagerInterface;

/** Cadastro, busca e autenticação de usuários via Doctrine ORM. */
final class Usuarios
{
    public function __construct(private readonly EntityManagerInterface $em)
    {
    }

    /**
     * Cria a tabela e, se ela estiver vazia, cadastra o usuário de teste utilizando a
     * variável de ambiente SENHA_INICIAL_TESTE ou 'password' como padrão.
     * (SENHA_INICIAL_TESTE="" desativa a criação do usuário de teste.)
     */
    public static function prepararBanco(EntityManagerInterface $em): void
    {
        Banco::criarTabelas($em->getConnection());

        if ($em->getRepository(Usuario::class)->findOneBy([]) !== null) {
            return;
        }
        $senhaTeste = getenv('SENHA_INICIAL_TESTE');
        if ($senhaTeste === false) {
            $senhaTeste = 'password';
        }
        if ($senhaTeste !== '') {
            // EntityManager próprio: se outra requisição criar o usuário ao mesmo tempo, o
            // Doctrine fecha o EntityManager que recebeu o erro, e o principal segue utilizável.
            // Exceção à política de senha: só o usuário de teste.
            $outro = Banco::criarEntityManager();
            try {
                (new self($outro))->cadastrar('fabio', $senhaTeste, aplicarPolitica: false);
            } finally {
                $outro->getConnection()->close();
            }
        }
    }

    /**
     * Insere um usuário (só o hash é gravado, nunca a senha em texto puro).
     * Retorna false se o banco recusar por duplicidade (nome já existente); nesse caso o
     * Doctrine fecha o EntityManager, que não deve mais ser usado.
     * Levanta \InvalidArgumentException se nome ou senha estiverem fora do formato permitido
     * ou se a senha não atender à política de força (aplicarPolitica = true).
     */
    public function cadastrar(string $nome, string $senha, bool $aplicarPolitica = true): bool
    {
        $nome = Entrada::normalizarUsuario($nome);
        $senha = Entrada::normalizarSenha($senha);
        if (!Entrada::usuarioValido($nome) || !Entrada::senhaValida($senha)) {
            throw new \InvalidArgumentException('Usuário ou senha fora do formato permitido.');
        }
        if ($aplicarPolitica) {
            $motivo = Entrada::motivoSenhaFraca($senha, $nome);
            if ($motivo !== null) {
                throw new \InvalidArgumentException("Senha fraca: {$motivo}");
            }
        }

        $this->em->persist(new Usuario($nome, Senhas::hash($senha)));
        try {
            $this->em->flush();
        } catch (UniqueConstraintViolationException) {
            return false;
        }
        // Outras violações (CHECK etc.) sobem como exceção
        return true;
    }

    /**
     * Retorna o usuário ativo com esse nome, ou null.
     * O Doctrine usa parâmetros vinculados, o que evita SQL injection.
     */
    public function buscarAtivo(string $nome): ?Usuario
    {
        return $this->em->getRepository(Usuario::class)
            ->findOneBy(['nomeUsuario' => $nome, 'inativo' => false]);
    }

    /** Se os parâmetros do Argon2 mudaram, grava um hash novo. */
    private function atualizarHashSeNecessario(Usuario $usuario, string $senha): void
    {
        if (Senhas::precisaNovoHash($usuario->getSenhaUsuario())) {
            $usuario->setSenhaUsuario(Senhas::hash($senha));
            $this->em->flush();
        }
    }

    /**
     * Retorna o nome do usuário se nome e senha conferirem, senão null.
     * Sem registro (inexistente ou inativo), verifica contra o hash falso:
     * tempo e mensagem de erro ficam iguais em todos os casos.
     */
    public function autenticar(string $nome, string $senha): ?string
    {
        $usuario = $this->buscarAtivo($nome);
        $hashSalvo = $usuario !== null ? $usuario->getSenhaUsuario() : Senhas::hashFalso();
        if (!Senhas::verificar($hashSalvo, $senha) || $usuario === null) {
            return null;
        }
        $nomeUsuario = $usuario->getNomeUsuario();
        $this->atualizarHashSeNecessario($usuario, $senha);
        return $nomeUsuario;
    }

    /** Valida o formato e autentica (espera usuário e senha já normalizados). */
    public function tentarLogin(string $usuario, string $senha): ?string
    {
        if (Entrada::usuarioValido($usuario) && Entrada::senhaValida($senha)) {
            return $this->autenticar($usuario, $senha);
        }
        return null;
    }
}
