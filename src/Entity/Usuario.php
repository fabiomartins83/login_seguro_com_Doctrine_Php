<?php
declare(strict_types=1);

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * Tabela tbUsuarios. As constraints (CHECK) ficam no DDL de App\Banco::criarTabelas():
 * o banco rejeita dados inválidos mesmo se o código falhar.
 */
#[ORM\Entity]
#[ORM\Table(name: 'tbUsuarios')]
class Usuario
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private ?int $id = null;

    #[ORM\Column(name: 'nome_usuario', type: 'text', unique: true)]
    private string $nomeUsuario;

    #[ORM\Column(name: 'senha_usuario', type: 'text')]
    private string $senhaUsuario;

    #[ORM\Column(name: 'Inativo', type: 'boolean', options: ['default' => false])]
    private bool $inativo = false;

    public function __construct(string $nomeUsuario, string $senhaUsuario)
    {
        $this->nomeUsuario = $nomeUsuario;
        $this->senhaUsuario = $senhaUsuario;
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getNomeUsuario(): string
    {
        return $this->nomeUsuario;
    }

    public function getSenhaUsuario(): string
    {
        return $this->senhaUsuario;
    }

    public function setSenhaUsuario(string $hash): void
    {
        $this->senhaUsuario = $hash;
    }

    public function isInativo(): bool
    {
        return $this->inativo;
    }
}
