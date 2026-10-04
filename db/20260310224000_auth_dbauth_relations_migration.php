<?php

declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class AuthDbauthRelationsMigration extends AbstractMigration
{
    public function change(): void
    {

        $this->table('role', ['signed' => false])
            ->addColumn('name', 'string', ['limit' => 255])
            ->addIndex(['name'], ['unique' => true])
            ->create();

        $user_roles = $this->table('user_roles', [
            'id' => false,
            'primary_key' => ['user_id', 'role_id'],
        ])
            ->addColumn('user_id', 'integer', ['signed' => false])
            ->addColumn('role_id', 'integer', ['signed' => false])
            ->addIndex(['role_id'])
            ->addForeignKey('user_id', 'user', 'id')
            ->addForeignKey('role_id', 'role', 'id')
            ->create();

        $this->table('delegations', ['id' => false, 'primary_key' => ['user_id', 'target_user_id', 'ability']])
            ->addColumn('user_id', 'integer', ['signed' => false])
            ->addColumn('target_user_id', 'integer', ['signed' => false])
            ->addColumn('ability', 'string', ['limit' => 64])
            ->addIndex(['target_user_id'])
            ->create();

    }
}
