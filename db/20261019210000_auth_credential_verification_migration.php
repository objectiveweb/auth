<?php

declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class AuthCredentialVerificationMigration extends AbstractMigration
{
    public function change(): void
    {
        // The original user_credentials table already has a token column.
        // Keep identity verification separate from user.password-reset tokens.
        $this->table('user_credentials')
            ->addColumn('token_expires_at', 'datetime', ['null' => true])
            ->addColumn('verified_at', 'datetime', ['null' => true])
            ->update();
    }
}
