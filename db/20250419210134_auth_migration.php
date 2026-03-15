<?php


use Phinx\Migration\AbstractMigration;
use Phinx\Util\Literal;

class AuthMigration extends AbstractMigration
{
    /**
     * Change Method.
     *
     * Write your reversible migrations using this method.
     *
     * More information on writing migrations is available here:
     * http://docs.phinx.org/en/latest/migrations.html#the-abstractmigration-class
     *
     * The following commands can be used in this method and Phinx will
     * automatically reverse them when rolling back:
     *
     *    createTable
     *    renameTable
     *    addColumn
     *    renameColumn
     *    addIndex
     *    addForeignKey
     *
     * Remember to call "create()" or "update()" and NOT "save()" when working
     * with the Table class.
     */
    public function change()
    {

        $user = $this->table('user', ['signed' => false]);
        $user
            ->addColumn('password', 'string', ['limit' => 60, 'null' => true])
            ->addColumn('name', 'string', ['limit' => 255, 'null' => true])
            ->addColumn('image', 'string', ['limit' => 255, 'null' => true])
            ->addColumn('token', 'string', ['limit' => 255, 'null' => true])
            ->addColumn('token_expires_at', 'datetime', ['null' => true])
            ->addColumn('created', 'datetime', [ 'default' => Literal::from('now()')])
            ->create();

        $user_credentials = $this->table('user_credentials', [
            'id' => false,
            'primary_key' => ['uid', 'provider']
        ]);
        $user_credentials
            ->addColumn('uid', 'string', ['limit' => 255])
            ->addColumn('provider', 'string', ['limit' => 32])
            ->addColumn('user_id', 'integer', ['signed' => false])
            ->addColumn('profile', 'text', ['null'=> true])
            ->addColumn('token', 'string', ['limit' => 255, 'null' => true])
            ->addColumn('last_login', 'datetime', ['null' => true])
            ->addColumn('created', 'datetime', [ 'default' => Literal::from('now()')])
            ->addForeignKey('user_id', $user->getTable())
            ->create();
    }
}
