<?php

return [
    'paths' => [
        'migrations' => dirname(__DIR__) . '/db',
    ],
    'environments' => [
        'default_migration_table' => 'phinxlog',
        'default_environment' => 'testing',
        'testing' => [
            'adapter' => 'pgsql',
            'host' => getenv('PGHOST') ?: '127.0.0.1',
            'name' => getenv('PGDATABASE') ?: 'auth_test',
            'user' => getenv('PGUSER') ?: 'postgres',
            'pass' => getenv('PGPASSWORD') ?: 'postgres',
            'port' => (int) (getenv('PGPORT') ?: 5432),
        ],
    ],
];
