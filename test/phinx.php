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
        // Separate environment shares the package migrations with PostgreSQL.
        // Provide MYSQL_* variables in the dedicated MySQL CI job.
        'mysql_testing' => [
            'adapter' => 'mysql',
            'host' => getenv('MYSQL_HOST') ?: '127.0.0.1',
            'name' => getenv('MYSQL_DATABASE') ?: 'auth_test',
            'user' => getenv('MYSQL_USER') ?: 'auth_user',
            'pass' => getenv('MYSQL_PASSWORD') ?: '',
            'port' => (int) (getenv('MYSQL_PORT') ?: 3306),
            'charset' => 'utf8mb4',
        ],
    ],
];
