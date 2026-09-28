<?php

$pdo = new PDO(
    sprintf(
        'pgsql:host=%s;port=%s;dbname=%s',
        getenv('PGHOST') ?: '127.0.0.1',
        getenv('PGPORT') ?: '5432',
        getenv('PGDATABASE') ?: 'auth_test'
    ),
    getenv('PGUSER') ?: 'postgres',
    getenv('PGPASSWORD') ?: 'postgres',
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
);

$expectedColumns = [
    'user' => [
        'id',
        'uuid',
        'password',
        'name',
        'image',
        'token',
        'token_expires_at',
        'disabled_at',
        'created',
    ],
    'user_credentials' => [
        'uid',
        'provider',
        'user_id',
        'profile',
        'token',
        'last_login',
        'created',
    ],
    'role' => ['id', 'name'],
    'user_roles' => ['user_id', 'role_id'],
];

foreach ($expectedColumns as $table => $columns) {
    $statement = $pdo->prepare(
        'SELECT column_name
           FROM information_schema.columns
          WHERE table_schema = current_schema()
            AND table_name = :table'
    );
    $statement->execute(['table' => $table]);
    $actual = $statement->fetchAll(PDO::FETCH_COLUMN);

    foreach ($columns as $column) {
        if (!in_array($column, $actual, true)) {
            fwrite(STDERR, "Missing column {$table}.{$column}\n");
            exit(1);
        }
    }
}

$uuidIndex = $pdo->query(
    "SELECT indexdef
       FROM pg_indexes
      WHERE schemaname = current_schema()
        AND tablename = 'user'
        AND indexdef ILIKE '%UNIQUE%'
        AND indexdef ILIKE '%uuid%'"
)->fetchColumn();

if ($uuidIndex === false) {
    fwrite(STDERR, "Missing unique index for user.uuid\n");
    exit(1);
}

echo "Migration schema matches DBAuth defaults.\n";
