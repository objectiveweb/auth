<?php

declare(strict_types=1);

// Verify the real schema produced by the bundled Phinx migrations on MySQL 8.
// Use information_schema rather than SQLite/PostgreSQL-specific introspection.
$database = getenv('MYSQL_DATABASE') ?: 'auth_test';
$pdo = new PDO(
    sprintf(
        'mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
        getenv('MYSQL_HOST') ?: '127.0.0.1',
        getenv('MYSQL_PORT') ?: '3306',
        $database
    ),
    getenv('MYSQL_USER') ?: 'auth_user',
    getenv('MYSQL_PASSWORD') ?: '',
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
);

$expectedColumns = [
    'user' => [
        'id', 'uuid', 'password', 'name', 'image', 'token',
        'token_expires_at', 'disabled_at', 'created',
    ],
    'user_credentials' => [
        'uid', 'provider', 'user_id', 'profile', 'token',
        'token_expires_at', 'verified_at', 'last_login', 'created',
    ],
    'role' => ['id', 'name'],
    'user_roles' => ['user_id', 'role_id'],
    'delegations' => ['user_id', 'target_user_id', 'ability'],
];

$assert = static function (bool $condition, string $message): void {
    if (!$condition) {
        throw new RuntimeException($message);
    }
};

$columnsStmt = $pdo->prepare(
    'SELECT COLUMN_NAME FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = :db AND TABLE_NAME = :table'
);
$engineStmt = $pdo->prepare(
    'SELECT ENGINE FROM information_schema.TABLES
     WHERE TABLE_SCHEMA = :db AND TABLE_NAME = :table'
);

foreach ($expectedColumns as $table => $columns) {
    $columnsStmt->execute(['db' => $database, 'table' => $table]);
    $actual = $columnsStmt->fetchAll(PDO::FETCH_COLUMN);
    foreach ($columns as $column) {
        $assert(in_array($column, $actual, true), "Missing MySQL column {$table}.{$column}");
    }
    $engineStmt->execute(['db' => $database, 'table' => $table]);
    $assert($engineStmt->fetchColumn() === 'InnoDB', "Expected InnoDB table {$table}");
}

// OAuth provider names and subject IDs must use exact comparisons on MySQL,
// regardless of the database/table's default case-insensitive collation.
$collationStmt = $pdo->prepare(
    'SELECT COLUMN_NAME, COLLATION_NAME FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = :db AND TABLE_NAME = :table'
);
$collationStmt->execute(['db' => $database, 'table' => 'user_credentials']);
$collations = $collationStmt->fetchAll(PDO::FETCH_KEY_PAIR);
foreach (['uid', 'provider'] as $column) {
    $assert(
        ($collations[$column] ?? null) === 'utf8mb4_0900_bin',
        "MySQL credential identity column {$column} must use utf8mb4_0900_bin"
    );
}

// Check indexes by indexed column, including whether they enforce uniqueness.
$indexStmt = $pdo->prepare(
    'SELECT INDEX_NAME, COLUMN_NAME, NON_UNIQUE, SEQ_IN_INDEX
     FROM information_schema.STATISTICS
     WHERE TABLE_SCHEMA = :db AND TABLE_NAME = :table
     ORDER BY INDEX_NAME, SEQ_IN_INDEX'
);
$requiredIndexes = [
    'user' => [
        ['uuid', true],
        ['token', false],
    ],
    'user_credentials' => [
        ['uid', true],
        ['provider', true],
    ],
    'role' => [['name', true]],
    'user_roles' => [
        ['user_id', true],
        ['role_id', false],
    ],
];
foreach ($requiredIndexes as $table => $requirements) {
    $indexStmt->execute(['db' => $database, 'table' => $table]);
    $indexes = $indexStmt->fetchAll(PDO::FETCH_ASSOC);
    foreach ($requirements as [$column, $unique]) {
        $found = false;
        foreach ($indexes as $index) {
            if ($index['COLUMN_NAME'] === $column
                && (!$unique || (int) $index['NON_UNIQUE'] === 0)) {
                $found = true;
                break;
            }
        }
        $assert($found, "Missing MySQL index for {$table}.{$column}");
    }
}

$foreignKeyStmt = $pdo->prepare(
    'SELECT COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME
     FROM information_schema.KEY_COLUMN_USAGE
     WHERE TABLE_SCHEMA = :db AND TABLE_NAME = :table
       AND REFERENCED_TABLE_NAME IS NOT NULL'
);
$foreignKeys = [
    'user_credentials' => ['user_id' => ['user', 'id']],
    'user_roles' => [
        'user_id' => ['user', 'id'],
        'role_id' => ['role', 'id'],
    ],
];
foreach ($foreignKeys as $table => $requirements) {
    $foreignKeyStmt->execute(['db' => $database, 'table' => $table]);
    $actual = $foreignKeyStmt->fetchAll(PDO::FETCH_ASSOC);
    foreach ($requirements as $column => [$referencedTable, $referencedColumn]) {
        $found = false;
        foreach ($actual as $key) {
            if ($key['COLUMN_NAME'] === $column
                && $key['REFERENCED_TABLE_NAME'] === $referencedTable
                && $key['REFERENCED_COLUMN_NAME'] === $referencedColumn) {
                $found = true;
                break;
            }
        }
        $assert($found, "Missing MySQL FK {$table}.{$column} -> {$referencedTable}.{$referencedColumn}");
    }
}

echo "MySQL 8 migration schema, indexes and foreign keys verified.\n";
