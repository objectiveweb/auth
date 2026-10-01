<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Objectiveweb\Auth\AuthException;
use Objectiveweb\Auth\BasicAuth;
use Objectiveweb\Auth\UserException;
use PHPUnit\Framework\TestCase;

class BasicAuthTest extends TestCase
{
    private BasicAuth $auth;

    protected function setUp(): void
    {
        $_SESSION = [];

        $this->auth = new BasicAuth(
            [
                'alice@example.com' => 'secret',
            ],
            [
                'token' => 'token',
            ]
        );
    }

    public function testLoginSuccessAndSessionData(): void
    {
        $user = $this->auth->login('alice@example.com', 'secret');

        $this->assertSame(1, $user['id']);
        $this->assertSame('alice@example.com', $user['uid']);
        $this->assertTrue($this->auth->check());
        $this->assertArrayNotHasKey('password', $user);
    }

    public function testLoginInvalidPassword(): void
    {
        $this->expectException(AuthException::class);
        $this->auth->login('alice@example.com', 'wrong');
    }

    public function testRegisterAndGetCredential(): void
    {
        $user = $this->auth->register('bob@example.com', 'pass123', ['name' => 'Bob']);
        $credential = $this->auth->get_credential('local', 'bob@example.com');

        $this->assertSame('Bob', $user['name']);
        $this->assertSame($user['id'], $credential['user_id']);
    }

    public function testPasswordResetFlow(): void
    {
        $credential = $this->auth->get_credential('local', 'alice@example.com');
        $token = $this->auth->update_token($credential['user_id']);

        $this->auth->passwd_reset($token, 'new-secret');
        $user = $this->auth->login('alice@example.com', 'new-secret');

        $this->assertSame('alice@example.com', $user['uid']);
    }

    public function testDeleteUserRemovesCredential(): void
    {
        $credential = $this->auth->get_credential('local', 'alice@example.com');
        $this->auth->delete($credential['user_id']);

        $this->expectException(UserException::class);
        $this->auth->login('alice@example.com', 'secret');
    }

    public function testLoginWithEmailProviderWhenConfiguredInLoginProviders(): void
    {
        $auth = new BasicAuth([], [
            'token' => 'token',
            'login_providers' => ['email', 'local'],
        ]);

        $auth->register('alice@example.com', 'secret', ['provider' => 'email']);
        $user = $auth->login('alice@example.com', 'secret');

        $this->assertSame('alice@example.com', $user['uid']);
    }

    public function testGetCredentialsReturnsOnlyExpectedFields(): void
    {
        $user = $this->auth->register('bob@example.com', 'secret', ['provider' => 'email']);
        $this->auth->update_credential($user['id'], 'phone', '+5511999999999', ['country' => 'BR']);

        $credentials = $this->auth->get_credentials($user['id']);
        $this->assertCount(2, $credentials);

        foreach ($credentials as $credential) {
            $this->assertSame(
                ['uid', 'provider', 'profile', 'last_login', 'created'],
                array_keys($credential)
            );
            $this->assertArrayHasKey('last_login', $credential);
            $this->assertNotNull($credential['created']);
        }
    }

    public function testRenameCredentialNormalizesTargetAndPreservesMetadata(): void
    {
        $user = $this->auth->register('rename@example.com', 'secret');
        $created = $this->auth->create_credential(
            $user['id'],
            'phone',
            '+5511999999999',
            ['country' => 'BR']
        );

        $renamed = $this->auth->rename_credential(
            $user['id'],
            'phone',
            '+5511999999999',
            ' sms ',
            ' +5511888888888 '
        );

        $this->assertSame('sms', $renamed['provider']);
        $this->assertSame('+5511888888888', $renamed['uid']);
        $this->assertSame($created['created'], $renamed['created']);
        $this->assertSame($created['last_login'], $renamed['last_login']);
        $this->assertFalse($this->auth->get_credential('phone', '+5511999999999'));
    }

    public function testRenameCredentialRejectsDuplicateAfterNormalization(): void
    {
        $user = $this->auth->register('duplicate-rename@example.com', 'secret');
        $this->auth->create_credential($user['id'], 'phone', '+5511999999999');
        $this->auth->create_credential($user['id'], 'sms', '+5511888888888');

        $this->expectException(UserException::class);
        $this->expectExceptionCode(409);

        $this->auth->rename_credential(
            $user['id'],
            'phone',
            '+5511999999999',
            ' sms ',
            ' +5511888888888 '
        );
    }

    public function testDeletionGuardCallbackPreventsDeletion(): void
    {
        $auth = new BasicAuth(
            ['guarded@example.com' => 'secret'],
            [
                'token' => 'token',
                'deletion_guard_callback' => fn ($userId): string => 'User has application history',
            ]
        );
        $credential = $auth->get_credential('local', 'guarded@example.com');

        try {
            $auth->delete($credential['user_id']);
            $this->fail('Expected deletion guard to reject deletion');
        } catch (UserException $exception) {
            $this->assertSame(409, $exception->getCode());
            $this->assertSame('User has application history', $exception->getMessage());
        }

        $this->assertSame(
            $credential['user_id'],
            $auth->get($credential['user_id'])['id']
        );
        $this->assertNotFalse($auth->get_credential('local', 'guarded@example.com'));
    }

    public function testManagedRelationValidationRunsBeforeMutation(): void
    {
        $validated = null;
        $auth = new BasicAuth([], [
            'token' => 'token',
            'managed_relations' => [
                'items' => [
                    'validate_callback' => function (array $values) use (&$validated): void {
                        $validated = $values;
                        if (in_array(99, $values, true)) {
                            throw new UserException('Invalid item', 400);
                        }
                    },
                ],
            ],
        ]);

        $user = $auth->register('relations@example.com', 'secret');
        $relations = $auth->sync_managed_relations($user['id'], [
            'items' => [3, 3, 8],
        ]);

        $this->assertSame([3, 8], $validated);
        $this->assertSame([3, 8], $relations['items']);

        try {
            $auth->sync_managed_relations($user['id'], ['items' => [99]]);
            $this->fail('Expected managed relation validation to reject the update');
        } catch (UserException $exception) {
            $this->assertSame(400, $exception->getCode());
        }

        $this->assertSame([3, 8], $auth->get_managed_relations($user['id'])['items']);
    }

    public function testQueryReturnsCollectionWithPaginationMetadata(): void
    {
        $this->auth->register('bob@example.com', 'secret', ['name' => 'Bob']);
        $this->auth->register('carol@example.com', 'secret', ['name' => 'Carol']);

        $result = $this->auth->query([
            'page' => 1,
            'size' => 2,
            'sort' => 'name ASC',
        ]);

        $this->assertInstanceOf(\Objectiveweb\DB\Collection::class, $result);
        $this->assertSame(3, $result->total());
        $this->assertSame('items 2-2/3', $result->contentRange());
        $this->assertCount(1, $result);
        $this->assertSame('Carol', $result[0]['name']);
    }

    public function testGetUsersByRoleReturnsMatchingUsers(): void
    {
        $admin = $this->auth->register('admin@example.com', 'secret', [
            'roles' => ['admin'],
        ]);
        $this->auth->register('viewer@example.com', 'secret', [
            'roles' => ['viewer'],
        ]);

        $admins = $this->auth->get_users_by_role('admin');

        $this->assertCount(1, $admins);
        $this->assertSame($admin['id'], $admins[0]['id']);
        $this->assertSame(['admin'], $admins[0]['roles']);
    }
}
