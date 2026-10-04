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

    public function testSessionContextIsLoadedAndRefreshedFromApplication(): void
    {
        $assignments = [1 => [5, 8]];
        $calls = 0;
        $auth = new BasicAuth([], [
            'user_context_callback' => function (array $user) use (&$assignments, &$calls): array {
                $calls++;
                $this->assertArrayNotHasKey('password', $user);
                return ['venues' => $assignments[$user['id']] ?? []];
            },
        ]);
        $auth->register('context@example.com', 'secret');
        $session = $auth->login('context@example.com', 'secret');
        $this->assertSame(['venues' => [5, 8]], $session['context']);
        $this->assertSame(1, $calls);

        $assignments[1] = [8, 13];
        $this->assertSame(['venues' => [5, 8]], $auth->user()['context']);
        $this->assertTrue($auth->revalidate());
        $this->assertSame(['venues' => [8, 13]], $auth->user()['context']);
        $this->assertSame(2, $calls);

        $auth->logout();
        $this->assertFalse($auth->check());
    }

    public function testContextCallbackReplacesUntrustedSessionContext(): void
    {
        $auth = new BasicAuth([], [
            'user_context_callback' => function (array $user): array {
                $this->assertArrayNotHasKey('context', $user);
                return ['venues' => [7]];
            },
        ]);
        $user = $auth->register('trusted@example.com', 'secret');
        $principal = $auth->get($user['id']);
        $principal['context'] = ['venues' => [999]];

        $session = $auth->establish_session($principal);
        $this->assertSame(['venues' => [7]], $session['context']);
    }

    public function testContextCallbackMustReturnArrayWithoutMutatingSession(): void
    {
        $auth = new BasicAuth([], [
            'user_context_callback' => fn (array $user): string => 'invalid',
        ]);
        $auth->register('invalid-context@example.com', 'secret');

        try {
            $auth->login('invalid-context@example.com', 'secret');
            $this->fail('Expected callback return type validation');
        } catch (\UnexpectedValueException $exception) {
            $this->assertSame('user_context_callback must return an array', $exception->getMessage());
        }

        $this->assertFalse($auth->check());
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
        $this->assertSame('alice', $result[0]['name']);
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
