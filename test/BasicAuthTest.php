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

    public function testPasswordLoginPreservesExistingCredentialProfile(): void
    {
        $profile = ['source' => 'import', 'attributes' => ['locale' => 'pt-BR']];
        $user = $this->auth->register('profile@example.com', 'secret', [
            'profile' => $profile,
        ]);
        $original = $this->auth->get_credential('local', 'profile@example.com');
        $this->assertSame(json_encode($profile), $original['profile']);
        $this->assertNull($original['last_login']);

        $this->auth->login('profile@example.com', 'secret');
        $afterLogin = $this->auth->get_credential('local', 'profile@example.com');
        $this->assertSame($original['profile'], $afterLogin['profile']);
        $this->assertSame($original['created'], $afterLogin['created']);
        $this->assertNotNull($afterLogin['last_login']);

        $this->auth->logout();
        $this->auth->login('profile@example.com', 'secret');
        $this->assertSame($original['profile'], $this->auth->get_credential('local', 'profile@example.com')['profile']);

        $listed = $this->auth->get_credentials($user['id']);
        $this->assertCount(1, $listed);
        $this->assertSame($profile, $listed[0]['profile']);
    }

    public function testNullCredentialProfileDoesNotReplaceMetadataButNonNullDoes(): void
    {
        $user = $this->auth->register('update-profile@example.com', 'secret');
        $this->assertNull($this->auth->get_credential('local', 'update-profile@example.com')['profile']);

        $firstProfile = ['source' => 'google', 'avatar' => 'example.png'];
        $this->auth->update_credential($user['id'], 'local', 'update-profile@example.com', $firstProfile);
        $this->assertSame(
            json_encode($firstProfile),
            $this->auth->get_credential('local', 'update-profile@example.com')['profile']
        );

        $this->auth->update_credential($user['id'], 'local', 'update-profile@example.com', null);
        $this->assertSame(
            json_encode($firstProfile),
            $this->auth->get_credential('local', 'update-profile@example.com')['profile']
        );

        $replacement = ['source' => 'manual'];
        $this->auth->update_credential($user['id'], 'local', 'update-profile@example.com', $replacement);
        $this->assertSame(
            json_encode($replacement),
            $this->auth->get_credential('local', 'update-profile@example.com')['profile']
        );
        $this->assertSame($replacement, $this->auth->get_credentials($user['id'])[0]['profile']);
    }

    public function testLoginInvalidPassword(): void
    {
        $this->expectException(AuthException::class);
        $this->auth->login('alice@example.com', 'wrong');
    }

    public function testPasswordLoginFailuresHaveIdenticalPublicErrors(): void
    {
        $auth = new BasicAuth([], ['disabled_at' => 'disabled_at']);
        $auth->register('known@example.com', 'secret');
        $auth->register('disabled@example.com', 'secret', [
            'disabled_at' => '2026-01-01 00:00:00',
        ]);
        $auth->register('passwordless@example.com', null);

        foreach ([
            ['absent@example.com', 'secret'],
            ['known@example.com', 'wrong'],
            ['disabled@example.com', 'secret'],
            ['passwordless@example.com', 'anything'],
        ] as [$uid, $password]) {
            try {
                $auth->login($uid, $password);
                $this->fail('Invalid login unexpectedly succeeded');
            } catch (AuthException $e) {
                $this->assertSame(401, $e->getCode());
                $this->assertSame('Invalid credentials', $e->getMessage());
            }
        }
    }

    public function testRegisterAndGetCredential(): void
    {
        $user = $this->auth->register('bob@example.com', 'pass123', ['name' => 'Bob']);
        $credential = $this->auth->get_credential('local', 'bob@example.com');

        $this->assertSame('Bob', $user['name']);
        $this->assertSame($user['id'], $credential['user_id']);
    }

    public function testPasswdInvalidatesOutstandingResetToken(): void
    {
        $credential = $this->auth->get_credential('local', 'alice@example.com');
        $userId = $credential['user_id'];
        $token = $this->auth->update_token($userId);
        $this->assertNotNull($this->auth->get($userId)['token']);
        $this->assertNotNull($this->auth->get($userId)['token_expires_at']);

        $this->assertTrue($this->auth->passwd($userId, 'changed-secret'));
        $updated = $this->auth->get($userId);
        $this->assertTrue(password_verify('changed-secret', $updated['password']));
        $this->assertNull($updated['token']);
        $this->assertNull($updated['token_expires_at']);

        try {
            $this->auth->passwd_reset($token, 'stale-reset-secret');
            $this->fail('Password reset token survived a direct password change');
        } catch (UserException $exception) {
            $this->assertSame(404, $exception->getCode());
        }

        $this->assertSame($userId, $this->auth->login('alice@example.com', 'changed-secret')['id']);
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

        $this->expectException(AuthException::class);
        $this->expectExceptionCode(401);
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
                ['uid', 'provider', 'profile', 'verified_at', 'last_login', 'created'],
                array_keys($credential)
            );
            $this->assertArrayHasKey('last_login', $credential);
            $this->assertNotNull($credential['created']);
        }
    }

    public function testCredentialVerificationIsScopedSingleUseAndHashed(): void
    {
        $user = $this->auth->register('token-user@example.com', 'secret');
        $this->auth->create_credential($user['id'], 'email', 'token-user@example.com');
        $this->auth->create_credential($user['id'], 'phone', '+5511999999999');

        $emailToken = $this->auth->issue_credential_token($user['id'], 'email', 'token-user@example.com');
        $phoneToken = $this->auth->issue_credential_token($user['id'], 'phone', '+5511999999999');

        $credential = $this->auth->get_credential('email', 'token-user@example.com');
        $this->assertSame(hash('sha256', $emailToken), $credential['token']);
        $this->assertNotSame($emailToken, $credential['token']);
        $this->assertNotEmpty($credential['token_expires_at']);
        $this->assertFalse($this->auth->verify_credential_token('phone', '+5511999999999', $emailToken));
        $this->assertFalse($this->auth->verify_credential_token('email', 'token-user@example.com', $phoneToken));
        $this->assertFalse($this->auth->verify_credential_token('email', 'token-user@example.com', 'bad-token'));

        $public = $this->auth->get_credentials($user['id']);
        foreach ($public as $item) {
            $this->assertArrayNotHasKey('token', $item);
            $this->assertArrayNotHasKey('token_expires_at', $item);
        }

        $this->assertTrue($this->auth->verify_credential_token('email', 'token-user@example.com', $emailToken));
        $this->assertFalse($this->auth->verify_credential_token('email', 'token-user@example.com', $emailToken));
        $this->assertNotEmpty($this->auth->get_credential('email', 'token-user@example.com')['verified_at']);
        $this->assertNull($this->auth->get_credential('phone', '+5511999999999')['verified_at'] ?? null);
        $this->assertTrue($this->auth->verify_credential_token('phone', '+5511999999999', $phoneToken));

        // Metadata refresh keeps verification, but a changed UID requires proof again.
        $this->auth->update_credential($user['id'], 'email', 'token-user@example.com', ['source' => 'profile']);
        $this->assertNotEmpty($this->auth->get_credential('email', 'token-user@example.com')['verified_at']);
        $renamed = $this->auth->rename_credential(
            $user['id'], 'email', 'token-user@example.com', 'email', 'renamed@example.com'
        );
        $this->assertNull($renamed['verified_at']);
    }

    public function testExternalOAuthCredentialCannotBeVerifiedWithContactToken(): void
    {
        $this->auth->create_credential(1, 'google', 'google-id');
        $this->assertFalse($this->auth->verify_credential_token('google', 'google-id', 'anything'));
        $this->expectException(UserException::class);
        $this->expectExceptionCode(400);
        $this->auth->issue_credential_token(1, 'google', 'google-id');
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
    public function testGeneratedIdsAreNotReusedAfterDeletion(): void
    {
        $first = $this->auth->register('first-id@example.com', 'secret');
        $this->assertTrue($this->auth->delete($first['id']));
        $second = $this->auth->register('second-id@example.com', 'secret');

        $this->assertGreaterThan($first['id'], $second['id']);
    }

    public function testExplicitFixtureIdAdvancesIdCounter(): void
    {
        $auth = new BasicAuth([
            'fixture@example.com' => [
                'id' => 50,
                'name' => 'Fixture',
                'password' => 'secret',
            ],
        ]);

        $this->assertSame(50, $auth->get(50)['id']);
        $created = $auth->register('after-fixture@example.com', 'secret');
        $this->assertSame(51, $created['id']);
    }

    public function testHashLookingFixturePasswordIsTreatedAsPlaintext(): void
    {
        $input = password_hash('actual-password', PASSWORD_BCRYPT);
        $user = $this->auth->register('hash-fixture@example.com', $input);
        $stored = $this->auth->get($user['id']);

        $this->assertTrue(password_verify($input, $stored['password']));
        $this->assertSame($user['id'], $this->auth->login('hash-fixture@example.com', $input)['id']);
    }

}
