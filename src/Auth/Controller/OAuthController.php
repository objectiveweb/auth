<?php

namespace Objectiveweb\Auth\Controller;

use Objectiveweb\Auth;
use Objectiveweb\Auth\Middleware\RequireRole;
use Objectiveweb\Auth\UserException;
use Objectiveweb\Router\Middleware;

/**
 * Class OAuthController
 *
 * OAuth-aware Authentication Controller
 *
 * @package Objectiveweb\Auth
 */
class OAuthController extends AuthController
{
    private $providers;

    private const FLOW_KEY = 'oauth2flows';
    private const PENDING_KEY = 'oauth2pending';
    private const PENDING_TTL = 600;

    private string $pendingAccountRedirect;

    function __construct(
        \Objectiveweb\Auth $auth,
        array $providers = [],
        string $pendingAccountRedirect = '/?oauth=choose-account'
    ) {
        parent::__construct($auth);
        $this->providers = $providers;
        // Never allow an OAuth callback to redirect to an external origin.
        $this->pendingAccountRedirect = $this->normalizeLogoutRedirect($pendingAccountRedirect);
    }

    /**
     * Start a normal OAuth sign-in or receive the provider callback.
     * This route never authorizes linking an unassociated provider identity.
     */
    #[Middleware(RequireRole::class, Auth::ALL)]
    function get($id, $query)
    {
        $provider = $this->buildProvider($id);

        if (!empty($query['error'])) {
            unset($_SESSION[self::FLOW_KEY][$id]);
            throw new \Exception('OAuth provider rejected authorization', 401);
        }

        if (empty($query['code'])) {
            // Beginning a new login discards any unfinished account choice.
            unset($_SESSION[self::PENDING_KEY]);
            $this->redirect($this->startAuthorization($id, $provider, 'login'));
            return;
        }

        // The purpose of an authorization is fixed when it starts, not by
        // callback query parameters. Consume it before any network request.
        $flow = $_SESSION[self::FLOW_KEY][$id] ?? null;
        unset($_SESSION[self::FLOW_KEY][$id]);
        $state = $query['state'] ?? null;
        if (!is_array($flow)
            || !is_string($state)
            || !isset($flow['state'], $flow['created_at'], $flow['code_verifier'], $flow['intent'])
            || !is_string($flow['state'])
            || !hash_equals($flow['state'], $state)
            || !is_int($flow['created_at'])
            || $flow['created_at'] > time()
            || time() - $flow['created_at'] > 600
            || !is_string($flow['code_verifier'])
            || $flow['code_verifier'] === ''
            || !in_array($flow['intent'], ['login', 'link'], true)) {
            throw new \Exception('Invalid or expired OAuth state', 406);
        }

        // A flow started under a particular account cannot be completed by a
        // different session (including a logout followed by another login).
        $currentPrincipal = $this->auth->check()
            ? (string) $this->auth->user()[$this->auth->params['id']]
            : null;
        if (($flow['principal'] ?? null) !== $currentPrincipal) {
            throw new \Exception('OAuth session changed during authorization', 403);
        }
        if ($flow['intent'] === 'link' && !$this->auth->revalidate()) {
            throw new \Objectiveweb\Auth\AuthException('Authentication required to link account', 401);
        }

        $token = $provider->getAccessToken('authorization_code', [
            'code' => $query['code'],
            'code_verifier' => $flow['code_verifier'],
        ]);
        $resourceOwner = $provider->getResourceOwner($token);
        $result = $this->login($id, $resourceOwner, $flow['intent']);
        if (($result['status'] ?? null) === 'pending') {
            $this->redirect($this->pendingAccountRedirect);
            return;
        }
        $this->redirect('/');
    }

    /**
     * Explicitly request an account link. Only a CSRF-protected POST made by
     * the already-authenticated user can authorize a link to this account.
     * The OAuth callback itself remains GET, as required by OAuth providers.
     */
    #[Middleware(RequireRole::class, Auth::AUTHENTICATED)]
    function postLink($id, array $form = []): array
    {
        if (!$this->auth->revalidate()) {
            throw new \Objectiveweb\Auth\AuthException('Authentication required to link account', 401);
        }
        $this->assertJsonCsrfPost();
        $provider = $this->buildProvider($id);
        // Return the URL for the application's browser to navigate to.
        // A JSON POST cannot reliably initiate cross-origin navigation by
        // sending a 302 to fetch/XMLHttpRequest.
        return ['authorization_url' => $this->startAuthorization($id, $provider, 'link')];
    }

    /**
     * The application renders its account-choice page using this safe DTO.
     * Nothing here constitutes a logged-in account or a verified email.
     */
    #[Middleware(RequireRole::class, Auth::ALL)]
    function getPendingAccount(): array
    {
        $pending = $this->requirePendingAccount();
        return [
            'status' => 'account_choice_required',
            'provider' => $pending['provider'],
            'name' => $pending['name'],
            'email_hint' => $pending['email_hint'],
            'expires_at' => $pending['created_at'] + self::PENDING_TTL,
            'choices' => ['create', 'existing'],
            '_csrf' => $this->auth->management_csrf_token(),
        ];
    }

    /**
     * Explicit user choice: create an OAuth-only account.
     * This is NEVER called automatically by the OAuth callback.
     */
    #[Middleware(RequireRole::class, Auth::ALL)]
    function postCreateAccount(array $form = []): array
    {
        $this->assertJsonCsrfPost();
        $pending = $this->requirePendingAccount();
        $this->assertCanRegister();

        foreach (array_keys($form) as $field) {
            if ($field !== 'name') {
                throw new UserException("Invalid account creation field `$field`", 400);
            }
        }
        if (isset($form['name']) && (!is_string($form['name']) || trim($form['name']) === '')) {
            throw new UserException('Invalid account name', 400);
        }

        if ($this->auth->get_credential($pending['provider'], $pending['uid'])) {
            unset($_SESSION[self::PENDING_KEY]);
            throw new UserException('OAuth identity is already associated with an account', 409);
        }

        $data = [
            'uid' => $pending['uid'],
            'provider' => $pending['provider'],
            'profile' => $pending['profile'],
            'name' => isset($form['name']) ? trim($form['name']) : $pending['name'],
            'image' => $pending['image'],
        ];

        // Single-use, including in the event of a database failure.
        unset($_SESSION[self::PENDING_KEY]);
        $user = $this->auth->register($data);
        $userId = $user[$this->auth->params['id']];
        $this->auth->mark_credential_verified($userId, $pending['provider'], $pending['uid']);
        $this->auth->audit('oauth.account_created', $userId, ['provider' => $pending['provider']]);
        return ['status' => 'created', 'user' => $this->auth->establish_session($this->auth->get($userId))];
    }

    /**
     * Explicit user choice: prove ownership of an existing account using
     * its email/password and attach the independently proven OAuth subject.
     */
    #[Middleware(RequireRole::class, Auth::ALL)]
    function postExistingAccount(array $form): array
    {
        $this->assertJsonCsrfPost();
        $pending = $this->requirePendingAccount();

        foreach (array_keys($form) as $field) {
            if (!in_array($field, ['uid', 'password'], true)) {
                throw new UserException("Invalid existing-account field `$field`", 400);
            }
        }
        $uid = $form['uid'] ?? null;
        $password = $form['password'] ?? null;
        if (!is_string($uid) || trim($uid) === ''
            || !is_string($password) || $password === '') {
            throw new UserException('Email and password are required', 400);
        }

        $existing = $this->auth->get_credential($pending['provider'], $pending['uid']);
        if ($existing) {
            unset($_SESSION[self::PENDING_KEY]);
            throw new UserException('OAuth identity is already associated with an account', 409);
        }

        // Invalid passwords leave the pending identity available for retry
        // during its limited lifetime. Successful login regenerates the
        // session ID; the pending OAuth identity stays in the PHP session.
        $user = $this->auth->login(trim($uid), $password);
        $userId = $user[$this->auth->params['id']];

        // Do not allow a competing request to attach this OAuth identity to
        // a different account. Backend uniqueness constraints also apply.
        $existing = $this->auth->get_credential($pending['provider'], $pending['uid']);
        unset($_SESSION[self::PENDING_KEY]);
        if ($existing) {
            throw new UserException('OAuth identity is already associated with an account', 409);
        }
        $this->auth->update_credential(
            $userId, $pending['provider'], $pending['uid'], $pending['profile']
        );
        $this->auth->mark_credential_verified($userId, $pending['provider'], $pending['uid']);
        $this->auth->audit('credential.linked', $userId, ['provider' => $pending['provider']]);
        return ['status' => 'linked', 'user' => $this->auth->user()];
    }

    /**
     * Explicitly cancel a pending first-time OAuth sign-in.
     */
    #[Middleware(RequireRole::class, Auth::ALL)]
    function postCancelPendingAccount(): array
    {
        $this->assertJsonCsrfPost();
        $this->requirePendingAccount();
        unset($_SESSION[self::PENDING_KEY]);
        return ['status' => 'cancelled'];
    }

    private function requirePendingAccount(): array
    {
        if ($this->auth->check()) {
            throw new UserException('Finish or cancel the OAuth account choice before signing in', 409);
        }
        $pending = $_SESSION[self::PENDING_KEY] ?? null;
        if (!is_array($pending)
            || !isset($pending['provider'], $pending['uid'], $pending['created_at'])
            || !is_string($pending['provider']) || $pending['provider'] === ''
            || !is_string($pending['uid']) || $pending['uid'] === ''
            || !is_int($pending['created_at'])
            || $pending['created_at'] > time()
            || time() - $pending['created_at'] > self::PENDING_TTL
            || !array_key_exists($pending['provider'], $this->providers)) {
            unset($_SESSION[self::PENDING_KEY]);
            throw new UserException('No valid pending OAuth account choice', 410);
        }
        return $pending;
    }

    private function assertJsonCsrfPost(): void
    {
        if (strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? '')) !== 'POST') {
            throw new UserException('POST is required', 405);
        }
        $contentType = strtolower(trim(explode(';', (string) ($_SERVER['CONTENT_TYPE'] ?? ''), 2)[0]));
        if ($contentType !== 'application/json') {
            throw new UserException('Content-Type application/json is required', 415);
        }
        $provided = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
        $expected = $this->auth->management_csrf_token();
        if (!is_string($provided) || $provided === '' || !hash_equals($expected, $provided)) {
            throw new UserException('Invalid CSRF token', 403);
        }
    }

    private function buildProvider($id): object
    {
        if (!isset($this->providers[$id])) {
            throw new \Exception("Invalid provider $id", 406);
        }
        $config = $this->providers[$id];
        if (empty($config['redirectUri'])) {
            $config['redirectUri'] = $this->resolveRedirectUri();
        }
        $classname = "\\League\\OAuth2\\Client\\Provider\\" . ucfirst($id);

        return new $classname($config);
    }

    private function startAuthorization($id, object $provider, string $intent): string
    {
        $verifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $authUrl = $provider->getAuthorizationUrl([
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]);

        $providerVerifier = method_exists($provider, 'getPkceCode')
            ? $provider->getPkceCode() : null;
        if (is_string($providerVerifier) && $providerVerifier !== '') {
            $verifier = $providerVerifier;
        }
        $state = $provider->getState();
        if (!is_string($state) || $state === '') {
            throw new \RuntimeException('OAuth provider did not generate state');
        }

        $principal = $this->auth->check()
            ? (string) $this->auth->user()[$this->auth->params['id']]
            : null;
        $_SESSION[self::FLOW_KEY][$id] = [
            'state' => $state,
            'created_at' => time(),
            'code_verifier' => $verifier,
            'principal' => $principal,
            'intent' => $intent,
        ];
        return $authUrl;
    }

    protected function resolveRedirectUri(): string
    {
        $forwardedProto = trim((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''));
        if ($forwardedProto !== '') {
            $forwardedProto = trim(explode(',', $forwardedProto, 2)[0]);
        }

        $scheme = $forwardedProto !== ''
            ? $forwardedProto
            : (string) ($_SERVER['REQUEST_SCHEME'] ?? 'https');
        $host = (string) ($_SERVER['HTTP_HOST'] ?? '');
        if ($host === '') {
            throw new \RuntimeException('Cannot determine OAuth redirect URI without HTTP_HOST');
        }

        $script = str_replace('/index.php', '', (string) ($_SERVER['PHP_SELF'] ?? ''));
        $pathInfo = (string) ($_SERVER['PATH_INFO'] ?? '');

        return sprintf('%s://%s%s%s', $scheme, $host, $script, $pathInfo);
    }

    protected function redirect(string $location): void
    {
        header('Location: ' . $location);
        exit;
    }

    /**
     * Complete OAuth sign-in or an explicitly initiated account-link flow.
     * A normal sign-in is never permission to attach an external identity.
     */
    private function login($provider, $resourceOwner, string $intent = 'login')
    {
        $uid = (string) $resourceOwner->getId();
        if ($uid === '') {
            throw new \Objectiveweb\Auth\AuthException('Invalid provider identity', 401);
        }
        if (!in_array($intent, ['login', 'link'], true)) {
            throw new UserException('Invalid OAuth intent', 400);
        }

        $credential = $this->auth->get_credential($provider, $uid);
        $sessionUser = $this->auth->check() ? $this->auth->user() : null;
        $idField = $this->auth->params['id'];
        $profile = $resourceOwner->toArray();

        if ($intent === 'link') {
            if ($sessionUser === null || !$this->auth->revalidate()) {
                throw new \Objectiveweb\Auth\AuthException('Authentication required to link account', 401);
            }
            $sessionUser = $this->auth->user();
            $userId = $sessionUser[$idField];

            if ($credential && $credential['user_id'] != $userId) {
                throw new UserException('Credential belongs to another account', 409);
            }
            $this->auth->update_credential($userId, $provider, $uid, $profile);
            $this->auth->mark_credential_verified($userId, $provider, $uid);
            $this->auth->audit('credential.linked', $userId, ['provider' => $provider]);
            return $this->auth->establish_session($this->auth->get($userId));
        }

        // This is sign-in only. Existing verified credentials authenticate
        // their owner, but unknown or unverified identities cannot be attached
        // to an unrelated session.
        if ($credential) {
            $userId = $credential['user_id'];
            if ($sessionUser !== null && $sessionUser[$idField] != $userId) {
                throw new UserException('Credential belongs to another account', 409);
            }
            if (empty($credential['verified_at'])) {
                throw new \Objectiveweb\Auth\AuthException(
                    'OAuth credential requires explicit account linking', 403
                );
            }
            $user = $this->auth->get($userId);
            $this->auth->update_credential($userId, $provider, $uid, $profile);
        } else {
            if ($sessionUser !== null) {
                throw new UserException('Use explicit OAuth account linking', 409);
            }
            // Provider authentication proves an external identity, but the
            // user must choose whether to create or link a local account.
            // The OAuth callback must not create any account by itself.
            $name = is_callable([$resourceOwner, 'getName'])
                ? $resourceOwner->getName() : null;
            $image = is_callable([$resourceOwner, 'getAvatar'])
                ? $resourceOwner->getAvatar()
                : (is_callable([$resourceOwner, 'getPictureUrl'])
                    ? $resourceOwner->getPictureUrl() : null);
            $email = is_callable([$resourceOwner, 'getEmail'])
                ? $resourceOwner->getEmail() : null;
            $_SESSION[self::PENDING_KEY] = [
                'provider' => $provider,
                'uid' => $uid,
                'profile' => $profile,
                'name' => is_string($name) ? $name : null,
                'image' => is_string($image) ? $image : null,
                'email_hint' => is_string($email) ? $email : null,
                'created_at' => time(),
            ];
            return ['status' => 'pending'];
        }

        return $this->auth->establish_session($user);
    }
}
