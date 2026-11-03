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

    function __construct(\Objectiveweb\Auth $auth, array $providers = [])
    {
        parent::__construct($auth);
        $this->providers = $providers;

    }

    /**
     * Execute login on oauth provider
     */
    #[Middleware(RequireRole::class, Auth::ALL)]
    function get($id, $query)
    {
        if (!isset($this->providers[$id])) {
            throw new \Exception("Invalid provider $id", 406);
        }

        $config = $this->providers[$id];

        if (empty($config['redirectUri'])) {
            $config['redirectUri'] = $this->resolveRedirectUri();
        }

        $classname = "\\League\\OAuth2\\Client\\Provider\\" . ucfirst($id);

        /** @var \League\OAuth2\Client\Provider\GenericProvider $provider */
        $provider = new $classname($config);

        $stateKey = 'oauth2flows';
        if (!empty($query['error'])) {
            unset($_SESSION[$stateKey][$id]);
            throw new \Exception('OAuth provider rejected authorization', 401);
        }

        if (empty($query['code'])) {
            // Generate a fresh PKCE S256 verifier for every authorization.
            $verifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
            $challenge = rtrim(
                strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'),
                '='
            );
            $authUrl = $provider->getAuthorizationUrl([
                'code_challenge' => $challenge,
                'code_challenge_method' => 'S256',
            ]);

            // OAuth clients that implement PKCE themselves may override the
            // supplied challenge; use their generated verifier when present.
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
            $_SESSION[$stateKey][$id] = [
                'state' => $state,
                'created_at' => time(),
                'code_verifier' => $verifier,
                'principal' => $principal,
            ];
            $this->redirect($authUrl);
            return;
        }

        // Keep the state, PKCE verifier and initiating principal bound to
        // this provider. Never allow callbacks to reuse a different provider's
        // state or silently link to a different session principal.
        $flow = $_SESSION[$stateKey][$id] ?? null;
        unset($_SESSION[$stateKey][$id]);
        $state = $query['state'] ?? null;
        if (!is_array($flow)
            || !is_string($state)
            || !isset($flow['state'], $flow['created_at'], $flow['code_verifier'])
            || !is_string($flow['state'])
            || !hash_equals($flow['state'], $state)
            || !is_int($flow['created_at'])
            || $flow['created_at'] > time()
            || time() - $flow['created_at'] > 600
            || !is_string($flow['code_verifier'])
            || $flow['code_verifier'] === '') {
            throw new \Exception('Invalid or expired OAuth state', 406);
        }
        $currentPrincipal = $this->auth->check()
            ? (string) $this->auth->user()[$this->auth->params['id']]
            : null;
        if (($flow['principal'] ?? null) !== $currentPrincipal) {
            throw new \Exception('OAuth session changed during authorization', 403);
        }

        // Consume state before exchanging the authorization code. A callback
        // cannot be replayed, even if token exchange or login fails.
        $token = $provider->getAccessToken('authorization_code', [
            'code' => $query['code'],
            'code_verifier' => $flow['code_verifier'],
        ]);
        $resourceOwner = $provider->getResourceOwner($token);
        $this->login($id, $resourceOwner);
        $this->redirect('/');
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
     * Login with oauth2 credentials. Create a new user if it doesn't exist
     * @param $provider
     * @param \League\OAuth2\Client\Provider\ResourceOwnerInterface $resourceOwner
     * @return mixed
     */
    private function login($provider, $resourceOwner)
    {
        // The OAuth provider has authenticated this provider-specific subject
        // through its code/token exchange. An email in the profile is NOT proof
        // that this subject owns any existing local account.
        $uid = (string) $resourceOwner->getId();
        if ($uid === '') {
            throw new \Objectiveweb\Auth\AuthException('Invalid provider identity', 401);
        }

        $credential = $this->auth->get_credential($provider, $uid);
        $sessionUser = $this->auth->check() ? $this->auth->user() : null;
        $idField = $this->auth->params['id'];
        $profile = $resourceOwner->toArray();

        if ($credential) {
            $userId = $credential['user_id'];
            if ($sessionUser !== null && $sessionUser[$idField] != $userId) {
                throw new UserException('Credential belongs to another account', 409);
            }

            // Older or administratively created OAuth mappings without proof
            // must never authorize an anonymous sign-in. A signed-in owner
            // can confirm that pending link by authenticating this provider.
            if (empty($credential['verified_at'])) {
                if ($sessionUser === null || $sessionUser[$idField] != $userId) {
                    throw new \Objectiveweb\Auth\AuthException(
                        'OAuth credential requires verified account linking', 403
                    );
                }
                $this->auth->mark_credential_verified($userId, $provider, $uid);
            }

            $user = $this->auth->get($userId);
            $this->auth->update_credential($userId, $provider, $uid, $profile);
        } elseif ($sessionUser !== null) {
            // Explicitly signed-in users can link a new provider after OAuth
            // authentication proves control of the provider-specific identity.
            $user = $this->auth->get($sessionUser[$idField]);
            $this->auth->update_credential($user[$idField], $provider, $uid, $profile);
            $this->auth->mark_credential_verified($user[$idField], $provider, $uid);
        } else {
            // A matching email does not grant ownership of any other account.
            // The provider identity becomes a new, independently verified
            // credential. Email credentials require their own proof token.
            $data = [
                'uid' => $uid,
                'provider' => $provider,
                'profile' => $profile,
                'name' => $resourceOwner->getName(),
                'image' => is_callable([$resourceOwner, 'getAvatar'])
                    ? $resourceOwner->getAvatar()
                    : $resourceOwner->getPictureUrl(),
            ];
            $user = $this->auth->register($data);
            $this->auth->mark_credential_verified($user[$idField], $provider, $uid);
        }

        return $this->auth->establish_session($user);
    }
}
