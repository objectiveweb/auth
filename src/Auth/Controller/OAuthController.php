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

        if (!empty($query['error'])) {
            unset($_SESSION['oauth2state']);
            throw new \Exception("Got error {$query['error']}", 500);
        } elseif (empty($query['code'])) {
            // generate authUrl first to update state
            $authUrl = $provider->getAuthorizationUrl();
            $_SESSION['oauth2state'] = $provider->getState();
            $this->redirect($authUrl);
            return;
        } elseif (
            empty($query['state'])
            || $query['state'] !== ($_SESSION['oauth2state'] ?? null)
        ) {
            unset($_SESSION['oauth2state']);
            throw new \Exception('Invalid state', 406);
        } else {
            // OAuth state is single-use. Consume it before exchanging the code
            // so a callback cannot be replayed even if the provider request fails.
            unset($_SESSION['oauth2state']);

            $token = $provider->getAccessToken('authorization_code', [
                'code' => $query['code']
            ]);
            $resourceOwner = $provider->getResourceOwner($token);

            $this->login($id, $resourceOwner);

            $this->redirect('/');
            return;
        }
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
