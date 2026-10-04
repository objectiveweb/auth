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

        $uid = $resourceOwner->getId();
        $email = $resourceOwner->getEmail();

        // check if provider user exists
        $credential = $this->auth->get_credential($provider, $uid);

        // if provider credential does not exist, check if there's a local user with the email
        if (!$credential && !empty($email)) {
            $credential = $this->auth->get_credential('email', $email);
        }

        // This credential/email is not registered yet
        if (empty($credential['user_id'])) {
            // Check if the user is already logged in
            if ($this->auth->check()) {
                $user = $this->auth->user();

                // Add the oauth cred to the existing user
                $this->auth->update_credential($user[$this->auth->params['id']],
                    $provider,
                    $uid,
                    $resourceOwner->toArray());

            } else {
                // This is a new user, need to register
                $data = [
                    'uid' => $uid,
                    'provider' => $provider,
                    'profile' => $resourceOwner->toArray(),
                    'name' => $resourceOwner->getName(),
                    'image' => is_callable([$resourceOwner, 'getAvatar']) ? $resourceOwner->getAvatar() : $resourceOwner->getPictureUrl()
                ];

                $user = $this->auth->register($data);

                // if email is defined, also create a local email credential for it
                if (!empty($email)) {
                    // Add local credential to the user
                    $this->auth->update_credential($user[$this->auth->params['id']],
                        'email',
                        $email,
                        []);
                }
            }
        } else {
            // there is already a user for the oauth provider / local email
            $user = $this->auth->get($credential['user_id']);
            // Add account to the user
            $this->auth->update_credential($credential['user_id'],
                $provider,
                $uid,
                $resourceOwner->toArray());
        }

        // Apply the same lifecycle and session-fixation protections as
        // password authentication before storing the principal.
        return $this->auth->establish_session($user);
    }
}
