<?php

namespace Objectiveweb\Auth\Controller;

use Objectiveweb\Auth;
use Objectiveweb\Auth\UserException;

use Objectiveweb\Auth\Attributes\RequireRole;

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
    #[RequireRole(Auth::ALL)]
    function get($id, $query)
    {
        if (!isset($this->providers[$id])) {
            throw new \Exception("Invalid provider $id", 406);
        }

        $config = $this->providers[$id];

        $config['redirectUri'] = sprintf("%s://%s%s%s",
            (empty($_SERVER['HTTP_X_FORWARDED_PROTO']) ? $_SERVER['REQUEST_SCHEME'] : $_SERVER['HTTP_X_FORWARDED_PROTO']),
            $_SERVER['HTTP_HOST'],
            str_replace("/index.php", "", $_SERVER['PHP_SELF']),
            $_SERVER['PATH_INFO']);

        $classname = "\\League\\OAuth2\\Client\\Provider\\" . ucfirst($id);

        /** @var \League\OAuth2\Client\Provider\GenericProvider $provider */
        $provider = new $classname($config);

        if (!empty($query['error'])) {
            throw new \Exception("Got error {$query['error']}", 500);
        } elseif (empty($query['code'])) {
            // generate authUrl first to update state
            $authUrl = $provider->getAuthorizationUrl();
            $_SESSION['oauth2state'] = $provider->getState();
            error_log('oauth2state ' . $_SESSION['oauth2state']);
            header('Location: ' . $authUrl);
            exit;
        } elseif (empty($query['state']) || $query['state'] !== $_SESSION['oauth2state']) {
            unset($_SESSION['oauth2state']);
            throw new \Exception('Invalid state', 406);
        } else {
            $token = $provider->getAccessToken('authorization_code', [
                'code' => $query['code']
            ]);
            $resourceOwner = $provider->getResourceOwner($token);

            $this->login($id, $resourceOwner);

            header("Location: /");
            exit();
        }
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
            $credential = $this->auth->get_credential('local', $email);
        }

        // This credential/email is not registered yet
        if (empty($credential['user_id'])) {
            // Check if the user is already logged in
            if ($this->auth->check()) {
                $user = $this->auth->user();

                // Add the oauth cred to the existing user
                $this->auth->update_credential($user['id'],
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
                        'local',
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

        // Set session
        $this->auth->user($user);

        return $user;
    }
}
