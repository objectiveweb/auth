<?php

namespace Objectiveweb\Auth\Controller;

use Objectiveweb\Auth\UserException;

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
    function get($id, $query)
    {
        if (!isset($this->providers[$id])) {
            throw new \Exception("Invalid provider $id", 406);
        }

        $config = $this->providers[$id];

        $config['redirectUri'] =
            (empty($_SERVER['HTTP_X_FORWARDED_PROTO']) ? $_SERVER['REQUEST_SCHEME'] : $_SERVER['HTTP_X_FORWARDED_PROTO'])
            . "://{$_SERVER['HTTP_HOST']}{$_SERVER['PHP_SELF']}";

        $classname = "\\League\\OAuth2\\Client\\Provider\\" . ucfirst($id);

        /** @var \League\OAuth2\Client\Provider\GenericProvider $provider */
        $provider = new $classname($config);

        if (!empty($query['error'])) {
            throw new \Exception("Got error {$query['error']}", 500);
        } elseif (empty($query['code'])) {
            // generate authUrl first to update state
            $authUrl = $provider->getAuthorizationUrl();
            $_SESSION['oauth2state'] = $provider->getState();
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

        if (!$credential && !empty($email)) {
            $credential = $this->auth->get_credential('local', $email);
        }

        if (empty($credential['user_id'])) {
            // Interface fields
            $data = [
                'uid' => $uid,
                'provider' => $provider,
                'profile' => $resourceOwner->toArray(),
                'name' => $resourceOwner->getName(),
                'image' => is_callable([$resourceOwner, 'getAvatar']) ? $resourceOwner->getAvatar() : $resourceOwner->getPictureUrl()
            ];

            $user = $this->auth->register($data);

            if (!empty($email)) {
                // Add local credential to the user
                $this->auth->update_credential($user[$this->auth->params['id']],
                    'local',
                    $email,
                    []);
            }
        } else {
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
