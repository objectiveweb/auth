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
        $config['redirectUri'] = "{$_SERVER['REQUEST_SCHEME']}://{$_SERVER['HTTP_HOST']}{$_SERVER['PHP_SELF']}";

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

            header("Location: /" );

        }
    }

    /**
     * @param $provider
     * @param \League\OAuth2\Client\Provider\ResourceOwnerInterface $resourceOwner
     * @return mixed
     */
    private function login($provider, $resourceOwner) {

        // Interface fields
        $uid = $resourceOwner->getId();
        $data = $resourceOwner->toArray();

        // Implementation-specific fields
        $email = $resourceOwner->getEmail();
        $name = $resourceOwner->getName();
        $image = is_callable([$resourceOwner, 'getAvatar']) ? $resourceOwner->getAvatar() : $resourceOwner->getPictureUrl();
        $account = $this->auth->get_account($provider, $uid);

        // if account does not exist, create
        if (!$account) {
            // if already logged in
            if ($this->auth->check()) {
                $user = $this->auth->user();
            } else {
                // create new user
                $username = empty($email) ?
                    "{$provider}:{$uid}"
                    : $email;

                // see if there's account with the same username
                try {
                    $user = $this->auth->get($username);
                } catch (UserException $ex) {
                    $user = $this->auth->register($username, null, [
                        'name' => $name,
                        'image' => $image
                    ]);
                }
            }

            // Add account to the user
            $this->auth->update_account($user[$this->auth->params['id']],
                $provider,
                $uid,
                $data);

            // fetch updated user
            $user = $this->auth->get($user[$this->auth->params['id']], $this->auth->params['id']);
        }
        else {
            // account exists, fetch existing user
            $user = $this->auth->get($account['user_id'], $this->auth->params['id']);
        }

        // Set session
        $this->auth->user($user);

        return $user;

    }

}
