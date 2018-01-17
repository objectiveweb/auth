<?php

namespace Objectiveweb\Auth;

/**
 * Class OAuthController
 *
 * OAuth-aware Authentication Controller
 * Supports all Strategies provided by OpAuth
 *
 * @package Objectiveweb\Auth
 */
class OAuthController extends AuthController
{

    /** @var \Opauth */
    private $opauth;

    function __construct(\Objectiveweb\Auth $auth, \Opauth $opauth)
    {
        parent::__construct($auth);

        $this->opauth = $opauth;

    }

    /**
     * Execute login on oauth provider
     */
    function get($provider)
    {
        $this->opauth->run();
    }

    /**
     * OAuth callback handler, based on transport configuration for callback
     */
    function callback()
    {

        $response = null;
        switch ($this->opauth->env['callback_transport']) {
            case 'session':
                if (!session_id())
                    session_start();
                $response = $_SESSION['opauth'];
                unset($_SESSION['opauth']);
                break;
            case 'post':
                $response = unserialize(base64_decode($_POST['opauth']));
                break;
            case 'get':
                $response = unserialize(base64_decode($_GET['opauth']));
                break;
            default:
                throw new \Exception("Unsupported callback_transport");
                break;
        }

        /**
         * Check if it's an error callback
         */
        if (array_key_exists('error', $response)) {
            $error = json_encode($response['error']);
            throw new \Exception("Authentication error: {$error}");
        }

        /**
         * Auth response validation
         *
         * To validate that the auth response received is unaltered, especially auth response that
         * is sent through GET or POST.
         */
        else {
            if (empty($response['auth']) || empty($response['timestamp']) || empty($response['signature']) || empty($response['auth']['provider']) || empty($response['auth']['uid'])) {
                throw new \Exception("Invalid auth response: Missing key auth response components");
            } elseif (!$this->opauth->validate(sha1(print_r($response['auth'], true)), $response['timestamp'], $response['signature'], $reason)) {
                throw new \Exception("Invalid auth response: $reason ");
            } else {

                /**
                 * It's all good. Go ahead with your application-specific authentication logic
                 */

                $account = $this->auth->get_account($response['auth']['provider'], $response['auth']['uid']);

                // if account does not exist, create
                if (!$account) {
                    // if already logged in
                    if ($this->auth->check()) {
                        $user = $this->auth->user();
                    } else {
                        // create new user
                        $username = empty($response['auth']['info']['email']) ?
                            "{$response['auth']['provider']}:{$response['auth']['uid']}"
                            : $response['auth']['info']['email'];

                        // see if there's account with the same email
                        try {
                            $user = $this->auth->get($username);
                        } catch (UserException $ex) {
                            $user = $this->auth->register($username, null, [
                                'name' => $response['auth']['info']['name'],
                                'image' => $response['auth']['info']['image']
                            ]);
                        }
                    }

                    // Add account to the user
                    $this->auth->update_account($user[$this->auth->params['id']],
                        $response['auth']['provider'],
                        $response['auth']['uid'],
                        $response['auth']['info']);

                    // fetch updated user
                    $user = $this->auth->get($user[$this->auth->params['id']], $this->auth->params['id']);
                }
                else {
                    // account exists, fetch existing user
                    $user = $this->auth->get($account['user_id'], $this->auth->params['id']);
                }

                // Set session
                $this->auth->user($user);
            }

        }

    }
}
