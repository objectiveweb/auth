<?php
/**
 * Created by PhpStorm.
 * User: developer
 * Date: 8/30/17
 * Time: 3:19 AM
 */

namespace Objectiveweb\Auth;

use Objectiveweb\Auth;

/**
 * Class AuthController
 *
 * OAuth-aware Authentication Controller
 * Supports all Strategies provided by OpAuth
 *
 * @package Objectiveweb\Auth
 */
class AuthController
{

    use AclTrait;

    protected $acl = [
        '*' => Auth::ANONYMOUS,
        'get' => Auth::ALL,
        'callback' => Auth::ALL
    ];

    /** @var \Opauth */
    private $opauth;

    /** @var \Objectiveweb\Auth */
    private $auth;

    function __construct(\Objectiveweb\Auth $auth, \Opauth $opauth)
    {
        $this->auth = $auth;
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
     * Login a local user
     */
    function postLogin(array $form)
    {
        $this->auth->login($form['username'], $form['password']);

        return $this->auth->user();
    }

    /**
     * Register a new user
     * @param $user array
     */
    function postRegister(array $user)
    {
        return $this->auth->register($user['username'], $user['password'], [
            'email' => $user['email']
        ]);
    }

    /**
     * OAuth callback handler, based on transport configuration for callback
     */
    function callback()
    {

        $response = null;
        switch ($this->opauth->env['callback_transport']) {
            case 'session':
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
            throw new \Exception("Authentication error: Opauth returns error auth response.");
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

                // print_r($response);
                // return '<strong style="color: green;">OK: </strong>Auth response is validated.' . "<br>\n";

                /**
                 * It's all good. Go ahead with your application-specific authentication logic
                 */

                $account = $this->auth->get_account($response['auth']['provider'], $response['auth']['uid']);

                if ($account) {
                    // Account already exists, login as user
                    $user = $this->auth->get($account['user_id'], 'id');
                    $this->auth->user($user);
                } else {
                    // if logged in
                    if ($this->auth->check()) {
                        $user = $this->auth->user();
                    } else {
                        // new account
                        $username = empty($response['auth']['info']['email']) ?
                            "{$response['auth']['provider']}:{$response['auth']['uid']}"
                            : $response['auth']['info']['email'];

                        // see if there's account with the same email
                        try {
                            $user = $this->auth->get($username);
                        } catch (UserException $ex) {
                            $user = $this->auth->register($username);
                        }
                    }

                    // Add account to the user
                    $this->auth->update_account($user['id'],
                        $response['auth']['provider'],
                        $response['auth']['uid'],
                        $response['auth']['info']);

                }
            }

        }

    }
}
