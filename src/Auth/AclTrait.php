<?php

namespace Objectiveweb\Auth;

use \Objectiveweb\Auth;

trait AclTrait {

    /** @var  \Objectiveweb\Auth */
    private $auth;

    /**  @var array The logged in user data */
    private $user;

    /**
     * List of acls for each method, `*` is the fallback
     *
     * Acls should be passed to the `setupAcl` function
     *
     * Each entry is an array with the necessary scopes to access the method
     * Access is granted if the user has at least one of the scopes listed
     *
     *  * Auth::AUTHENTICATED - [ "auth" ] only allow authenticated users
     *  * Auth::ANONYMOUS     - [ "anon" ] only allow anonymous users
     *  * Auth::ALL           - [ "auth", "anon" ] allow all users
     *
     * You can defined arbitrary constraints, for example
     *
     * ```
     * $acl = [
     *     '*' => Auth::AUTHENTICATED,
     *     'register' => Auth::ANONYMOUS,
     *     'post' => [ 'admin' ]
     * ]
     * ```
     *
     * So only users with the `admin` scope will have access to the `post` method
     *
     * Acls can also be defined as a callback that should return an array of scopes
     *
     *
     * ```
     * $acl = [
     *     'post' => function() {
     *          return [ 'scope1', 'scope2' ]
     *     }
     * ]
     * ```
     *
     * @var array
     */
    private $acl = [
        '*' => Auth::AUTHENTICATED
    ];

    function aclSetup(Auth $auth, array $acl = []) {
        $this->auth = $auth;

        $this->acl = array_merge($this->acl, $acl);
    }

    function before($method, $fn) {

        if($this->auth->check()) {
            $scopes = [ 'auth' ];

            $this->user = $this->auth->user();

            if(is_array($this->user['scopes'])) {
                $scopes = array_merge($scopes, $this->user['scopes']);
            }
        }
        else {
            $scopes = [ 'anon' ];
        }

        $perms = isset($this->acl[$fn]) ? $this->acl[$fn] : $this->acl['*'];

        if(is_callable($perms)) {
            $perms = call_user_func($perms);
        }

        if(count(array_intersect($perms, $scopes)) == 0) {
            throw new \Exception("Forbidden", 403);
        }

    }
}