<?php

namespace Objectiveweb\Auth;

use \Objectiveweb\Auth;

trait AclTrait {

    /** @var  \Objectiveweb\Auth */
    private $auth;

    /** @var array */
    private $user;

    private $acl = [
        '*' => Auth::AUTHENTICATED
 //       'get' => Auth::ANONYMOUS,
 //       'post' => Auth::AUTHENTICATED
 ////// 'public' => Auth::ALL
    ];

    function aclSetup(Auth $auth, array $acl) {
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

        if(count(array_intersect($perms, $scopes)) == 0) {
            throw new \Exception("Forbidden", 403);
        }

    }
}