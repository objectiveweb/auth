<?php

namespace Objectiveweb\Auth;

use \Objectiveweb\Auth;

trait AclTrait {

    /** @var  \Objectiveweb\Auth */
    private $auth;

//    protected $acl = [
  //      '*' => Auth::AUTHENTICATED
 //       'get' => Auth::ANONYMOUS,
 //       'post' => Auth::AUTHENTICATED
        // 'public' => Auth::ALL
   // ];

    function before($method, $fn) {

        if(!isset($this->acl)) {
            error_log("AclTrait loaded but no acl found on ".get_class($this));
            return;
        }

        if($this->auth->check()) {
            $scopes = [ 'auth' ];
            // TODO include other user-specific scopes
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