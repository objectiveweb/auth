<?php

namespace Objectiveweb\Auth;

use Throwable;

class UserException extends \Exception {

    private $user;

    function __construct($message = "", $code = 0, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }

    function setUser(array $user) {
        $this->user = $user;
    }

    function getUser() {
        return $this->user;
    }
}
