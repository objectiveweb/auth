<?php

namespace Objectiveweb\Auth;

class AuthController {

    /** @var  \Objectiveweb\Auth */
	private $auth;
	
	public function __construct(\Objectiveweb\Auth $auth) {
		$this->auth = $auth;	
	}
	
	public function index() {
		return $this->get();
	}

	public function get($params = array()) {
		if(is_array($params)) {
            return $this->auth->query($params);
        }
        else {
            return $this->auth->get($params);
        }
	}
	
	public function post($data) {
				
		return $this->auth->register($data);
		
	}
	
	public function put($username, $data) {

        if(!empty($data['password'])) {
            $this->auth->passwd($username, $data['password']);
        }

        unset($data['password']);

		$this->auth->update($username, $data);

        return true;
	}
	
	public function delete($username) {
		$this->auth->delete($username);
	}
}
