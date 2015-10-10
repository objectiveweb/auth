<?php

namespace Objectiveweb\Auth;

class AuthController {
	
	private $auth;
	
	public function __construct($auth) {
		$this->auth = $auth;	
	}
	
	public function get($username = null) {
		if(!$username) {
			// list all
		}
		else {
			return $this->auth->get($username);
		}
	}
	
	public function post($data) {
		
		$username = $data['username'];
		$password = $data['password'];
		
		unset($data['username']);
		unset($data['password']);
		
		return $this->auth->register($username, $password, $data);
		
	}
	
	public function put($username, $data) {
		if(isset($data['password'])) {
			$this->auth->passwd($username, $data['password']);
			
			unset($data['password']);
		}
		
		return $this->auth->update($username, $data);
	}
	
	public function delete($username) {
		$this->auth->delete($username);
	}
}