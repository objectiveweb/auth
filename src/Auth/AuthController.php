<?php

namespace Objectiveweb\Auth;

class AuthController {
	
	private $auth;
	
	public function __construct($auth) {
		$this->auth = $auth;	
	}
	
	public function get($params = array()) {
		if(is_string($params)) {
			return $this->auth->get($params);
		}
		else {
			return $this->auth->query($params);
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