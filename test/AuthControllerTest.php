<?php
/**
 * Created by IntelliJ IDEA.
 * User: guigouz
 * Date: 16/02/15
 * Time: 15:43
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use Objectiveweb\Auth;
use Objectiveweb\Auth\AuthController;

class AuthControllerTest extends PHPUnit_Framework_TestCase
{

    /** @var  AuthController */
    protected static $controller;

    private static $shared_session = array();

    public static function setUpBeforeClass()
    {

        $pdo = new PDO('mysql:dbname=objectiveweb;host=localhost', 'root');
        $pdo->query('drop table if exists ow_auth_test');
        $pdo->query('create table ow_auth_test
            (`id` INT UNSIGNED PRIMARY KEY NOT NULL AUTO_INCREMENT,
                `username` VARCHAR(255),
                `displayName` VARCHAR(255),
                `email` VARCHAR(255),
                `created` DATETIME,
                `last_login` DATETIME,
                `password` CHAR(60),
                `token` CHAR(32));');

        $auth = new Auth($pdo, [
            'table' => 'ow_auth_test',
            'created' => 'created',
            'token' => 'token',
            'last_login' => 'last_login'
        ]);
		
		self::$controller = new AuthController($auth);
    }

    public function testPost()
    {

        $user = self::$controller->post([
			'username' => 'user', 
			'password' => 'test',
            'email' => 'vagrant@localhost',
            'displayName' => 'Test User']);

        $this->assertEquals(1, $user['id']);

    }
	
	/**
	 * @depends testPost
	 */
	public function testGet() {
		$user = self::$controller->get('user');

        $this->assertEquals(1, $user['id']);
	}
	
	/**
	 * @depends testGet
	 */
    public function testPut() {

        self::$controller->put('user', [ 'displayName' => 'Updated name' ]);

        $user = self::$controller->get('user');

        $this->assertEquals('Updated name', $user['displayName']);
    }

	/**
	 * @depends testPut
     * @expectedException Objectiveweb\Auth\UserException
     */
	public function testDelete() {
		self::$controller->delete('user');
		
		$user = self::$controller->get('user');
	}
}