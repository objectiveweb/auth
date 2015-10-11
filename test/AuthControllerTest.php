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

        $auth = new Auth($pdo, array(
            'table' => 'ow_auth_test',
            'created' => 'created',
            'token' => 'token',
            'last_login' => 'last_login'
        ));
		
		self::$controller = new AuthController($auth);
    }

    public function testPost()
    {

        $user = self::$controller->post(array(
			'username' => 'user', 
			'password' => 'test',
            'email' => 'vagrant@localhost',
            'displayName' => 'Test User'));

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
	public function testQuery() {
		$all = self::$controller->get();
		
		$this->assertEquals(1, count($all['_embedded']['ow_auth_test']));
		
		$this->assertEquals('Test User', $all['_embedded']['ow_auth_test'][0]['displayName']);
		
		$this->assertEquals(1, $all['page']['totalElements']);
		$this->assertEquals(1, $all['page']['totalPages']);
		$this->assertEquals(0, $all['page']['number']);
	}
	
	/**
	 * @depends testQuery
	 */
    public function testPut() {

        self::$controller->put('user', array( 'displayName' => 'Updated name' ));

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