<?php
/**
 * Created by IntelliJ IDEA.
 * User: guigouz
 * Date: 16/02/15
 * Time: 15:43
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use Objectiveweb\Auth\MysqlAuth;
use Objectiveweb\Auth\Controller\UserController;

class UserControllerTest extends PHPUnit_Framework_TestCase
{

    /** @var  UserController */
    protected static $controller;

    private static $shared_session = array();

    public static function setUpBeforeClass()
    {

        $pdo = new PDO('mysql:dbname=objectiveweb;host=mysql', 'root', 'root');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec('drop table if exists ow_credentials');
        $pdo->exec('drop table if exists ow_user');
        $pdo->query('create table ow_user
            (`id` INT UNSIGNED PRIMARY KEY NOT NULL AUTO_INCREMENT,
                `name` VARCHAR(255),
                `image` VARCHAR(255),
                `scopes` VARCHAR(255),
                `created` DATETIME,
                `password` CHAR(60),
                `token` CHAR(32))');

        $pdo->query("create table ow_credentials
            (
                uid varchar(255) not null,
                provider varchar(32) not null,
                user_id int(11) unsigned not null,
                profile text null,
                modified datetime null,
                primary key (uid, provider),
                constraint credentials_ibfk_1
                    foreign key (user_id) references ow_user (id)
            )");

        $auth = new MysqlAuth($pdo, array(
            'created' => 'created',
            'token' => 'token'
        ));
		
		self::$controller = new UserController($auth);
    }

    public function testPost()
    {

        $user = self::$controller->post(array(
			'uid' => 'vagrant@localhost',
			'password' => 'test',
            'name' => 'Test User'));

        $this->assertEquals(1, $user['id']);

    }

	/**
	 * @depends testPost
	 */
	public function testGet() {
		$user = self::$controller->get(1);

        $this->assertEquals(1, $user['id']);
	}

	/**
	 * @depends testGet
	 */
	public function testQuery() {
		$all = self::$controller->get();

		$this->assertEquals(1, count($all['_embedded']['ow_user']));

		$this->assertEquals('Test User', $all['_embedded']['ow_user'][0]['name']);

		$this->assertEquals(1, $all['page']['totalElements']);
		$this->assertEquals(1, $all['page']['totalPages']);
		$this->assertEquals(0, $all['page']['number']);
	}

	/**
	 * @depends testQuery
	 */
    public function testPut() {

        self::$controller->put(1, array( 'name' => 'Updated name' ));

        $user = self::$controller->get(1);

        $this->assertEquals('Updated name', $user['name']);
    }

	/**
	 * @depends testPut
     * @expectedException Objectiveweb\Auth\UserException
     */
	public function testDelete() {
		self::$controller->delete(1);

		$user = self::$controller->get(1);
	}
}