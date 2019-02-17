<?php
/**
 * Created by IntelliJ IDEA.
 * User: guigouz
 * Date: 16/02/15
 * Time: 15:43
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use Objectiveweb\Auth\MysqlAuth;

class MysqlAuthTest extends PHPUnit_Framework_TestCase
{

    /** @var  Auth */
    protected static $auth;

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

        self::$auth = new MysqlAuth($pdo, array(
            'created' => 'created',
            'token' => 'token'
        ));

    }

    public function setUp()
    {
        $_SESSION = self::$shared_session;
    }

    public function tearDown()
    {

        self::$shared_session = $_SESSION;
    }

    public function testRegistration()
    {

        $user = self::$auth->register('vagrant@localhost', 'test', array(
            'name' => 'Test User'
        ));

        $this->assertEquals(1, $user['id']);

        // test Login
        $user = self::$auth->login('vagrant@localhost', 'test');

        $this->assertEquals(1, $user['id'], "Check user ID");
        $this->assertRegExp('/[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}/',
            $user['created'],
            "Check creation date");
        $this->assertTrue(self::$auth->check());

        // test Session
        $user = self::$auth->user();

        $this->assertEquals(1, $user['id']);

        // test Logout
        self::$auth->logout();

        $this->assertFalse(self::$auth->check());
    }

    /**
     * @expectedException Objectiveweb\Auth\UserException
     */
    public function testInvalidLogin()
    {
        self::$auth->login('nouser', 'pass');

    }

    /**
     * @expectedException Objectiveweb\Auth\AuthException
     */
    public function testInvalidPassword()
    {
        self::$auth->login('vagrant@localhost', 'pass');

    }

    public function testPasswd()
    {

        $account = self::$auth->get_credential('local', 'vagrant@localhost');

        $this->assertNotNull($account);

        $t = self::$auth->passwd($account['user_id'], "1234");

        $this->assertTrue($t);

        $user = self::$auth->login('vagrant@localhost', '1234');

        $this->assertEquals(1, $user['id']);

    }

	/**
	 * @depends testRegistration
	 */
    public function testUpdate() {

        $account = self::$auth->get_credential('local', 'vagrant@localhost');

        $user = self::$auth->get($account['user_id']);

        $this->assertEquals(1, $user['id']);

        self::$auth->update($account['user_id'], array( 'name' => 'Updated name' ));

        $user = self::$auth->get($account['user_id']);

        $this->assertEquals('Updated name', $user['name']);
    }
	
    /**
	 * @depends testUpdate
	 */
	public function testQuery() {
		$all = self::$auth->query();
		
		$this->assertEquals(1, count($all['_embedded']['ow_user']));
		
		$this->assertEquals('Updated name', $all['_embedded']['ow_user'][0]['name']);
		
		$this->assertEquals(1, $all['page']['totalElements']);
		$this->assertEquals(1, $all['page']['totalPages']);
		$this->assertEquals(0, $all['page']['number']);
	}
	
    public function testRequestToken() {
	    $account = self::$auth->get_credential('local', 'vagrant@localhost');

        $token = self::$auth->update_token($account['user_id']);

        self::$auth->passwd_reset($token, 'test');

        self::$auth->login('vagrant@localhost', 'test');
    }
	/**
     * @expectedException Objectiveweb\Auth\UserException
     */
	public function testDelete() {
        $account = self::$auth->get_credential('local', 'vagrant@localhost');

        self::$auth->logout();
		self::$auth->delete($account['user_id']);
		self::$auth->login('vagrant@localhost', 'pass');
	}
       
}