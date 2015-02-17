<?php
/**
 * Created by IntelliJ IDEA.
 * User: guigouz
 * Date: 16/02/15
 * Time: 15:43
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use Objectiveweb\Auth;

class AuthTest extends PHPUnit_Framework_TestCase
{

    /** @var  Auth */
    protected static $auth;

    private static $shared_session = array();

    public static function setUpBeforeClass()
    {

        $pdo = new PDO('mysql:dbname=objectiveweb;host=192.168.56.101', 'root');
        $pdo->query('drop table if exists ow_auth_test');
        $pdo->query('create table ow_auth_test
            (`id` INT UNSIGNED PRIMARY KEY NOT NULL AUTO_INCREMENT,
                `username` VARCHAR(255),
                `displayName` VARCHAR(255),
                `email` VARCHAR(255),
                `created` DATETIME,
                `last_login` DATETIME,
                `password` VARCHAR(60),
                `token` VARCHAR(32));');

        self::$auth = new Auth($pdo, ['table' => 'ow_auth_test']);
    }

    public function setUp()
    {
        $_SESSION = self::$shared_session;
    }

    public function tearDown()
    {

        self::$shared_session = $_SESSION;
    }

    public function testRegister()
    {

        $user = AuthTest::$auth->register([
            'username' => 'user',
            'password' => 'test',
            'email' => 'vagrant@localhost',
            'displayName' => 'Test User'
        ]);

        $this->assertEquals(1, $user['id']);
    }

    /**
     * @expectedException Objectiveweb\Auth\UserException
     */
    public function testInvalidLogin()
    {
        self::$auth->login('nouser', 'pass');

    }

    /**
     * @expectedException Objectiveweb\Auth\PasswordMismatchException
     */
    public function testInvalidPassword()
    {
        self::$auth->login('user', 'pass');

    }

    public function testValidLogin()
    {
        $user = self::$auth->login('user', 'test');

        $this->assertEquals(1, $user['id'], "Check user ID");
        $this->assertRegExp('/[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}/',
            $user['created'],
            "Check creation date");
        $this->assertTrue(AuthTest::$auth->check());

    }

    public function testSession()
    {
        $user = self::$auth->user();

        $this->assertEquals(1, $user['id']);
    }

    public function testLogout()
    {
        self::$auth->logout();

        $this->assertFalse(self::$auth->check());
    }


    /**
     * @expectedException Objectiveweb\Auth\PasswordMismatchException
     */
    public function testPasswd()
    {
        $t = self::$auth->passwd('user', "1234");

        $this->assertTrue($t);

        self::$auth->login('user', 'test');

    }

    public function testLoginWithNewPassword()
    {
        $user = self::$auth->login('user', '1234');

        $this->assertEquals(1, $user['id']);
    }

}