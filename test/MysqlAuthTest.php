<?php
/**
 * Created by IntelliJ IDEA.
 * User: guigouz
 * Date: 16/02/15
 * Time: 15:43
 */

#require dirname(__DIR__) . '/vendor/autoload.php';

require __DIR__ . '/Mysql_TestCase.php';

use Objectiveweb\Auth\MysqlAuth;

class MysqlAuthTest extends Mysql_TestCase
{

    private static $shared_session = array();


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

        $this->assertEquals('Test User', $user['name']);

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