<?php

require_once __DIR__ . '/Mysql_TestCase.php';

use Objectiveweb\Auth\Controller\UserController;

class UserControllerTest extends Mysql_TestCase
{

    /** @var  UserController */
    protected static $controller;

    private static $shared_session = array();

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();
        if (self::$auth) {
            self::$controller = new UserController(self::$auth);
        }
    }

    public function testPost()
    {

        $user = self::$controller->post(array(
			'uid' => 'vagrant@localhost',
			'password' => 'test',
            'name' => 'Test User'));

        $this->assertEquals(1, $user['id']);

    }

    public function testPostMissingUid(): void
    {
        $this->expectException(\Objectiveweb\Auth\UserException::class);
        self::$controller->post([
            'name' => 'Invalid User',
        ]);
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

    public function testQueryInvalidFilterField(): void
    {
        $this->expectException(\Objectiveweb\Auth\UserException::class);
        self::$controller->get(['unknown_field' => 'x']);
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
     */
    public function testDelete() {
        $this->expectException(\Objectiveweb\Auth\UserException::class);
        $deleted = self::$controller->delete(1);
        $this->assertTrue($deleted);

        $user = self::$controller->get(1);
    }
}
