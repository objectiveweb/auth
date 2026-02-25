<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Objectiveweb\Auth\BasicAuth;
use Objectiveweb\Auth\Controller\OAuthController;
use PHPUnit\Framework\TestCase;

class OAuthControllerTest extends TestCase
{
    public function testGetWithInvalidProviderThrows(): void
    {
        $_SESSION = [];
        $auth = new BasicAuth([], ['token' => 'token']);
        $controller = new OAuthController($auth, []);

        $this->expectException(\Exception::class);
        $this->expectExceptionCode(406);
        $controller->get('missing-provider', []);
    }
}
