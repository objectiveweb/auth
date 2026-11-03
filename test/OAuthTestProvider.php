<?php

namespace League\OAuth2\Client\Provider;

final class Test
{
    public static array $lastConfig = [];
    public static mixed $resourceOwner = null;
    public static string $state = 'test-oauth-state';

    public function __construct(array $config)
    {
        self::$lastConfig = $config;
    }

    public function getAuthorizationUrl(): string
    {
        return 'https://oauth.example/authorize';
    }

    public function getState(): string
    {
        return self::$state;
    }

    public function getAccessToken(string $grant, array $options): object
    {
        if ($grant !== 'authorization_code' || ($options['code'] ?? null) !== 'oauth-code') {
            throw new \RuntimeException('Unexpected OAuth token request');
        }

        return (object) ['access_token' => 'test-token'];
    }

    public function getResourceOwner(object $token): object
    {
        if (self::$resourceOwner === null) {
            throw new \RuntimeException('Missing OAuth test resource owner');
        }

        return self::$resourceOwner;
    }
}
