<?php

namespace League\OAuth2\Client\Provider;

final class Test
{
    public static array $lastConfig = [];
    public static array $lastAuthorizationOptions = [];
    public static array $lastTokenOptions = [];
    public static mixed $resourceOwner = null;
    public static string $state = 'test-oauth-state';

    public function __construct(array $config)
    {
        self::$lastConfig = $config;
    }

    public function getAuthorizationUrl(array $options = []): string
    {
        self::$lastAuthorizationOptions = $options;
        return 'https://oauth.example/authorize';
    }

    public function getState(): string
    {
        return self::$state;
    }

    public function getAccessToken(string $grant, array $options): object
    {
        self::$lastTokenOptions = $options;
        if ($grant !== 'authorization_code' || ($options['code'] ?? null) !== 'oauth-code'
            || empty($options['code_verifier'])) {
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
