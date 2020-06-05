<?php

namespace OneSite\Core\Test\Security;


use OneSite\Core\Security\RSA;
use PHPUnit\Framework\TestCase;

class RSATest extends TestCase
{

    private $service;

    /**
     *
     */
    public function setUp(): void
    {
        parent::setUp();

        $this->service = new RSA();
    }

    /**
     *
     */
    public function tearDown(): void
    {
        $this->service = null;

        parent::tearDown();
    }

    /**
     * PHPUnit test: vendor/bin/phpunit --filter testCreateKeys tests/Security/RSATest.php
     */
    public function testCreateKeys()
    {
        $this->service->createKeys(
            config('test.security.rsa.private_key'),
            config('test.security.rsa.public_key'),
            config('test.security.rsa.password')
        );

        echo "\n" . json_encode(config('test.security.rsa'));

        return $this->assertTrue(true);
    }

}
