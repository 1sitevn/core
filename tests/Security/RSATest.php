<?php

namespace OneSite\Core\Test\Security;


use OneSite\Core\Security\RSA;
use PHPUnit\Framework\TestCase;

/**
 * Class RSATest
 * @package OneSite\Core\Test\Security
 */
class RSATest extends TestCase
{

    /**
     * @var RSA
     */
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

    /**
     * PHPUnit test: vendor/bin/phpunit --filter testSign tests/Security/RSATest.php
     */
    public function testSign()
    {
        $signText = $this->service->sign(
            config('test.security.rsa.private_key'),
            config('test.security.rsa.signature'),
            config('test.security.rsa.password')
        );

        echo "\n" . $signText;

        return $this->assertTrue(true);
    }

    /**
     * PHPUnit test: vendor/bin/phpunit --filter testVerify tests/Security/RSATest.php
     */
    public function testVerify()
    {
        $signVerify = $this->service->verify(
            config('test.security.rsa.public_key'),
            config('test.security.rsa.message'),
            config('test.security.rsa.signature')
        );

        echo "\n" . ($signVerify ? 'Is valid' : 'Is not valid');

        return $this->assertTrue($signVerify);
    }
}
