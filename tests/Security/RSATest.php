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

        return $this->assertTrue(true);
    }

    /**
     * PHPUnit test: vendor/bin/phpunit --filter testSign tests/Security/RSATest.php
     */
    public function testSign()
    {
        $signText = $this->service->sign(
            config('test.security.rsa.private_key'),
            config('test.security.rsa.message'),
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

    /**
     * PHPUnit test: vendor/bin/phpunit --filter testEncrypt tests/Security/RSATest.php
     */
    public function testEncrypt()
    {
        $data = $this->service->encrypt(
            config('test.security.rsa.public_key'),
            config('test.security.rsa.message')
        );

        echo "\n" . json_encode($data);

        return $this->assertTrue(true);
    }

    /**
     * PHPUnit test: vendor/bin/phpunit --filter testDecrypt tests/Security/RSATest.php
     */
    public function testDecrypt()
    {
        $data = $this->service->decrypt(
            config('test.security.rsa.private_key'),
            config('test.security.rsa.password'),
            config('test.security.rsa.cipher_text')
        );

        echo "\n" . json_encode($data);

        return $this->assertSame($data, config('test.security.rsa.message'));
    }
}
