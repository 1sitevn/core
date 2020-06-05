<?php
/**
 * Created by PhpStorm.
 * User: tungnt
 * Date: 10/7/19
 * Time: 16:27
 */

namespace OneSite\Core\Security;


/**
 * Class RSA
 * @package OneSite\Core\Security
 */
class RSA
{

    /**
     * @var int
     */
    private $bitsKey = 2048;
    /**
     * @var string
     */
    private $hash = "sha512";

    /**
     * @return int
     */
    public function getBitsKey(): int
    {
        return $this->bitsKey;
    }

    /**
     * @param int $bitsKey
     */
    public function setBitsKey(int $bitsKey): void
    {
        $this->bitsKey = $bitsKey;
    }

    /**
     * @return string
     */
    public function getHash(): string
    {
        return $this->hash;
    }

    /**
     * @param string $hash
     */
    public function setHash(string $hash): void
    {
        $this->hash = $hash;
    }


    /**
     * @param $privateKeyPath
     * @param $publicKeyPath
     * @param string $password
     * @param array $options
     */
    public function createKeys($privateKeyPath, $publicKeyPath, $password = "", $options = [])
    {
        $rsa = new \phpseclib\Crypt\RSA();

        $rsa->setEncryptionMode(\phpseclib\Crypt\RSA::ENCRYPTION_PKCS1);

        if (!empty($password)) {
            $rsa->setPassword($password);
        }

        $keys = $rsa->createKey($this->getBitsKey());

        file_put_contents($privateKeyPath, $keys['privatekey']);
        file_put_contents($publicKeyPath, $keys['publickey']);

        chmod($privateKeyPath, 0600);
    }

    /**
     * @param $publicKeyPath
     * @param $plaintext
     * @return string
     */
    public function encrypt($publicKeyPath, $plaintext)
    {
        $rsaPublic = new \phpseclib\Crypt\RSA();

        $publicKeyData = file_get_contents($publicKeyPath);

        $rsaPublic->setEncryptionMode(\phpseclib\Crypt\RSA::ENCRYPTION_PKCS1);

        $rsaPublic->loadKey($publicKeyData);

        $rsaPublic->setHash($this->getHash());
        $rsaPublic->setMGFHash($this->getHash());

        $cipherTextRaw = $rsaPublic->encrypt($plaintext);

        $cipherText = base64_encode($cipherTextRaw);

        return $cipherText;
    }

    /**
     * @param $privateKeyPath
     * @param $password
     * @param $cipherText
     * @return string
     */
    public function decrypt($privateKeyPath, $password, $cipherText)
    {
        $rsaPrivate = new \phpseclib\Crypt\RSA();

        $rsaPrivate->setEncryptionMode(\phpseclib\Crypt\RSA::ENCRYPTION_PKCS1);

        $rsaPrivate->setPassword($password);

        $privateKeyData = file_get_contents($privateKeyPath);

        $rsaPrivate->loadKey($privateKeyData, \phpseclib\Crypt\RSA::PRIVATE_FORMAT_PKCS1);

        $rsaPrivate->setHash($this->getHash());
        $rsaPrivate->setMGFHash($this->getHash());

        $decrypted = $rsaPrivate->decrypt(base64_decode($cipherText));

        return $decrypted;
    }

    /**
     * @param $privateKeyPath
     * @param $message
     * @param string $password
     * @return string
     */
    public function sign($privateKeyPath, $message, $password = '')
    {
        $rsaSigner = new \phpseclib\Crypt\RSA();

        $privateKeyData = file_get_contents($privateKeyPath);

        if (!empty($password)) {
            $rsaSigner->setPassword($password);
        }

        $rsaSigner->loadKey($privateKeyData);
        $rsaSigner->setHash($this->getHash());
        $rsaSigner->setMGFHash($this->getHash());

        $signature = $rsaSigner->sign($message);

        return base64_encode($signature);
    }

    /**
     * @param $publicKeyPath
     * @param $message
     * @param $signature
     * @return bool
     */
    public function verify($publicKeyPath, $message, $signature)
    {
        $rsaVerifier = new \phpseclib\Crypt\RSA();

        $rsaVerifier->setHash($this->getHash());
        $rsaVerifier->setMGFHash($this->getHash());

        $publicKeyData = file_get_contents($publicKeyPath);

        $rsaVerifier->loadKey($publicKeyData);

        $signature = base64_decode($signature);

        return $rsaVerifier->verify($message, $signature);
    }

    /**
     * @param $data
     * @return string
     */
    private function _sign($data)
    {
        $privateKey = file_get_contents('/Sources/Packages/napas-billing/storage/credentials/1591263414_private.key');

        $privateKeyId = openssl_pkey_get_private($privateKey);

        openssl_sign($data, $binarySignature, $privateKeyId, OPENSSL_ALGO_SHA1);

        return base64_encode($binarySignature);
    }

    /**
     * @param $sign
     * @param $data
     * @return bool
     */
    private function _verify($sign, $data)
    {
        $publicKey = file_get_contents('/Sources/Packages/napas-billing/storage/credentials/1591263414_public.pem');

        $publicKeyId = openssl_pkey_get_public($publicKey);

        return (bool)openssl_verify($data, base64_decode($sign), $publicKeyId, OPENSSL_ALGO_SHA1);
    }

    /**
     * @return bool|string
     */
    private function getPassword()
    {
        return substr(base64_encode(openssl_random_pseudo_bytes(45)), 0, 32);
    }
}
