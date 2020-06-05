<?php

namespace OneSite\Napas\Billing;


/**
 * Class Service
 * @package OneSite\Napas\Billing
 */
class Service
{
    /**
     * @var array|mixed|null
     */
    private $apiUrl;
    /**
     * @var array|mixed|null
     */
    private $userId;
    /**
     * @var array|mixed|null
     */
    private $userPassword;
    private $npayPrivateKey;
    private $npayPublicKey;
    private $npayPassword;

    /**
     * Service constructor.
     */
    public function __construct()
    {
        $this->apiUrl = Config::get('napas.billing.api_url');
        $this->userId = Config::get('napas.billing.user_id');
        $this->userPassword = Config::get('napas.billing.user_password');
        $this->npayPrivateKey = Config::get('napas.billing.9pay_private_key');
        $this->npayPublicKey = Config::get('napas.billing.9pay_public_key');
        $this->npayPassword = Config::get('napas.billing.9pay_password');
    }

    /**
     *
     */
    public function payment()
    {
        $params = [
            'mti' => '0200',
            'processingCode' => '050000',
            'amount' => 10000,
            'transDate' => date('YmdHis'),
            'trace' => time(),
            'channel' => 6012,
            'agentID' => 905001,
            'currencyCode' => 704,
            'serviceCode' => 'VTVCABBILL',
            'paymentID' => '6751958',
            // 'signature' => '',
        ];

        $text = md5(implode('', $params));

        $rsa = new RSA();

        $params['signature'] = $rsa->sign(
            $this->npayPrivateKey,
            $text,
            $this->npayPassword
        );

        var_dump($text, $params['signature']);

        var_dump($rsa->verify(
            $this->npayPublicKey,
            $text,
            $params['signature']
        ));

        exit;
    }

}
