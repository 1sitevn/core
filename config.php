<?php

return [
    'test' => [
        'security' => [
            'rsa' => [
                'private_key' => env('TEST_SECURITY_RSA_PRIVATE_KEY'),
                'public_key' => env('TEST_SECURITY_RSA_PUBLIC_KEY'),
                'password' => env('TEST_SECURITY_RSA_PASSWORD'),
                'message' => env('TEST_SECURITY_RSA_MESSAGE'),
                'signature' => env('TEST_SECURITY_RSA_SIGNATURE'),
                'cipher_text' => env('TEST_SECURITY_RSA_CIPHER_TEXT'),
            ]
        ]
    ]
];
