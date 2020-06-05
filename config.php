<?php

return [
    'test' => [
        'security' => [
            'rsa' => [
                'private_key' => env('TEST_SECURITY_RSA_PRIVATE_KEY'),
                'public_key' => env('TEST_SECURITY_RSA_PUBLIC_KEY'),
                'password' => env('TEST_SECURITY_RSA_PASSWORD')
            ]
        ]
    ]
];
