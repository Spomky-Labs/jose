<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\Stub;

use Base64Url\Base64Url;
use Jose\Finder\JWKFinderInterface;

/**
 */
class APVFinder implements JWKFinderInterface
{
    /**
     * {@inheritdoc}
     */
    public function findJWK(array $header)
    {
        if (!isset($header['apv'])) {
            return;
        }

        if ('Bob' === Base64Url::decode($header['apv'])) {
            return [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
                'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
                'd'   => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
            ];
        }
        if ('Alice' === Base64Url::decode($header['apv'])) {
            return [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
                'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
                'd'   => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
            ];
        }
    }
}
