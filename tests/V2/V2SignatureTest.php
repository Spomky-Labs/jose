<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\V2;

use Jose\Factory\JWKFactory;
use Jose\Factory\JWSFactory;
use Jose\Factory\SignerFactory;

/**
 * @group V2
 */
class V2SignatureTest extends \PHPUnit_Framework_TestCase
{
    public function testCreateJWSAndSign()
    {
        $jws = JWSFactory::createJWS('Je suis Charlie');
        $signer = SignerFactory::createSigner(['HS256', 'HS384', 'HS512']);
        $key = JWKFactory::createFromValues([
            'kty' => 'oct',
            'k'   => 'foo',
        ]);

        $jws = $signer->addSignature($jws, $key, ['alg' => 'HS256']);
        $jws = $signer->addSignature($jws, $key, ['alg' => 'HS384'], ['foo' => 'bar']);
        $jws = $signer->addSignature($jws, $key, ['alg' => 'HS512'], ['plic' => 'ploc']);
    }

    public function testCreateJWSWithDetachedPayloadAndSign()
    {
        $jws = JWSFactory::createJWSWithDetachedPayload('Je suis Charlie', $encoded_payload);
        $signer = SignerFactory::createSigner(['HS256', 'HS384', 'HS512']);
        $key = JWKFactory::createFromValues([
            'kty' => 'oct',
            'k'   => 'foo',
        ]);

        $jws = $signer->addSignatureWithDetachedPayload($jws, $key, $encoded_payload, ['alg' => 'HS256']);
        $jws = $signer->addSignatureWithDetachedPayload($jws, $key, $encoded_payload, ['alg' => 'HS384'], ['foo' => 'bar']);
        $jws = $signer->addSignatureWithDetachedPayload($jws, $key, $encoded_payload, ['alg' => 'HS512'], ['plic' => 'ploc']);
    }
}
