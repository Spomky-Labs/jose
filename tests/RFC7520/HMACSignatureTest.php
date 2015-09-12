<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Test\RFC7520;

use Base64Url\Base64Url;
use Jose\JSONSerializationModes;
use SpomkyLabs\Jose\Algorithm\Signature\HS256;
use SpomkyLabs\Jose\JWK;
use SpomkyLabs\Jose\Util\Converter;

/**
 * @see https://tools.ietf.org/html/rfc7520#section-4.4
 *
 * @group HMAC
 */
class HMACSignatureTest extends \PHPUnit_Framework_TestCase
{
    /**
     *
     */
    public function testES512Verify()
    {
        $key = new JWK();

        /*
         * Symmetric Key
         * @see https://tools.ietf.org/html/rfc7520#section-3.5
         */
        $key->setValues([
            'kty' => 'oct',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
            'use' => 'sig',
            'alg' => 'HS256',
            'k'   => 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg',
        ]);

        $header = 'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9';
        $payload = 'SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4';
        $expected_signature = 's0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0';

        $hs256 = new HS256();
        $this->assertEquals($expected_signature, Base64Url::encode($hs256->sign($key, $header.'.'.$payload)));
        $this->assertTrue($hs256->verify($key, $header.'.'.$payload, Base64Url::decode($expected_signature)));
    }

    /**
     *
     */
    public function testES512VerifyWithDetachedPayload()
    {
        $key = new JWK();

        /*
         * Symmetric Key
         * @see https://tools.ietf.org/html/rfc7520#section-3.5
         */
        $key->setValues([
            'kty' => 'oct',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
            'use' => 'sig',
            'alg' => 'HS256',
            'k'   => 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg',
        ]);

        $header = 'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9';
        $payload = 'SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4';
        $expected_signature = 's0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0';

        $hs256 = new HS256();
        $this->assertEquals($expected_signature, Base64Url::encode($hs256->sign($key, $header.'.'.$payload)));
        $this->assertTrue($hs256->verify($key, $header.'.'.$payload, Base64Url::decode($expected_signature)));
    }

    /**
     * @see https://tools.ietf.org/html/rfc7520#section-4.4.3
     */
    public function testConversion()
    {
        $header = 'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9';
        $payload = 'SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4';
        $signature = 's0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0';

        /*
         * Figure 35
         */
        $compact_serialization = $header.'.'.$payload.'.'.$signature;

        /*
         * Figure 35
         */
        $expected_general_serialization = [
            'payload'    => 'SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4',
            'signatures' => [
               [
                   'protected'  => 'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9',
                    'signature' => 's0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0',
               ],
            ],
        ];

        /*
         * Figure 36
         */
        $expected_flattened_serialization = [
            'payload'   => 'SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4',
            'protected' => 'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9',
            'signature' => 's0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0',
        ];

        $this->assertEquals($expected_general_serialization, Converter::convert($compact_serialization, JSONSerializationModes::JSON_SERIALIZATION, false));
        $this->assertEquals($expected_flattened_serialization, Converter::convert($compact_serialization, JSONSerializationModes::JSON_FLATTENED_SERIALIZATION, false));
        $this->assertEquals($compact_serialization, Converter::convert($expected_flattened_serialization, JSONSerializationModes::JSON_COMPACT_SERIALIZATION));
    }

    /**
     * @see https://tools.ietf.org/html/rfc7520#section-4.5.3
     */
    public function testConversionWithDetachedPayload()
    {
        $header = 'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9';
        $payload = '';
        $signature = 's0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0';

        /*
         * Figure 35
         */
        $compact_serialization = $header.'.'.$payload.'.'.$signature;

        /*
         * Figure 35
         */
        $expected_general_serialization = [
            'signatures' => [
               [
                   'protected'  => 'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9',
                    'signature' => 's0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0',
               ],
            ],
        ];

        /*
         * Figure 36
         */
        $expected_flattened_serialization = [
            'protected' => 'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9',
            'signature' => 's0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0',
        ];

        $this->assertEquals($expected_general_serialization, Converter::convert($compact_serialization, JSONSerializationModes::JSON_SERIALIZATION, false));
        $this->assertEquals($expected_flattened_serialization, Converter::convert($compact_serialization, JSONSerializationModes::JSON_FLATTENED_SERIALIZATION, false));
        $this->assertEquals($compact_serialization, Converter::convert($expected_flattened_serialization, JSONSerializationModes::JSON_COMPACT_SERIALIZATION));
    }
}
