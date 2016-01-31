<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Factory\DecrypterFactory;
use Jose\Loader;
use Jose\Test\TestCase;

/**
 * Class FlattenedTest.
 *
 * @group Functional
 */
class FlattenedTest extends TestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc7516#appendix-A.5
     */
    public function testLoadFlattenedJWE()
    {
        $decrypter = DecrypterFactory::createDecrypter(['A128KW', 'A128CBC-HS256'], ['DEF'], $this->getCheckers());

        $loaded = Loader::load('{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","unprotected":{"jku":"https://server.example.com/keys.jwks"},"header":{"alg":"A128KW","kid":"7"},"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ","iv":"AxY8DCtDaGlsbGljb3RoZQ","ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","tag":"Mz-VPPyU4RlcuYv1IwIvzw"}');

        $this->assertInstanceOf('Jose\Object\JWEInterface', $loaded);
        $this->assertEquals('A128KW', $loaded->getRecipient(0)->getHeader('alg'));
        $this->assertEquals('A128CBC-HS256', $loaded->getSharedProtectedHeader('enc'));
        $this->assertNull($loaded->getPayload());

        $result = $decrypter->decryptUsingKeySet($loaded, $this->getSymmetricKeySet());

        $this->assertEquals(0, $result);
        $this->assertEquals('Live long and prosper.', $loaded->getPayload());
    }

    /**
     * @see https://tools.ietf.org/html/rfc7516#appendix-A.5
     */
    public function testLoadFlattenedJWS()
    {
        $loaded = Loader::load('{"payload":"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ","protected":"eyJhbGciOiJFUzI1NiJ9","header":{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},"signature":"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"}');

        $this->assertInstanceOf('Jose\Object\JWSInterface', $loaded);
        $this->assertEquals('ES256', $loaded->getSignature(0)->getProtectedHeader('alg'));
        $this->assertEquals(['iss' => 'joe', 'exp' => 1300819380, 'http://example.com/is_root' => true], $loaded->getPayload());
    }
}
