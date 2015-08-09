<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Test;

/**
 * Class FlattenedTest.
 */
class FlattenedTest extends TestCase
{
    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-39#appendix-A.5
     */
    public function testLoadFlattenedJWE()
    {
        $loader = $this->getLoader();

        $result = $loader->load('{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","unprotected":{"jku":"https://server.example.com/keys.jwks"},"header":{"alg":"A128KW","kid":"7"},"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ","iv":"AxY8DCtDaGlsbGljb3RoZQ","ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","tag":"Mz-VPPyU4RlcuYv1IwIvzw"}');

        $this->assertInstanceOf('Jose\JWEInterface', $result);
        $this->assertEquals('Live long and prosper.', $result->getPayload());
        $this->assertEquals('A128KW', $result->getAlgorithm());
        $this->assertEquals('A128CBC-HS256', $result->getEncryptionAlgorithm());
    }

    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-39#appendix-A.5
     */
    public function testLoadFlattenedJWS()
    {
        $loader = $this->getLoader();

        $result = $loader->load('{"payload":"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ","protected":"eyJhbGciOiJFUzI1NiJ9","header":{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},"signature":"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"}');

        $this->assertInstanceOf("Jose\JWSInterface", $result);
        $this->assertEquals(['iss' => 'joe', 'exp' => 1300819380, 'http://example.com/is_root' => true], $result->getPayload());
        $this->assertEquals('ES256', $result->getAlgorithm());
    }
}
