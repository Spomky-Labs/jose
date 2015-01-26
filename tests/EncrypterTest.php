<?php

namespace SpomkyLabs\Jose\Tests;

use SpomkyLabs\Jose\JWK;
use SpomkyLabs\Jose\EncryptionInstruction;
use Jose\JSONSerializationModes;

class EncrypterTest extends TestCase
{
    public function testEncryptAndLoadCompact()
    {
        $encrypter = $this->getEncrypter();
        $loader = $this->getLoader();

        $instruction = new EncryptionInstruction();
        $instruction->setRecipientPublicKey($this->getRecipientKey());

        $encrypted = $encrypter->encrypt($this->getKeyToEncrypt(), array($instruction), array("kid" => "123456789", "enc" => "A128GCM", "alg" => "RSA-OAEP-256", "zip" => "DEF"), array(), JSONSerializationModes::JSON_FLATTENED_SERIALIZATION);

        $loaded = $loader->load($encrypted);

        $this->assertInstanceOf("Jose\JWEInterface", $loaded);
        $this->assertInstanceOf("Jose\JWKInterface", $loaded->getPayload());
        $this->assertEquals("RSA-OAEP-256", $loaded->getAlgorithm());
        $this->assertEquals("A128GCM", $loaded->getEncryptionAlgorithm());
        $this->assertEquals("DEF", $loaded->getZip());
    }

    protected function getKeyToEncrypt()
    {
        $key = new JWK();
        $key->setValues(array(
            "kty" => "EC",
            "crv" => "P-256",
            "x" => "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y" => "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "d" => "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
        ));

        return $key;
    }

    protected function getRecipientKey()
    {
        $key = new JWK();
        $key->setValues(array(
            "kty" => "RSA",
            'n' => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e' => 'AQAB',
        ));

        return $key;
    }
}
