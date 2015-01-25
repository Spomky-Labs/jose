<?php

namespace SpomkyLabs\Jose\Tests;

use SpomkyLabs\Jose\JWK;
use SpomkyLabs\Jose\JWKSet;
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

        $encrypted = $encrypter->encrypt($this->getKeyToEncrypt(), array($instruction), array("enc"=>"A128GCM"), array("zip"=>"DEF"));
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
            "n" => "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
            "e" => "AQAB",
        ));

        return $key;
    }
}
