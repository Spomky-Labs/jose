<?php

namespace SpomkyLabs\Jose\Tests;

use SpomkyLabs\Jose\JWK;
use SpomkyLabs\Jose\JWKSet;
use Jose\JSONSerializationModes;

class SignerTest extends TestCase
{
    public function testSignAndLoadCompact()
    {
        $signer = $this->getSigner();
        $loader = $this->getLoader();

        $keyset = $this->getKeyset();
        $input = $this->getJWK();

        $signatures = $signer->sign($input, $keyset, JSONSerializationModes::JSON_COMPACT_SERIALIZATION);

        $this->assertTrue(is_array($signatures));
        $this->assertEquals(2, count($signatures));

        $this->assertTrue(is_string($signatures[0]));
        $this->assertTrue(is_string($signatures[1]));

        $loaded1 = $loader->load($signatures[0]);
        $loaded2 = $loader->load($signatures[1]);

        $this->assertInstanceOf("Jose\JWSInterface", $loaded1);
        $this->assertInstanceOf("Jose\JWKInterface", $loaded1->getPayload());
        $this->assertEquals("HS512", $loaded1->getAlgorithm());

        $this->assertInstanceOf("Jose\JWSInterface", $loaded2);
        $this->assertInstanceOf("Jose\JWKInterface", $loaded2->getPayload());
        $this->assertEquals("RS512", $loaded2->getAlgorithm());
    }

    public function testSignAndLoadFlattened()
    {
        $signer = $this->getSigner();
        $loader = $this->getLoader();

        $keyset = $this->getKeyset();

        $signatures = $signer->sign($keyset, $keyset, JSONSerializationModes::JSON_FLATTENED_SERIALIZATION);

        $this->assertTrue(is_array($signatures));
        $this->assertEquals(2, count($signatures));

        $this->assertTrue(is_string($signatures[0]));
        $this->assertTrue(is_string($signatures[1]));

        $loaded1 = $loader->load($signatures[0]);
        $loaded2 = $loader->load($signatures[1]);

        $this->assertInstanceOf("Jose\JWSInterface", $loaded1);
        $this->assertInstanceOf("Jose\JWKSetInterface", $loaded1->getPayload());
        $this->assertEquals("HS512", $loaded1->getAlgorithm());

        $this->assertInstanceOf("Jose\JWSInterface", $loaded2);
        $this->assertInstanceOf("Jose\JWKSetInterface", $loaded2->getPayload());
        $this->assertEquals("RS512", $loaded2->getAlgorithm());
    }

    public function testSignAndLoad()
    {
        $signer = $this->getSigner();
        $loader = $this->getLoader();

        $keyset = $this->getKeyset();

        $signatures = $signer->sign($keyset, $keyset, JSONSerializationModes::JSON_SERIALIZATION);

        $this->assertTrue(is_string($signatures));

        $loaded = $loader->load($signatures);

        $this->assertInstanceOf("Jose\JWSInterface", $loaded);
        $this->assertInstanceOf("Jose\JWKSetInterface", $loaded->getPayload());
        $this->assertEquals("HS512", $loaded->getAlgorithm());
    }

    protected function getKeyset()
    {
        $key1 = new JWK();
        $key1->setValues(array(
            "kty" => "oct",
            "alg" => "HS512",
            "k"   => "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
        ));

        $key2 = new JWK();
        $key2->setValues(array(
            "kty" => "RSA",
            "alg" => "RS512",
            "n" => "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
            "e" => "AQAB",
            "d" => "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
            "p" => "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
            "q" => "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
            "dp" => "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
            "dq" => "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
            "qi" => "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U",
        ));

        $keyset = new JWKSet();
        $keyset->addKey($key1)
               ->addKey($key2);

        return $keyset;
    }

    protected function getJWK()
    {
        $input = new JWK();
        $input->setValues(array(
            "kty" => "EC",
            "crv" => "P-256",
            "x" => "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y" => "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "d" => "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
        ));

        return $input;
    }
}
