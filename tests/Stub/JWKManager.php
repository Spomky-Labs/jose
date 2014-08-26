<?php

namespace SpomkyLabs\JOSE\Tests\Stub;

use SpomkyLabs\JOSE\JWKManager as Base;
use SpomkyLabs\JOSE\JWKSet;
use SpomkyLabs\JOSE\Util\Base64Url;

/**
 */
class JWKManager extends Base
{
    private $keys = array();

    protected function findJWKByAPV($apv)
    {
        if ('Bob' === Base64Url::decode($apv)) {
            return $this->createJWK(array(
                "kty" =>"EC",
                "crv" =>"P-256",
                "x"   =>"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
                "y"   =>"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
                "d"   =>"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
            ));
        }
        if ('Alice' === Base64Url::decode($apv)) {
            return $this->createJWK(array(
                "kty" =>"EC",
                "crv" =>"P-256",
                "x"   =>"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
                "y"   =>"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
                "d"   =>"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
            ));
        }

        return null;
    }

    protected function findJWKByKid($kid)
    {
        if ($kid === '2010-12-29') {
            return $this->createJWK(array(
                "kty" =>"RSA",
                "n"   =>"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
                "e"   =>"AQAB",
                "d"   =>"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"
            ));
        }

        if ($kid === 'e9bc097a-ce51-4036-9562-d2ade882db0d') {
            return $this->createJWK(array(
                "kty" =>"EC",
                "crv" =>"P-256",
                "x"   =>"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y"   =>"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                "d"   =>"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
            ));
        }

        return isset($this->keys[$kid]) ? $this->keys[$kid] : null;
    }

    public function createJWKSet(array $values = array())
    {
        $key_set = new JWKSet();
        foreach ($values as $value) {
            $key = $this->createJWK($value);
            $key_set->addKey($key);
        }

        return $key_set;
    }

    public function createJWK(array $values)
    {
        if (!isset($values["kty"])) {
            throw new \Exception("'kty' value is missing");
        }
        $class = $this->getClass($values["kty"]);
        $jwk = new $class();
        $jwk->setValues($values);

        return $jwk;
    }

    protected function getSupportedMethods()
    {
        return parent::getSupportedMethods()+array(
            'alg' => 'findJWKByAlgorithm',
            'apv' => 'findJWKByAPV',
        );
    }

    protected function findJWKByAlgorithm($alg)
    {
        if ($alg === "RSA1_5" || $alg === 'RSA-OAEP' || $alg === 'RSA-OAEP-256') {
            return $this->createJWK(array(
                "kty" =>"RSA",
                "alg" =>$alg,
                "n"   =>"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
                "e"   =>"AQAB",
                "d"   =>"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
            ));
        }

        if ($alg === "dir") {
            return $this->createJWK(array(
                "kty" =>"dir",
                "alg" =>$alg,
                "dir" =>'f5aN5V6iihwQVqP-tPNNtkIJNCwUb9-JukCIKkF0rNfxqxA771RJynYAT2xtzAP0MYaR7U5fMP_wvbRQq5l38Q'
            ));
        }

        return null;
    }

    private function getClass($type)
    {
        switch ($type) {
            case 'EC':
                return 'SpomkyLabs\JOSE\Tests\Algorithm\EC';
            case 'RSA':
                return 'SpomkyLabs\JOSE\Tests\Algorithm\RSA';
            case 'none':
                return 'SpomkyLabs\JOSE\Tests\Algorithm\None';
            case 'oct':
                return 'SpomkyLabs\JOSE\Tests\Algorithm\HMAC';
            case 'AES':
                return 'SpomkyLabs\JOSE\Tests\Algorithm\AES';
            case 'dir':
                return 'SpomkyLabs\JOSE\Tests\Algorithm\Dir';
            default:
                throw new \Exception("Unsupported type $type");
        }
    }
}
