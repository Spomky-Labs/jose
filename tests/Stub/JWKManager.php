<?php

namespace SpomkyLabs\JOSE\Tests\Stub;

use SpomkyLabs\JOSE\JWKManager as Base;

/**
 */
class JWKManager extends Base
{
    private $keys = array();

    protected function findJWKByKid($kid)
    {
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
        $type = isset($values['alg']) ? $values['alg'] : (isset($values['enc']) ? $values['enc'] : '');
        $class = $this->getClass($type);
        $jwk = new $class();
        $jwk->setValues($values);

        return $jwk;
    }

    protected function getSupportedMethods()
    {
        return parent::getSupportedMethods()+array(
            'alg' => 'findJWKByAlgorithm'
        );
    }

    protected function findJWKByAlgorithm($alg)
    {
        if ($alg === "RSA1_5" || $alg === 'RSA-OAEP' || $alg === 'RSA-OAEP-256') {
            return $this->createJWK(array(
                "alg" =>$alg,
                "n"   =>"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
                "e"   =>"AQAB",
                "d"   =>"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
            ));
        }

        return null;
    }

    private function getClass($alg)
    {
        switch ($alg) {
            case 'ES256':
            case 'ES384':
            case 'ES512':
                return 'SpomkyLabs\JOSE\Tests\Signature\ECDSA';
            case 'RS256':
            case 'RS384':
            case 'RS512':
            case 'PS256':
            case 'PS384':
            case 'PS512':
                return 'SpomkyLabs\JOSE\Tests\Signature\RSA';
            case 'none':
                return 'SpomkyLabs\JOSE\Tests\Signature\None';
            case 'HS256':
            case 'HS384':
            case 'HS512':
                return 'SpomkyLabs\JOSE\Tests\Signature\Hmac';
            case 'RSA1_5':
            case 'RSA-OAEP':
            case 'RSA-OAEP-256':
                return 'SpomkyLabs\JOSE\Tests\Encryption\RSA';
            case 'A128CBC-HS256':
            case 'A192CBC-HS384':
            case 'A256CBC-HS512':
                return 'SpomkyLabs\JOSE\Tests\Encryption\AES';
            default:
                throw new \Exception("Unsupported algorithm $alg");
        }
    }
}
