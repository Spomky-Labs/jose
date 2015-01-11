<?php

namespace SpomkyLabs\Jose\Tests\Stub;

use SpomkyLabs\Jose\JWK;
use SpomkyLabs\Jose\JWKSet;
use SpomkyLabs\Jose\JWKManager as Base;
use SpomkyLabs\Jose\Util\Base64Url;

/**
 */
class JWKManager extends Base
{
    /**
     * {@inheritdoc}
     */
    public function createJWK(array $values = array())
    {
        $jwk = new JWK();
        $jwk->setValues($values);

        return $jwk;
    }

    /**
     * {@inheritdoc}
     */
    public function createJWKSet(array $values = array())
    {
        $key_set = new JWKSet();
        foreach ($values as $value) {
            $key = $this->createJWK($value);
            $key_set->addKey($key);
        }

        return $key_set;
    }

    protected function findByAPV($header)
    {
        if (!isset($header['apv'])) {
            return;
        }

        if ('Bob' === Base64Url::decode($header['apv'])) {
            return $this->createJWK(array(
                "kty" => "EC",
                "crv" => "P-256",
                "x"   => "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
                "y"   => "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
                "d"   => "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
            ));
        }
        if ('Alice' === Base64Url::decode($header['apv'])) {
            return $this->createJWK(array(
                "kty" => "EC",
                "crv" => "P-256",
                "x"   => "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
                "y"   => "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
                "d"   => "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo",
            ));
        }
    }

    protected function findByKid($header)
    {
        if (!isset($header['kid'])) {
            return;
        }
        switch ($header['kid']) {
            case '2010-12-29':
                return $this->createJWK(array(
                    "kty" => "RSA",
                    "n"   => "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
                    "e"   => "AQAB",
                    "d"   => "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
                ));

            case 'e9bc097a-ce51-4036-9562-d2ade882db0d':
                return $this->createJWK(array(
                    "kty" => "EC",
                    "crv" => "P-256",
                    "x"   => "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y"   => "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                    "d"   => "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
                ));

            case '123456789':
                return $this->createJWK(array(
                    "kty" => "RSA",
                    'n' => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
                    'e' => 'AQAB',
                    'p' => '5BGU1c7af_5sFyfsa-onIJgo5BZu8uHvz3Uyb8OA0a-G9UPO1ShLYjX0wUfhZcFB7fwPtgmmYAN6wKGVce9eMAbX4PliPk3r-BcpZuPKkuLk_wFvgWAQ5Hqw2iEuwXLV0_e8c2gaUt_hyMC5-nFc4v0Bmv6NT6Pfry-UrK3BKWc',
                    'd' => 'Kp0KuZwCZGL1BLgsVM-N0edMNitl9wN5Hf2WOYDoIqOZNAEKzdJuenIMhITJjRFUX05GVL138uyp2js_pqDdY9ipA7rAKThwGuDdNphZHech9ih3DGEPXs-YpmHqvIbCd3GoGm38MKwxYkddEpFnjo8rKna1_BpJthrFxjDRhw9DxJBycOdH2yWTyp62ZENPvneK40H2a57W4QScTgfecZqD59m2fGUaWaX5uUmIxaEmtGoJnd9RE4oywKhgN7_TK7wXRlqA4UoRPiH2ACrdU-_cLQL9Jc0u0GqZJK31LDbOeN95QgtSCc72k3Vtzy3CrVpp5TAA67s1Gj9Skn-CAQ',
                    'q' => 'zPD-B-nrngwF-O99BHvb47XGKR7ON8JCI6JxavzIkusMXCB8rMyYW8zLs68L8JLAzWZ34oMq0FPUnysBxc5nTF8Nb4BZxTZ5-9cHfoKrYTI3YWsmVW2FpCJFEjMs4NXZ28PBkS9b4zjfS2KhNdkmCeOYU0tJpNfwmOTI90qeUdU',
                    'dp' => 'aJrzw_kjWK9uDlTeaES2e4muv6bWbopYfrPHVWG7NPGoGdhnBnd70-jhgMEiTZSNU8VXw2u7prAR3kZ-kAp1DdwlqedYOzFsOJcPA0UZhbORyrBy30kbll_7u6CanFm6X4VyJxCpejd7jKNw6cCTFP1sfhWg5NVJ5EUTkPwE66M',
                    'dq' => 'Swz1-m_vmTFN_pu1bK7vF7S5nNVrL4A0OFiEsGliCmuJWzOKdL14DiYxctvnw3H6qT2dKZZfV2tbse5N9-JecdldUjfuqAoLIe7dD7dKi42YOlTC9QXmqvTh1ohnJu8pmRFXEZQGUm_BVhoIb2_WPkjav6YSkguCUHt4HRd2YwE',
                    'qi' => 'BocuCOEOq-oyLDALwzMXU8gOf3IL1Q1_BWwsdoANoh6i179psxgE4JXToWcpXZQQqub8ngwE6uR9fpd3m6N_PL4T55vbDDyjPKmrL2ttC2gOtx9KrpPh-Z7LQRo4BE48nHJJrystKHfFlaH2G7JxHNgMBYVADyttN09qEoav8Os',
                ));

            case '71ee230371d19630bc17fb90ccf20ae632ad8cf8':
                return $this->createJWK(array(
                    "kty" => "RSA",
                    "alg" => "RS256",
                    "use" => "sig",
                    "kid" => "71ee230371d19630bc17fb90ccf20ae632ad8cf8",
                    "n"   => "vnMTRCMvsS04M1yaKR112aB8RxOkWHFixZO68wCRlVLxK4ugckXVD_Ebcq-kms1T2XpoWntVfBuX40r2GvcD9UsTFt_MZlgd1xyGwGV6U_tfQUll5mKxCPjr60h83LXKJ_zmLXIqkV8tAoIg78a5VRWoms_0Bn09DKT3-RBWFjk=",
                    "e"   => "AQAB",
                ));

            case '02491f945c951adf156f370788e8ccdabf8877a8':
                return $this->createJWK(array(
                    "kty" => "RSA",
                    "alg" => "RS256",
                    "use" => "sig",
                    "kid" => "02491f945c951adf156f370788e8ccdabf8877a8",
                    "n"   => "rI67uHIDWDgCy_Ut-FhhjTCkEcqzoO80IRgdpk_fJHlDmXhMTJKPizxbIEMs0wRHRZpwH-4D20thpnQB5Mgx6-XM9kOvcYpHSdcYME77BwX6uQG-hw2w77NOhYiCSZCLzx-5ld5Wjy0dympL-ExqQw-wrWipMX7NQhIbJqVbZ18=",
                    "e"   => "AQAB",
                ));
        }
    }

    protected function getSupportedMethods()
    {
        return array_merge(
            parent::getSupportedMethods(),
            array(
                'findByKid',
                'findByAPV',
                'findByAlgorithm',
                'findByJku',
            )
        );
    }

    protected function findByJku($header)
    {
        if (!isset($header['jku'])) {
            return;
        }
        if ("https://server.example.com/keys.jwks" === $header['jku']) {
            return $this->createJWK(array(
                "kty" => "oct",
                "k"   => "GawgguFyGrWKav7AX4VKUg",
            ));
        }
    }

    protected function findByAlgorithm($header)
    {
        if (!isset($header['alg'])) {
            return;
        }
        $alg = $header['alg'];
        if ($alg === "RSA1_5" || $alg === 'RSA-OAEP' || $alg === 'RSA-OAEP-256') {
            return $this->createJWK(array(
                "kty" => "RSA",
                "n"   => "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
                "e"   => "AQAB",
                "d"   => "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
            ));
        }

        if ($alg === "dir") {
            return $this->createJWK(array(
                "kty" => "dir",
                "dir" => 'f5aN5V6iihwQVqP-tPNNtkIJNCwUb9-JukCIKkF0rNfxqxA771RJynYAT2xtzAP0MYaR7U5fMP_wvbRQq5l38Q',
            ));
        }
    }

    private function convertArrayToBinString(array $data)
    {
        foreach ($data as $key => $value) {
            $data[$key] = str_pad(dechex($value), 2, "0", STR_PAD_LEFT);
        }

        return hex2bin(implode("", $data));
    }
}
