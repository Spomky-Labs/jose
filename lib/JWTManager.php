<?php

namespace SpomkyLabs\JOSE;

use SpomkyLabs\JOSE\Base64Url;
use SpomkyLabs\JOSE\JWTManagerInterface;
use SpomkyLabs\JOSE\JWTInterface;
use SpomkyLabs\JOSE\JWKInterface;
use SpomkyLabs\JOSE\JWKSetInterface;
use SpomkyLabs\JOSE\JWKDecryptInterface;
use SpomkyLabs\JOSE\JWKEncryptInterface;
use SpomkyLabs\JOSE\JWKVerifyInterface;
use SpomkyLabs\JOSE\JWKSignInterface;

/**
 * Class representing a JSON Web Token Manager.
 */
abstract class JWTManager implements JWTManagerInterface
{
    abstract protected function getKeyManager();

    public function load($data)
    {
        //We try to identity if the data is a JSON object. In this case, we consider that data is a JWE or JWS Seralization object
        if(json_decode($data,true) !== null)
        {
            return $this->loadSerializedJson($data);
        }

        //Else, we consider that data is a JWE or JWS Compact Seralized object
        return $this->loadCompactSerializedJson($data);
    }

    public static function convertToCompactSerializedJson(JWTInterface $jwt, JWKInterface $jwk)
    {
        if(!$jwk->isPrivate())
        {
            throw new \Exception("The key is not a private key");
        }

        $header = Base64Url::encode(json_encode($jwt->getHeader()));
        $payload = Base64Url::encode(json_encode($jwt->getPayload()));

        //We try to encrypt first
        if(self::canEncrypt($jwk))
        {
            throw new \Exception('Not implemented');
        }
        //Then we try to sign
        if(self::canSign($jwk))
        {
            $signature = $jwk->sign($header.".".$payload);
            return $header.".".$payload.".".$signature;
        }
        throw new \Exception("The key can not sign or encrypt data");
    }

    public static function convertToSerializedJson(JWTInterface $jwt, JWKSetInterface $jwk_set)
    {
        throw new \Exception('Not implemented');
    }

    private function loadSerializedJson($data)
    {
        throw new \Exception('Not implemented');
    }

    private function loadCompactSerializedJson($data)
    {
        $parts = explode('.', $data);

        switch (count($parts)) {
            case 3:
                return $this->loadCompactSerializedJWS($parts);
            case 5:
                return $this->loadCompactSerializedJWE($parts);
            default:
                throw new \InvalidArgumentException('Unable to load data');
        }
    }

    private function loadCompactSerializedJWE($parts)
    {
        throw new \Exception('Not implemented');
    }

    private function loadCompactSerializedJWS($parts)
    {
        $header     = json_decode(Base64Url::decode($parts[0]), true);
        $payload    = json_decode(Base64Url::decode($parts[1]), true);

        $key_set = $this->getKeyManager()->findJWKSetByHeader($header);

        if($key_set->isEmpty())
        {
            throw new \Exception('Unable to find the key used for this token');
        }

        foreach ($key_set->getKeys() as $key) {
            if(self::canVerify($key) && $key->verify($parts[0].".".$parts[1], $parts[2]) === true)
            {
                $jwt = $this->createJWT();
                $jwt->setHeader($header);
                $jwt->setPayload($payload);

                return $jwt;
            }
        }
        throw new \InvalidArgumentException('Invalid signature or unable to find the key used for this token');
    }

    private static function canEncrypt(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "enc", we can not use it
        $use = $jwk->getValue('use');
        if($use !== null && $use !== "enc") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "encrypt", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if($key_ops !== null && strpos($key_ops, "encrypt") === -1) {
            return false;
        }

        //If the JWK does not implement JWKEncryptInterface, we can not use it
        return $jwk instanceof JWKEncryptInterface;
    }

    private static function canDecrypt(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "enc", we can not use it
        $use = $jwk->getValue('use');
        if($use !== null && $use !== "enc") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "decrypt", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if($key_ops !== null && strpos($key_ops, "decrypt") === -1) {
            return false;
        }

        //If the JWK does not implement JWKDeryptInterface, we can not use it
        return $jwk instanceof JWKDeryptInterface;
    }

    private static function canSign(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "sig", we can not use it
        $use = $jwk->getValue('use');
        if($use !== null && $use !== "sig") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "sign", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if($key_ops !== null && strpos($key_ops, "sign") === -1) {
            return false;
        }

        //If the JWK does not implement JWKSignInterface, we can not use it
        return $jwk instanceof JWKSignInterface;
    }

    private static function canVerify(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "sig", we can not use it
        $use = $jwk->getValue('use');
        if($use !== null && $use !== "sig") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "verify", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if($key_ops !== null && strpos($key_ops, "verify") === -1) {
            return false;
        }

        //If the JWK does not implement JWKVerifyInterface, we can not use it
        return $jwk instanceof JWKVerifyInterface;
    }
}
