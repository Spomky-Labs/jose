<?php

namespace SpomkyLabs\JOSE;

/**
 */
abstract class JWKManager implements JWKManagerInterface
{
    public function findJWKByHeader(array $header)
    {
        foreach ($this->getSupportedMethods() as $key => $method) {
            if (isset($header[$key])) {
                $result = $this->$method($header[$key]);
                if (null !== $result) {
                    return $result;
                }
            }
        }

        return null;
    }

    protected function getSupportedMethods()
    {
        return array(
            'kid' => 'findJWKByKid',
            'jwk' => 'findJWKByJWK'
        );
    }

    abstract protected function findJWKByKid($kid);

    protected function findJWKByJWK(array $values)
    {
        return $this->createJWK($values);
    }

    public static function canEncrypt(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "enc", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "enc") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "encrypt", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && strpos($key_ops, "encrypt") === -1) {
            return false;
        }

        //If the JWK does not implement JWKEncryptInterface, we can not use it
        return $jwk instanceof JWKEncryptInterface;
    }

    public static function canDecrypt(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "enc", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "enc") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "decrypt", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && strpos($key_ops, "decrypt") === -1) {
            return false;
        }

        //If the JWK does not implement JWKDecryptInterface, we can not use it
        return $jwk instanceof JWKDecryptInterface;
    }

    public static function canSign(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "sig", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "sig") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "sign", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && strpos($key_ops, "sign") === -1) {
            return false;
        }

        //If the JWK does not implement JWKSignInterface, we can not use it
        return $jwk instanceof JWKSignInterface;
    }

    public static function canVerify(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "sig", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "sig") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "verify", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && strpos($key_ops, "verify") === -1) {
            return false;
        }

        //If the JWK does not implement JWKVerifyInterface, we can not use it
        return $jwk instanceof JWKVerifyInterface;
    }

    public function getType($value)
    {
        switch ($value) {
            case 'ES256':
            case 'ES384':
            case 'ES512':
            case 'ECDH-ES':
                return 'EC';
            case 'RS256':
            case 'RS384':
            case 'RS512':
            case 'PS256':
            case 'PS384':
            case 'PS512':
            case 'RSA1_5':
            case 'RSA-OAEP':
            case 'RSA-OAEP-256':
                return 'RSA';
            case 'none':
                return 'None';
            case 'HS256':
            case 'HS384':
            case 'HS512':
                return 'HMAC';
            case 'A128CBC-HS256':
            case 'A192CBC-HS384':
            case 'A256CBC-HS512':
                return 'AES';
            case 'dir':
                return 'Dir';
            default:
                throw new \Exception("Unsupported algorithm '$value'");
        }
    }
}
