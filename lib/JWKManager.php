<?php

namespace SpomkyLabs\JOSE;

/**
 */
abstract class JWKManager implements JWKManagerInterface
{
    public function findJWKSetByHeader(array $header)
    {
        $key_set = $this->createJWKSet();
        foreach ($this->getSupportedMethods() as $key => $method) {
            if (isset($header[$key])) {
                $result = $this->$method($header[$key]);
                if (null !== $result) {
                    $key_set->addKey($result);
                }
            }
        }

        return $key_set;
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
}
