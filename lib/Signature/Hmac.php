<?php

namespace SpomkyLabs\JOSE\Signature;

use SpomkyLabs\JOSE\JWKInterface;
use SpomkyLabs\JOSE\JWKSignInterface;
use SpomkyLabs\JOSE\JWKVerifyInterface;

/**
 * This class handles signatures using HMAC.
 * It supports algorithms HS256, HS384 and HS512;
 */
abstract class Hmac implements JWKInterface, JWKSignInterface, JWKVerifyInterface
{
    public function toPrivate()
    {
        return parent::toArray()+array(
            'kty' => 'oct',
        );
    }

    public function toPublic()
    {
        return $this->toPrivate();
    }

    public function isPrivate()
    {
        return $this->getValue('k') !== null;
    }

    /**
     * @inheritdoc
     */
    public function sign($data)
    {
        $key = $this->getValue('k');

        return hash_hmac($this->getHashAlgorithm(), $data, $key);
    }

    /**
     * @inheritdoc
     */
    public function verify($data, $signature)
    {
        return $signature === $this->sign($data);
    }

    private function getHashAlgorithm()
    {
        $alg = $this->getValue('alg');
        switch ($alg) {
            case 'HS256':
                return 'sha256';
            case 'HS384':
                return 'sha384';
            case 'HS512':
                return 'sha512';
            default:
                throw new \Exception("Algorithm $alg is not supported");
        }
    }
}
