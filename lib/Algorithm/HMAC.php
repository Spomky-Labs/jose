<?php

namespace SpomkyLabs\JOSE\Algorithm;

use SpomkyLabs\JOSE\JWKInterface;
use SpomkyLabs\JOSE\JWKSignInterface;
use SpomkyLabs\JOSE\JWKVerifyInterface;

/**
 * This class handles signatures using HMAC.
 * It supports algorithms HS256, HS384 and HS512;
 */
abstract class HMAC implements JWKInterface, JWKSignInterface, JWKVerifyInterface
{
    public function __toString()
    {
        return json_encode($this->getValues());
    }

    public function toPublic()
    {
        return $this->getValues();
    }

    public function isPrivate()
    {
        return $this->getValue('k') !== null;
    }

    public function isPublic()
    {
        return $this->isPrivate();
    }

    /**
     * @inheritdoc
     */
    public function sign($data, array $header = array())
    {
        $key = $this->getValue('k');

        return hash_hmac($this->getHashAlgorithm(), $data, $key);
    }

    /**
     * @inheritdoc
     */
    public function verify($data, $signature, array $header = array())
    {
        return $signature === $this->sign($data);
    }

    protected function getHashAlgorithm()
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
