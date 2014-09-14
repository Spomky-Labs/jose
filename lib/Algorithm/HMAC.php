<?php

namespace SpomkyLabs\JOSE\Algorithm;

use SpomkyLabs\JOSE\JWKInterface;

/**
 * This class handles signatures using HMAC.
 * It supports algorithms HS256, HS384 and HS512;
 */
abstract class HMAC implements JWKInterface, SignatureInterface, VerificationInterface
{
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

        return hash_hmac($this->getHashAlgorithm($header), $data, $key);
    }

    /**
     * @inheritdoc
     */
    public function verify($data, $signature, array $header = array())
    {
        return $signature === $this->sign($data, $header);
    }

    protected function getAlgorithm($header)
    {
        if (isset($header['alg']) && $header['alg'] !== null) {
            return $header['alg'];
        }

        return $this->getValue('alg');
    }

    protected function getHashAlgorithm($header)
    {
        $alg = $this->getAlgorithm($header);
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
