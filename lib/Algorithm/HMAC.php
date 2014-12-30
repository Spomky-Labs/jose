<?php

namespace SpomkyLabs\JOSE\Algorithm;

use Jose\JWK;
use Jose\JWKInterface;
use Jose\KeyOperation\SignatureInterface;
use Jose\KeyOperation\VerificationInterface;

/**
 * This class handles signatures using HMAC.
 * It supports algorithms HS256, HS384 and HS512;
 */
class HMAC implements JWKInterface, SignatureInterface, VerificationInterface
{
    use JWK;

    protected $values = array('kty' => 'oct');

    public function getValue($key)
    {
        return array_key_exists($key, $this->getValues()) ? $this->values[$key] : null;
    }

    public function getValues()
    {
        return $this->values;
    }

    public function setValue($key, $value)
    {
        $this->values[$key] = $value;

        return $this;
    }

    public function setValues(array $values)
    {
        $this->values = $values;

        return $this;
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

        return hash_hmac($this->getHashAlgorithm($header), $data, $key);
    }

    /**
     * @inheritdoc
     */
    public function verify($data, $signature, array $header = array())
    {
        return $signature === $this->sign($data, $header);
    }

    protected function getHashAlgorithm($header)
    {
        $alg = $this->getAlgorithm();
        if (null === $alg && isset($header['alg'])) {
            $alg = $header['alg'];
        }
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
