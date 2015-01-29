<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

use Mdanter\Ecc\EccFactory;

/**
 */
class ES256 extends ECDSA
{
    /**
     * @return \Mdanter\Ecc\CurveFp
     */
    protected function getCurve()
    {
        return EccFactory::getNistCurves()->curve256();
    }

    /**
     * @return \Mdanter\Ecc\GeneratorPoint
     */
    protected function getGenerator()
    {
        return EccFactory::getNistCurves()->generator256();
    }

    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'SHA256';
    }

    /**
     * @return int
     */
    protected function getSignaturePartLength()
    {
        return 64;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return "ES256";
    }
}
