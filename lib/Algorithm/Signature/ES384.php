<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

use Mdanter\Ecc\EccFactory;

/**
 */
class ES384 extends ECDSA
{
    /**
     * @return \Mdanter\Ecc\CurveFp
     */
    protected function getCurve()
    {
        return EccFactory::getNistCurves()->curve384();
    }

    /**
     * @return \Mdanter\Ecc\GeneratorPoint
     */
    protected function getGenerator()
    {
        return EccFactory::getNistCurves()->generator384();
    }

    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'SHA384';
    }

    /**
     * @return int
     */
    protected function getSignaturePartLength()
    {
        return 96;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'ES384';
    }
}
