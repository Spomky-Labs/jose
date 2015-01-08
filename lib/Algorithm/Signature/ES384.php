<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

use Mdanter\Ecc\EccFactory;

/**
 */
class ES384 extends ECDSA
{
    protected function getCurve()
    {
        return EccFactory::getNistCurves()->curve384();
    }

    protected function getGenerator()
    {
        return EccFactory::getNistCurves()->generator384();
    }

    protected function getHashAlgorithm()
    {
        return 'SHA384';
    }

    protected function getSignaturePartLength()
    {
        return 96;
    }

    public function getAlgorithmName()
    {
        return "ES384";
    }
}
