<?php

namespace SpomkyLabs\JOSE\Algorithm\Signature;

use Mdanter\Ecc\EccFactory;

/**
 */
class ES512 extends ECDSA
{
    protected function getCurve()
    {
        return EccFactory::getNistCurves()->curve521();
    }

    protected function getGenerator()
    {
        return EccFactory::getNistCurves()->generator521();
    }

    protected function getHashAlgorithm()
    {
        return 'SHA512';
    }

    protected function getSignaturePartLength()
    {
        return 132;
    }

    public function getAlgorithmName()
    {
        return "ES512";
    }
}
