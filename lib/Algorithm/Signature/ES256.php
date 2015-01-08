<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

use Mdanter\Ecc\EccFactory;

/**
 */
class ES256 extends ECDSA
{
    protected function getCurve()
    {
        return EccFactory::getNistCurves()->curve256();
    }

    protected function getGenerator()
    {
        return EccFactory::getNistCurves()->generator256();
    }

    protected function getHashAlgorithm()
    {
        return 'SHA256';
    }

    protected function getSignaturePartLength()
    {
        return 64;
    }

    public function getAlgorithmName()
    {
        return "ES256";
    }
}
