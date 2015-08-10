<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\Algorithm\Signature;

use Mdanter\Ecc\EccFactory;

/**
 */
class ES256 extends ECDSA
{
    /**
     * @return \Mdanter\Ecc\Primitives\CurveFp
     */
    protected function getCurve()
    {
        return EccFactory::getNistCurves()->curve256();
    }

    /**
     * @return \Mdanter\Ecc\Primitives\GeneratorPoint
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
        return 'sha256';
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
        return 'ES256';
    }
}
