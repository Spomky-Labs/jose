<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

/**
 * Class A192CBCHS384.
 */
class A192CBCHS384 extends AESCBCHS
{
    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'sha384';
    }

    /**
     * @return int
     */
    protected function getKeySize()
    {
        return 384;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'A192CBC-HS384';
    }
}
