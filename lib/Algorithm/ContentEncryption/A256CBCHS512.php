<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

/**
 * Class A256CBCHS512.
 */
class A256CBCHS512 extends AESCBCHS
{
    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'sha512';
    }

    /**
     * @return int
     */
    protected function getKeySize()
    {
        return 512;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'A256CBC-HS512';
    }
}
