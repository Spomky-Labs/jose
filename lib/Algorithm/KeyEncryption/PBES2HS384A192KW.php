<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use AESKW\A192KW as Wrapper;

/**
 * Class PBES2HS384A192KW.
 */
class PBES2HS384A192KW extends PBES2AESKW
{
    /**
     * @return Wrapper
     */
    protected function getWrapper()
    {
        return new Wrapper();
    }

    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'sha384';
    }

    /**
     * @return float
     */
    protected function getKeySize()
    {
        return 192 / 8;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'PBES2-HS384+A192KW';
    }
}
