<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use AESKW\A128KW as Wrapper;

/**
 * Class PBES2HS256A128KW.
 */
class PBES2HS256A128KW extends PBES2AESKW
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
        return 'sha256';
    }

    /**
     * @return float
     */
    protected function getKeySize()
    {
        return 128 / 8;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'PBES2-HS256+A128KW';
    }
}
