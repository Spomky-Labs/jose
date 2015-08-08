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

/**
 * Class A192GCMKW.
 */
class A192GCMKW extends AESGCMKW
{
    /**
     * @return int
     */
    protected function getKeySize()
    {
        return 192;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'A192GCMKW';
    }
}
