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
 * Class A128GCM.
 */
class A128GCM extends AESGCM
{
    /**
     * @return int
     */
    protected function getKeySize()
    {
        return 128;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'A128GCM';
    }
}
