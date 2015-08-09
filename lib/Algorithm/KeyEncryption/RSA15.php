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

use phpseclib\Crypt\RSA as PHPSecLibRSA;

/**
 * Class RSA15.
 */
class RSA15 extends RSA
{
    /**
     * @return int
     */
    protected function getEncryptionMode()
    {
        return PHPSecLibRSA::ENCRYPTION_PKCS1;
    }

    /**
     *
     */
    protected function getHashAlgorithm()
    {
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'RSA1_5';
    }
}
