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
 * Class RSAOAEP.
 */
class RSAOAEP extends RSA
{
    /**
     * @return int
     */
    protected function getEncryptionMode()
    {
        return PHPSecLibRSA::ENCRYPTION_OAEP;
    }

    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'sha1';
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'RSA-OAEP';
    }
}
