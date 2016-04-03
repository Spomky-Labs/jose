<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

use Jose\Object\JWEInterface;
use Psr\Log\LoggerInterface;

/**
 * Encrypter Interface.
 */
interface EncrypterInterface
{
    /**
     * @param string[]|\Jose\Algorithm\JWAInterface[]           $key_encryption_algorithms
     * @param string[]|\Jose\Algorithm\JWAInterface[]           $content_encryption_algorithms
     * @param string[]|\Jose\Compression\CompressionInterface[] $compression_methods
     * @param \Psr\Log\LoggerInterface|null                     $logger
     *
     * @return \Jose\DecrypterInterface
     */
    public static function createEncrypter(array $key_encryption_algorithms, array $content_encryption_algorithms, array $compression_methods = ['DEF', 'ZLIB', 'GZ'], LoggerInterface $logger = null);

    /**
     * @return string[]
     */
    public function getSupportedKeyEncryptionAlgorithms();

    /**
     * @return string[]
     */
    public function getSupportedContentEncryptionAlgorithms();

    /**
     * @return string[]
     */
    public function getSupportedCompressionMethods();
    
    /**
     * @param \Jose\Object\JWEInterface $jwe
     */
    public function encrypt(JWEInterface &$jwe);
}
