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

use Jose\Object\JWSInterface;
use Psr\Log\LoggerInterface;

/**
 * Signer Interface.
 */
interface SignerInterface
{
    /**
     * Signer constructor.
     *
     * @param string[]|\Jose\Algorithm\SignatureAlgorithmInterface[] $signature_algorithms
     * @param \Psr\Log\LoggerInterface|null                          $logger
     *
     * @return \Jose\SignerInterface
     */
    public static function createSigner(array $signature_algorithms, LoggerInterface $logger = null);

    /**
     * @return string[]
     */
    public function getSupportedSignatureAlgorithms();

    /**
     * @param \Jose\Object\JWSInterface $jws
     */
    public function sign(JWSInterface &$jws);
}
