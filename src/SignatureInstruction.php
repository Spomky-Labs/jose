<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

use Jose\JWKInterface;
use Jose\SignatureInstructionInterface;

/**
 * Class SignatureInstruction.
 */
class SignatureInstruction implements SignatureInstructionInterface
{
    /**
     * @var null|\Jose\JWKInterface
     */
    protected $key = null;
    /**
     * @var array
     */
    protected $protected_header = [];
    /**
     * @var array
     */
    protected $unprotected_header = [];

    /**
     * @param JWKInterface $key
     *
     * @return self
     */
    public function setKey(JWKInterface $key)
    {
        $this->key = $key;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @param array $protected_header
     *
     * @return self
     */
    public function setProtectedHeader(array $protected_header)
    {
        $this->protected_header = $protected_header;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getProtectedHeader()
    {
        return $this->protected_header;
    }

    /**
     * @param array $unprotected_header
     *
     * @return self
     */
    public function setUnprotectedHeader(array $unprotected_header)
    {
        $this->unprotected_header = $unprotected_header;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getUnprotectedHeader()
    {
        return $this->unprotected_header;
    }
}
