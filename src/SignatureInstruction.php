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

/**
 * Class SignatureInstruction.
 */
class SignatureInstruction implements SignatureInstructionInterface
{
    /**
     * @var \Jose\JWKInterface
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
     * SignatureInstruction constructor.
     *
     * @param \Jose\JWKInterface $key
     * @param array              $protected_header
     * @param array              $unprotected_header
     */
    public function __construct(JWKInterface $key, array $protected_header = [], array $unprotected_header = [])
    {
        $this->key = $key;
        $this->protected_header = $protected_header;
        $this->unprotected_header = $unprotected_header;
    }

    /**
     * {@inheritdoc}
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * {@inheritdoc}
     */
    public function getProtectedHeader()
    {
        return $this->protected_header;
    }

    /**
     * {@inheritdoc}
     */
    public function getUnprotectedHeader()
    {
        return $this->unprotected_header;
    }
}
