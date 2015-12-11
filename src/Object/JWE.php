<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

/**
 * Class JWE.
 */
final class JWE extends JWT implements JWEInterface
{
    /**
     * @var string|null
     */
    private $ciphertext = null;

    /**
     * @var string|null
     */
    private $encrypted_key = null;

    /**
     * @var string|null
     */
    private $iv = null;

    /**
     * @var string|null
     */
    private $aad = null;

    /**
     * @var string|null
     */
    private $tag;

    /**
     * @var string|null
     */
    protected $encoded_protected_header = null;

    /**
     * JWE constructor.
     *
     * @param string|null $ciphertext
     * @param string|null $encrypted_key
     * @param string|null $iv
     * @param string|null $aad
     * @param string|null $tag
     * @param string|null $encoded_protected_header
     */
    public function __construct($input = null, $ciphertext = null, $encrypted_key = null, $iv = null, $aad = null, $tag = null, $encoded_protected_header = null)
    {
        parent::__construct($input);
        $this->ciphertext = $ciphertext;
        $this->encrypted_key = $encrypted_key;
        $this->iv = $iv;
        $this->aad = $aad;
        $this->tag = $tag;
        $this->encoded_protected_header = $encoded_protected_header;
    }

    /**
     * {@inheritdoc}
     */
    public function getCiphertext()
    {
        return $this->ciphertext;
    }

    /**
     * {@inheritdoc}
     */
    public function getEncryptedKey()
    {
        return $this->encrypted_key;
    }

    /**
     * {@inheritdoc}
     */
    public function getAAD()
    {
        return $this->aad;
    }

    /**
     * {@inheritdoc}
     */
    public function getIV()
    {
        return $this->iv;
    }

    /**
     * {@inheritdoc}
     */
    public function getTag()
    {
        return $this->tag;
    }

    /**
     * {@inheritdoc}
     */
    public function getEncodedProtectedHeader()
    {
        return $this->encoded_protected_header;
    }
}
