<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose;

use Jose\JWE as Base;

/**
 * Class JWE.
 */
class JWE extends Base
{
    use JWable;

    /**
     * @var string|null
     */
    private $ciphertext;

    /**
     * @var string|null
     */
    private $encrypted_key;

    /**
     * @var string|null
     */
    private $iv;

    /**
     * @var string|null
     */
    private $aad;

    /**
     * @var string|null
     */
    private $tag;

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
    public function setCiphertext($ciphertext)
    {
        $this->ciphertext = $ciphertext;

        return $this;
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
    public function setEncryptedKey($encrypted_key)
    {
        $this->encrypted_key = $encrypted_key;

        return $this;
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
    public function setAAD($aad)
    {
        $this->aad = $aad;

        return $this;
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
    public function setIV($iv)
    {
        $this->iv = $iv;

        return $this;
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
    public function setTag($tag)
    {
        $this->tag = $tag;

        return $this;
    }
}
