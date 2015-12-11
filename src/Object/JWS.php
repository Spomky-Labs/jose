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
 * Class JWS.
 */
final class JWS extends JWT implements JWSInterface
{
    /**
     * @var string|null
     */
    protected $encoded_payload = null;

    /**
     * @var string|null
     */
    protected $encoded_protected_header = null;

    /**
     * @var string|null
     */
    protected $signature = null;

    /**
     * JWS constructor.
     *
     * @param string $signature
     */
    public function __construct($input = null, $signature = null, $encoded_payload = null, $encoded_protected_header = null)
    {
        parent::__construct($input);
        $this->encoded_payload = $encoded_payload;
        $this->encoded_protected_header = $encoded_protected_header;
        $this->signature = $signature;
    }

    /**
     * {@inheritdoc}
     */
    public function getEncodedPayload()
    {
        return $this->encoded_payload;
    }

    /**
     * {@inheritdoc}
     */
    public function getEncodedProtectedHeader()
    {
        return $this->encoded_protected_header;
    }

    /**
     * {@inheritdoc}
     */
    public function getSignature()
    {
        return $this->signature;
    }
}
