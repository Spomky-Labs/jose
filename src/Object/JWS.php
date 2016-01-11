<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

use Base64Url\Base64Url;

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
     * @param string      $input
     * @param string      $signature
     * @param string|null $encoded_payload
     * @param string|null $payload
     * @param string|null $encoded_protected_header
     * @param array       $unprotected_headers
     */
    public function __construct($input, $signature, $encoded_payload = null, $payload = null, $encoded_protected_header = null, array $unprotected_headers = [])
    {
        $protected_header = empty($encoded_protected_header) ? [] : json_decode(Base64Url::decode($encoded_protected_header), true);
        parent::__construct($input, $protected_header, $unprotected_headers, $payload);
        $this->signature = $signature;
        $this->encoded_payload = $encoded_payload;
        $this->encoded_protected_header = $encoded_protected_header;
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
