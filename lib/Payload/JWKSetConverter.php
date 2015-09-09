<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\Payload;

use Jose\JWKSetInterface;
use Jose\JWKSetManagerInterface;

/**
 * Trait used to convert payload.
 */
class JWKSetConverter implements PayloadConverterInterface
{
    /**
     * @var \Jose\JWKSetManagerInterface
     */
    private $jwkset_manager;

    /**
     * @param \Jose\JWKSetManagerInterface $jwkset_manager
     */
    public function __construct(JWKSetManagerInterface $jwkset_manager)
    {
        $this->jwkset_manager = $jwkset_manager;
    }

    /**
     * {@inheritdoc}
     */
    public function isPayloadToStringSupported(array $header, $payload)
    {
        return $payload instanceof JWKSetInterface;
    }

    /**
     * {@inheritdoc}
     */
    public function isStringToPayloadSupported(array $header, $content)
    {
        return array_key_exists('cty', $header) && $header['cty'] === 'jwkset+json';
    }

    /**
     * {@inheritdoc}
     */
    public function convertPayloadToString(array &$header, $payload)
    {
        $header['cty'] = 'jwkset+json';

        return json_encode($payload);
    }

    /**
     * {@inheritdoc}
     */
    public function convertStringToPayload(array $header, $content)
    {
        $jwk = json_decode($content, true);
        if (!is_array($jwk)) {
            throw new \InvalidArgumentException('The content type claims content is a JWKSet, but cannot be converted into JWKSet');
        }
        if (!array_key_exists('keys', $jwk)) {
            throw new \Exception('The content type claims content is a JWKSet, but cannot be converted into JWKSet');
        }

        return $this->jwkset_manager->createJWKSet($jwk);
    }
}
