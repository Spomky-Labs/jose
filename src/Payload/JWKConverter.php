<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Payload;

use Jose\JWKInterface;
use Jose\JWKManagerInterface;

/**
 * Trait used to convert payload.
 */
class JWKConverter implements PayloadConverterInterface
{
    /**
     * @var \Jose\JWKManagerInterface
     */
    private $jwk_manager;

    /**
     * @param \Jose\JWKManagerInterface $jwk_manager
     */
    public function __construct(JWKManagerInterface $jwk_manager)
    {
        $this->jwk_manager = $jwk_manager;
    }

    /**
     * {@inheritdoc}
     */
    public function isPayloadToStringSupported(array $header, $payload)
    {
        return $payload instanceof JWKInterface;
    }

    /**
     * {@inheritdoc}
     */
    public function isStringToPayloadSupported(array $header, $content)
    {
        return array_key_exists('cty', $header) && $header['cty'] === 'jwk+json';
    }

    /**
     * {@inheritdoc}
     */
    public function convertPayloadToString(array &$header, $payload)
    {
        $header['cty'] = 'jwk+json';

        return json_encode($payload);
    }

    /**
     * {@inheritdoc}
     */
    public function convertStringToPayload(array $header, $content)
    {
        $jwk = json_decode($content, true);
        if (!is_array($jwk)) {
            throw new \InvalidArgumentException('The content type claims content is a JWK, but cannot be converted into JWK');
        }

        return $this->jwk_manager->createJWK($jwk);
    }
}
