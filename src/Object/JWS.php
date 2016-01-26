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
final class JWS implements JWSInterface
{
    use JWT;

    /**
     * @var \Jose\Object\SignatureInterface[]
     */
    private $signatures = [];

    /**
     * {@inheritdoc}
     */
    public function getEncodedPayload()
    {
        return is_string($this->getPayload()) ? Base64Url::encode($this->getPayload()) : null;
    }

    /**
     * {@inheritdoc}
     */
    public function getSignatures()
    {
        return $this->signatures;
    }

    /**
     * @param \Jose\Object\SignatureInterface $signature
     *
     * @return \Jose\Object\JWSInterface
     */
    public function addSignature(SignatureInterface $signature)
    {
        $jws = clone $this;
        $jws->signatures[] = $signature;

        return $jws;
    }

    /**
     * Returns the number of signature associated with the JWS.
     *
     * @return int
     */
    public function countSignatures()
    {
        return count($this->signatures);
    }

    /**
     * @param int $signature
     *
     * @return string
     */
    public function toCompactJSON($signature)
    {
        if (!isset($this->signatures[$signature])) {
            throw new \InvalidArgumentException('The signature does not exist.');
        }

        if (!empty($this->signatures[$signature]->getHeaders())) {
            throw new \InvalidArgumentException('The signature contains unprotected headers and cannot be converted into compact JSON');
        }

        return sprintf(
            '%s.%s.%s',
            $this->signatures[$signature]->getEncodedProtectedHeaders(),
            $this->getEncodedPayload(),
            Base64Url::encode($this->signatures[$signature]->getSignature())
        );
    }

    /**
     * @param int $signature
     *
     * @return string
     */
    public function toFlattenedJSON($signature)
    {
        if (!isset($this->signatures[$signature])) {
            throw new \InvalidArgumentException('The signature does not exist.');
        }

        $data = [];
        $values = [
            'payload'   => $this->getEncodedPayload(),
            'protected' => $this->signatures[$signature]->getEncodedProtectedHeaders(),
            'header'    => $this->signatures[$signature]->getHeaders(),
        ];

        foreach ($values as $key => $value) {
            if (!empty($value)) {
                $data[$key] = $value;
            }
        }
        $data['signature'] = $this->signatures[$signature]->getSignature();

        return json_encode($data);
    }

    /**
     * @return string
     */
    public function toJSON()
    {
        if (0 === $this->countSignatures()) {
            throw new \BadMethodCallException('No signature.');
        }

        $data = [];
        if (!empty($this->getEncodedPayload())) {
            $data['payload'] = $this->getEncodedPayload();
        }

        $data['signatures'] = [];
        foreach ($this->getSignatures() as $signature) {
            $tmp = ['signature' => $signature->getSignature()];
            $values = [
                'protected' => $signature->getEncodedProtectedHeaders(),
                'header'    => $signature->getHeaders(),
            ];

            foreach ($values as $key => $value) {
                if (!empty($value)) {
                    $tmp[$key] = $value;
                }
            }
            $data['signatures'][] = $tmp;
        }

        return json_encode($data);
    }
}
