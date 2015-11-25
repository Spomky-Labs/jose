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
 * Class JWT.
 */
class JWT implements JWTInterface
{
    /**
     * @var string
     */
    protected $encoded_protected_header = '';

    /**
     * @var string
     */
    protected $input = null;

    /**
     * @var string
     */
    protected $encoded_payload = '';

    /**
     * @var array
     */
    protected $protected_headers = [];

    /**
     * @var array
     */
    protected $unprotected_headers = [];

    /**
     * @var null
     */
    protected $payload = null;

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
    public function getInput()
    {
        return $this->input;
    }

    /**
     * {@inheritdoc}
     */
    public function getEncodedPayload()
    {
        return $this->encoded_payload;
    }

    /**
     * @return array
     */
    public function getProtectedHeader()
    {
        return $this->protected_headers;
    }

    /**
     * {@inheritdoc}
     */
    public function getUnprotectedHeader()
    {
        return $this->unprotected_headers;
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * {@inheritdoc}
     */
    public function setInput($input)
    {
        $this->input = $input;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function setEncodedProtectedHeader($encoded_protected_header)
    {
        $this->encoded_protected_header = $encoded_protected_header;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function setEncodedPayload($encoded_payload)
    {
        $this->encoded_payload = $encoded_payload;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function setProtectedHeader(array $values)
    {
        $this->protected_headers = $values;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function setUnprotectedHeader(array $values)
    {
        $this->unprotected_headers = $values;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function setProtectedHeaderValue($key, $value)
    {
        $this->protected_headers[$key] = $value;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function setUnprotectedHeaderValue($key, $value)
    {
        $this->unprotected_headers[$key] = $value;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function setPayload($payload)
    {
        $this->payload = $payload;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getProtectedHeaderValue($key)
    {
        $protected_header = $this->getProtectedHeader();
        if (array_key_exists($key, $protected_header)) {
            return $protected_header[$key];
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getUnprotectedHeaderValue($key)
    {
        $unprotected_header = $this->getUnprotectedHeader();
        if (array_key_exists($key, $unprotected_header)) {
            return $unprotected_header[$key];
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getHeaderValue($key)
    {
        if (null !== ($value = $this->getProtectedHeaderValue($key))) {
            return $value;
        }

        return $this->getUnprotectedHeaderValue($key);
    }

    /**
     * {@inheritdoc}
     */
    public function getHeaderOrPayloadValue($key)
    {
        return $this->getHeaderValue($key) ? $this->getHeaderValue($key) : $this->getPayloadValue($key);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayloadValue($key)
    {
        $payload = $this->getPayload();

        return is_array($payload) && array_key_exists($key, $payload) ? $payload[$key] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function getType()
    {
        return $this->getHeaderValue('jty');
    }

    /**
     * {@inheritdoc}
     */
    public function getContentType()
    {
        return $this->getHeaderValue('cty');
    }

    /**
     * {@inheritdoc}
     */
    public function getIssuer()
    {
        return $this->getHeaderOrPayloadValue('iss');
    }

    /**
     * {@inheritdoc}
     */
    public function getSubject()
    {
        return $this->getHeaderOrPayloadValue('sub');
    }

    /**
     * {@inheritdoc}
     */
    public function getAudience()
    {
        return $this->getHeaderOrPayloadValue('aud');
    }

    /**
     * {@inheritdoc}
     */
    public function getExpirationTime()
    {
        return $this->getPayloadValue('exp');
    }

    /**
     * {@inheritdoc}
     */
    public function getNotBefore()
    {
        return $this->getPayloadValue('nbf');
    }

    /**
     * {@inheritdoc}
     */
    public function getIssuedAt()
    {
        return $this->getPayloadValue('iat');
    }

    /**
     * {@inheritdoc}
     */
    public function getJWTID()
    {
        return $this->getPayloadValue('jti');
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm()
    {
        return $this->getHeaderValue('alg');
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyID()
    {
        return $this->getHeaderValue('kid');
    }

    /**
     * {@inheritdoc}
     */
    public function getJWKUrl()
    {
        return $this->getHeaderValue('jku');
    }

    /**
     * {@inheritdoc}
     */
    public function getJWK()
    {
        return $this->getHeaderValue('jwk');
    }

    /**
     * {@inheritdoc}
     */
    public function getX509Url()
    {
        return $this->getHeaderValue('x5u');
    }

    /**
     * {@inheritdoc}
     */
    public function getX509CertificateChain()
    {
        return $this->getHeaderValue('x5c');
    }

    /**
     * {@inheritdoc}
     */
    public function getX509CertificateSha1Thumbprint()
    {
        return $this->getHeaderValue('x5t');
    }

    /**
     * {@inheritdoc}
     */
    public function getX509CertificateSha256Thumbprint()
    {
        return $this->getHeaderValue('x5t#256');
    }

    /**
     * {@inheritdoc}
     */
    public function getCritical()
    {
        return $this->getProtectedHeaderValue('crit');
    }
}
