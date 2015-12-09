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
 * Class JWT.
 */
class JWT implements JWTInterface
{
    /**
     * @var string
     */
    private $encoded_protected_header = '';

    /**
     * @var string
     */
    private $input = null;

    /**
     * @var string
     */
    private $encoded_payload = '';

    /**
     * @var array
     */
    private $protected_headers = [];

    /**
     * @var array
     */
    private $unprotected_headers = [];

    /**
     * @var null
     */
    private $payload = null;

    /**
     * {@inheritdoc}
     */
    public function getEncodedProtectedHeaders()
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
     * {@inheritdoc}
     */
    public function getProtectedHeaders()
    {
        return $this->protected_headers;
    }

    /**
     * {@inheritdoc}
     */
    public function getUnprotectedHeaders()
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
    public function withInput($input)
    {
        $jwt = clone $this;
        $jwt->input = $input;

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function withEncodedProtectedHeaders($encoded_protected_header)
    {
        $jwt = clone $this;
        $jwt->encoded_protected_header = $encoded_protected_header;

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function withEncodedPayload($encoded_payload)
    {
        $jwt = clone $this;
        $jwt->encoded_payload = $encoded_payload;

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function withProtectedHeaders(array $values)
    {
        $jwt = clone $this;
        $jwt->protected_headers = $values;

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function withUnprotectedHeaders(array $values)
    {
        $jwt = clone $this;
        $jwt->unprotected_headers = $values;

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function withProtectedHeader($key, $value)
    {
        $jwt = clone $this;
        $jwt->protected_headers[$key] = $value;

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function withUnprotectedHeader($key, $value)
    {
        $jwt = clone $this;
        $jwt->unprotected_headers[$key] = $value;

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function withPayload($payload)
    {
        $jwt = clone $this;
        $jwt->payload = $payload;

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function getProtectedHeader($key)
    {
        if ($this->hasProtectedHeader($key)) {
            return $this->protected_headers[$key];
        }
        throw new \InvalidArgumentException(sprintf('The protected header "%" does not exist', $key));
    }

    /**
     * {@inheritdoc}
     */
    public function hasProtectedHeader($key)
    {
        return array_key_exists($key, $this->protected_headers);
    }

    /**
     * {@inheritdoc}
     */
    public function withoutProtectedHeader($key)
    {
        if (!$this->hasProtectedHeader($key)) {
            return $this;
        }
        $jwt = clone $this;
        unset($jwt->protected_headers[$key]);

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function getUnprotectedHeader($key)
    {
        if ($this->hasUnprotectedHeader($key)) {
            return $this->unprotected_headers[$key];
        }
        throw new \InvalidArgumentException(sprintf('The unprotected header "%" does not exist', $key));
    }

    /**
     * {@inheritdoc}
     */
    public function hasUnprotectedHeader($key)
    {
        return array_key_exists($key, $this->unprotected_headers);
    }

    /**
     * {@inheritdoc}
     */
    public function withoutUnprotectedHeader($key)
    {
        if (!$this->hasUnprotectedHeader($key)) {
            return $this;
        }
        $jwt = clone $this;
        unset($jwt->unprotected_headers[$key]);

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function getHeaders()
    {
        return array_merge($this->protected_headers, $this->unprotected_headers);
    }

    /**
     * {@inheritdoc}
     */
    public function getHeader($key)
    {
        if ($this->hasProtectedHeader($key)) {
            return $this->getProtectedHeader($key);
        } elseif ($this->hasUnprotectedHeader($key)) {
            return $this->getUnprotectedHeader($key);
        }
        throw new \InvalidArgumentException(sprintf('The protected or unprotected headers do not contain header "%"', $key));
    }

    /**
     * {@inheritdoc}
     */
    public function hasHeader($key)
    {
        return $this->hasProtectedHeader($key) || $this->hasUnprotectedHeader($key);
    }

    /**
     * {@inheritdoc}
     */
    public function getHeaderOrClaim($key)
    {
        if ($this->hasHeader($key)) {
            return $this->getHeader($key);
        } elseif ($this->hasClaim($key)) {
            return $this->getClaim($key);
        }
        throw new \InvalidArgumentException(sprintf('The header or claim do not contain value with key "%"', $key));
    }

    /**
     * {@inheritdoc}
     */
    public function hasHeaderOrClaim($key)
    {
        return $this->hasHeader($key) || $this->hasClaim($key);
    }

    /**
     * {@inheritdoc}
     */
    public function getClaim($key)
    {
        if ($this->hasClaim($key)) {
            return $this->payload[$key];
        }
        throw new \InvalidArgumentException(sprintf('The payload does not contain claim "%"', $key));
    }

    /**
     * {@inheritdoc}
     */
    public function getClaims()
    {
        if (is_array($this->payload)) {
            return $this->payload;
        }
        throw new \InvalidArgumentException('The payload does not contain claims');
    }

    /**
     * {@inheritdoc}
     */
    public function hasClaim($key)
    {
        return $this->hasClaims() && array_key_exists($key, $this->payload);
    }

    /**
     * {@inheritdoc}
     */
    public function hasClaims()
    {
        return is_array($this->payload);
    }

    /**
     * {@inheritdoc}
     */
    public function withClaim($key, $value)
    {
        $jwt = clone $this;
        if (!is_array($jwt->payload)) {
            $jwt->payload = [];
        }
        $jwt->payload[$key] = $value;

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function withoutClaim($key)
    {
        if (!$this->hasClaim($key)) {
            return $this;
        }
        $jwt = clone $this;
        unset($jwt->payload[$key]);

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function withClaims(array $claims)
    {
        $jwt = clone $this;
        $jwt->payload = $claims;

        return $jwt;
    }
}
