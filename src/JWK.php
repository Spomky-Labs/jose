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
 * Class JWK.
 */
class JWK implements JWKInterface
{
    /**
     * @var array
     */
    protected $values = [];

    /**
     * {@inheritdoc}
     */
    public function getKeyType()
    {
        return $this->getValue('kty');
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicKeyUse()
    {
        return $this->getValue('use');
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyOperations()
    {
        return $this->getValue('key_ops');
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm()
    {
        return $this->getValue('alg');
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyID()
    {
        return $this->getValue('kid');
    }

    /**
     * {@inheritdoc}
     */
    public function getX509Url()
    {
        return $this->getValue('x5u');
    }

    /**
     * {@inheritdoc}
     */
    public function getX509CertificateChain()
    {
        return $this->getValue('x5c');
    }

    /**
     * {@inheritdoc}
     */
    public function getX509CertificateSha1Thumbprint()
    {
        return $this->getValue('x5t');
    }

    /**
     * {@inheritdoc}
     */
    public function getX509CertificateSha256Thumbprint()
    {
        return $this->getValue('x5t#256');
    }

    /**
     * @param array $values
     */
    public function __construct(array $values = [])
    {
        $this->setValues($values);
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        return $this->getValues();
    }

    /**
     * {@inheritdoc}
     */
    public function getValue($key)
    {
        return array_key_exists($key, $this->getValues()) ? $this->values[$key] : null;
    }

    /**
     * @return array
     */
    public function getValues()
    {
        return $this->values;
    }

    /**
     * @param string $key
     * @param mixed  $value
     *
     * @return self
     */
    public function setValue($key, $value)
    {
        $this->values[$key] = $value;

        return $this;
    }

    /**
     * @param array $values
     *
     * @return self
     */
    public function setValues(array $values)
    {
        $this->values = $values;

        return $this;
    }
}
