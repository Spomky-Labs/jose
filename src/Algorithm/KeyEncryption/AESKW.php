<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\KeyEncryption;

use Base64Url\Base64Url;
use Jose\Object\JWKInterface;
use Jose\Util\StringUtil;

/**
 * Class AESKW.
 */
abstract class AESKW implements KeyWrappingInterface
{
    /**
     * @param \Jose\Object\JWKInterface $key
     * @param string                    $cek
     * @param array                     $header
     *
     * @return mixed
     */
    public function wrapKey(JWKInterface $key, $cek, array &$header)
    {
        $this->checkKey($key);
        $wrapper = $this->getWrapper();

        return $wrapper->wrap(Base64Url::decode($key->get('k')), $cek);
    }

    /**
     * @param \Jose\Object\JWKInterface $key
     * @param string                    $encryted_cek
     * @param array                     $header
     *
     * @return mixed
     */
    public function unwrapKey(JWKInterface $key, $encryted_cek, array $header)
    {
        $this->checkKey($key);
        $wrapper = $this->getWrapper();

        return $wrapper->unwrap(Base64Url::decode($key->get('k')), $encryted_cek);
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyManagementMode()
    {
        return self::MODE_WRAP;
    }

    /**
     * @param \Jose\Object\JWKInterface $key
     */
    protected function checkKey(JWKInterface $key)
    {
        if ('oct' !== $key->get('kty') || !$key->has('k')) {
            throw new \InvalidArgumentException('The key is not valid');
        }
        if ($this->getKeySize() !==  StringUtil::strlen(Base64Url::decode($key->get('k')))) {
            throw new \InvalidArgumentException('The key size is not valid');
        }
    }

    /**
     * @return int
     */
    abstract protected function getKeySize();

    /**
     * @return \AESKW\A128KW|\AESKW\A192KW|\AESKW\A256KW
     */
    abstract protected function getWrapper();
}
