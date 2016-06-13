<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\Signature;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Algorithm\SignatureAlgorithmInterface;
use Jose\Object\JWKInterface;
use Mdanter\Ecc\Crypto\Signature\Signature;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Random\RandomGeneratorFactory;

/**
 * Class ECDSA.
 */
abstract class ECDSA implements SignatureAlgorithmInterface
{
    /**
     * {@inheritdoc}
     */
    public function sign(JWKInterface $key, $data)
    {
        $this->checkKey($key);
        Assertion::true($key->has('d'), 'The EC key is not private');

        $p = $this->getGenerator();
        $d = $this->convertBase64ToGmp($key->get('d'));
        $hash = $this->convertHexToGmp(hash($this->getHashAlgorithm(), $data));

        $k = RandomGeneratorFactory::getRandomGenerator()->generate($p->getOrder());

        $signer = EccFactory::getSigner();

        $private_key = $p->getPrivateKeyFrom($d);
        $signature = $signer->sign($private_key, $hash, $k);

        $part_length = $this->getSignaturePartLength();

        $R = str_pad($this->convertDecToHex($signature->getR()), $part_length, '0', STR_PAD_LEFT);
        $S = str_pad($this->convertDecToHex($signature->getS()), $part_length, '0', STR_PAD_LEFT);

        return $this->convertHexToBin($R.$S);
    }

    /**
     * {@inheritdoc}
     */
    public function verify(JWKInterface $key, $data, $signature)
    {
        $this->checkKey($key);

        $signature = $this->convertBinToHex($signature);
        $part_length = $this->getSignaturePartLength();
        if (mb_strlen($signature, '8bit') !== 2 * $part_length) {
            return false;
        }

        $p = $this->getGenerator();
        $x = $this->convertBase64ToGmp($key->get('x'));
        $y = $this->convertBase64ToGmp($key->get('y'));
        $R = $this->convertHexToGmp(mb_substr($signature, 0, $part_length, '8bit'));
        $S = $this->convertHexToGmp(mb_substr($signature, $part_length, null, '8bit'));
        $hash = $this->convertHexToGmp(hash($this->getHashAlgorithm(), $data));

        $public_key = $p->getPublicKeyFrom($x, $y);

        $signer = EccFactory::getSigner();

        return $signer->verify($public_key, new Signature($R, $S), $hash);
    }

    /**
     * @return \Mdanter\Ecc\Primitives\GeneratorPoint
     */
    abstract protected function getGenerator();

    /**
     * @return string
     */
    abstract protected function getHashAlgorithm();

    /**
     * @return int
     */
    abstract protected function getSignaturePartLength();

    /**
     * @param string $value
     *
     * @return string
     */
    private function convertHexToBin($value)
    {
        return pack('H*', $value);
    }

    /**
     * @param string $value
     */
    private function convertBinToHex($value)
    {
        $value = unpack('H*', $value);

        return $value[1];
    }

    /**
     * @param $value
     *
     * @return string
     */
    private function convertDecToHex($value)
    {
        $value = gmp_strval($value);

        return EccFactory::getAdapter()->decHex($value);
    }

    /**
     * @param $value
     *
     * @return \GMP
     */
    private function convertHexToGmp($value)
    {
        return gmp_init('0x'.$value);
    }

    /**
     * @param $value
     *
     * @return \GMP
     */
    private function convertBase64ToGmp($value)
    {
        $value = unpack('H*', Base64Url::decode($value));
        $value = $value[1];

        return gmp_init('0x'.$value);
    }

    /**
     * @param JWKInterface $key
     */
    private function checkKey(JWKInterface $key)
    {
        Assertion::eq($key->get('kty'), 'EC', 'Wrong key type.');
        Assertion::true($key->has('x'), 'The key parameter "x" is missing.');
        Assertion::true($key->has('y'), 'The key parameter "y" is missing.');
        Assertion::true($key->has('crv'), 'The key parameter "crv" is missing.');
    }
}
