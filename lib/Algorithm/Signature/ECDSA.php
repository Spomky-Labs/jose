<?php

namespace SpomkyLabs\Jose\Algorithm\Signature;

use Jose\JWKInterface;
use Jose\Operation\SignatureInterface;
use Mdanter\Ecc\Crypto\Signature\Signature;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Random\RandomGeneratorFactory;
use Base64Url\Base64Url;

/**
 * Class ECDSA.
 */
abstract class ECDSA implements SignatureInterface
{
    /**
     * @var \Mdanter\Ecc\Math\MathAdapterInterface
     */
    private $adapter;

    /**
     *
     */
    public function __construct()
    {
        if (!class_exists("\Mdanter\Ecc\EccFactory")) {
            throw new \RuntimeException("The library 'mdanter/ecc' is required to use Elliptic Curves based algorithm algorithms");
        }
        $this->adapter = EccFactory::getAdapter();
    }

    /**
     * @inheritdoc
     */
    public function sign(JWKInterface $key, $data)
    {
        $this->checkKey($key);

        $p     = $this->getGenerator();
        //$x     = $this->convertBase64ToDec($key->getValue('x'));
        //$y     = $this->convertBase64ToDec($key->getValue('y'));
        $d     = $this->convertBase64ToDec($key->getValue('d'));
        $hash  = $this->convertHexToDec(hash($this->getHashAlgorithm(), $data));

        $k = RandomGeneratorFactory::getRandomGenerator()->generate($p->getOrder());

        $signer = EccFactory::getSigner();

        $private_key = $p->getPrivateKeyFrom($d);
        $signature = $signer->sign($private_key, $hash, $k);

        $part_length = $this->getSignaturePartLength();

        $R = str_pad($this->convertDecToHex($signature->getR()), $part_length, '0', STR_PAD_LEFT);
        $S = str_pad($this->convertDecToHex($signature->getS()), $part_length, '0', STR_PAD_LEFT);

        return $this->convertHextoBin($R.$S);
    }

    /**
     * @inheritdoc
     */
    public function verify(JWKInterface $key, $data, $signature)
    {
        $this->checkKey($key);
        $signature = $this->convertBinToHex($signature);
        $part_length = $this->getSignaturePartLength();
        if (strlen($signature) !== 2 * $part_length) {
            return false;
        }

        $p     = $this->getGenerator();
        $x     = $this->convertBase64ToDec($key->getValue('x'));
        $y     = $this->convertBase64ToDec($key->getValue('y'));
        $R     = $this->convertHexToDec(substr($signature, 0, $part_length));
        $S     = $this->convertHexToDec(substr($signature, $part_length));
        $hash  = $this->convertHexToDec(hash($this->getHashAlgorithm(), $data));

        $public_key = $p->getPublicKeyFrom($x, $y);

        $signer = EccFactory::getSigner();

        return $signer->verify($public_key, new Signature($R, $S), $hash);
    }

    /**
     * @return \Mdanter\Ecc\Primitives\CurveFp
     */
    abstract protected function getCurve();

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
    protected function convertHexToBin($value)
    {
        return pack('H*', $value);
    }

    /**
     * @param string $value
     */
    protected function convertBinToHex($value)
    {
        $value = unpack('H*', $value);

        return $value[1];
    }

    /**
     * @return string
     */
    protected function convertDecToHex($value)
    {
        return $this->adapter->decHex($value);
    }

    /**
     * @param $value
     *
     * @return int|string
     */
    protected function convertHexToDec($value)
    {
        return $this->adapter->hexDec($value);
    }

    /**
     * @param $value
     *
     * @return int|string
     */
    protected function convertBase64ToDec($value)
    {
        $value = unpack('H*', Base64Url::decode($value));

        return $this->convertHexToDec($value[1]);
    }

    /**
     * @param JWKInterface $key
     */
    protected function checkKey(JWKInterface $key)
    {
        if ('EC' !== $key->getKeyType()) {
            throw new \InvalidArgumentException('The key is not valid');
        }
    }
}
