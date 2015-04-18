<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use Jose\Operation\KeyAgreementInterface;
use Mdanter\Ecc\Point;
use Mdanter\Ecc\EccFactory;
use SpomkyLabs\Jose\JWK;
use Base64Url\Base64Url;
use SpomkyLabs\Jose\Util\ConcatKDF;

/**
 * Class ECDHES.
 */
class ECDHES implements KeyAgreementInterface
{
    /**
     * @var \Mdanter\Ecc\MathAdapter
     */
    private $adapter;

    /**
     *
     */
    public function __construct()
    {
        if (!class_exists("\Mdanter\Ecc\Point") || !class_exists("\Mdanter\Ecc\EccFactory")) {
            throw new \RuntimeException("The library 'mdanter/ecc' is required to use Elliptic Curves based algorithm algorithms");
        }
        $this->adapter = EccFactory::getAdapter();
    }

    /**
     * @inheritdoc
     */
    public function getAgreementKey($encryption_key_length, JWKInterface $private_key, JWKInterface $public_key = null, array $complete_header = array(), array &$additional_header_values = array())
    {
        $this->checkKey($private_key, true);
        if (is_null($public_key)) {
            $public_key = $this->getPublicKey($complete_header);
        } else {
            $this->checkKey($public_key, false);
            $additional_header_values = array_merge($additional_header_values, array(
                'epk' => array(
                    'kty' => $private_key->getKeyType(),
                    'crv' => $private_key->getValue('crv'),
                    'x'   => $private_key->getValue('x'),
                    'y'   => $private_key->getValue('y'),
                ),
            ));
        }
        if ($private_key->getValue('crv') !== $public_key->getValue('crv')) {
            throw new \RuntimeException('Curves are different');
        }

        $agreed_key = $this->calculateAgreementKey($private_key, $public_key);

        return ConcatKDF::generate($this->convertDecToBin($agreed_key), $complete_header['enc'], $encryption_key_length);
    }

    /**
     * @param JWKInterface $private_key
     * @param JWKInterface $public_key
     *
     * @return int|string|void
     *
     * @throws \Exception
     */
    public function calculateAgreementKey(JWKInterface $private_key, JWKInterface $public_key)
    {
        $p     = $this->getGenerator($private_key);
        $curve = $this->getCurve($private_key);

        $rec_x = $this->convertBase64ToDec($public_key->getValue('x'));
        $rec_y = $this->convertBase64ToDec($public_key->getValue('y'));
        $sen_d = $this->convertBase64ToDec($private_key->getValue('d'));

        $receiver_point = new Point($curve, $rec_x, $rec_y, $p->getOrder(), $this->adapter);

        return $receiver_point->mul($sen_d)->getX();
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'ECDH-ES';
    }

    /**
     * @param array $complete_header
     *
     * @return \Jose\JWKInterface
     */
    private function getPublicKey(array $complete_header)
    {
        if (!array_key_exists('epk', $complete_header)) {
            throw new \RuntimeException('"epk" parameter missing');
        }
        if (!is_array($complete_header['epk'])) {
            throw new \RuntimeException('"epk" parameter is not an array of parameter');
        }
        $public_key = new JWK();
        $public_key->setValues($complete_header['epk']);
        $this->checkKey($public_key, false);

        return $public_key;
    }

    /**
     * @param JWKInterface $key
     * @param boolean $is_private
     */
    private function checkKey(JWKInterface $key, $is_private)
    {
        if ('EC' !== $key->getKeyType()) {
            throw new \RuntimeException("The key type must be 'EC'");
        }
        if (null === $key->getValue('d') && true === $is_private) {
            throw new \RuntimeException('The key must be private');
        }
    }

    /**
     * @param JWKInterface $key
     *
     * @return \Mdanter\Ecc\CurveFp
     *
     * @throws \Exception
     */
    private function getCurve(JWKInterface $key)
    {
        $crv = $key->getValue('crv');
        switch ($crv) {
            case 'P-256':
                return EccFactory::getNistCurves()->curve256();
            case 'P-384':
                return EccFactory::getNistCurves()->curve384();
            case 'P-521':
                return EccFactory::getNistCurves()->curve521();
            default:
                throw new \Exception("Curve $crv is not supported");
        }
    }

    /**
     * @param JWKInterface $key
     *
     * @return \Mdanter\Ecc\GeneratorPoint
     *
     * @throws \Exception
     */
    private function getGenerator(JWKInterface $key)
    {
        $crv = $key->getValue('crv');

        switch ($crv) {
            case 'P-256':
                return EccFactory::getNistCurves()->generator256();
            case 'P-384':
                return EccFactory::getNistCurves()->generator384();
            case 'P-521':
                return EccFactory::getNistCurves()->generator521();
            default:
                throw new \Exception("Curve $crv is not supported");
        }
    }

    /**
     * @param $value
     *
     * @return int|string
     */
    private function convertHexToDec($value)
    {
        return $this->adapter->hexDec($value);
    }

    /**
     * @param $value
     *
     * @return int|string
     */
    private function convertBase64ToDec($value)
    {
        $value = unpack('H*', Base64Url::decode($value));

        return $this->convertHexToDec($value[1]);
    }

    /**
     * @param $value
     *
     * @return string
     */
    private function convertDecToBin($value)
    {
        $adapter = EccFactory::getAdapter();

        return hex2bin($adapter->decHex($value));
    }
}
