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
     * @param JWKInterface $receiver_key
     * @param int          $encryption_key_length
     * @param array        $header
     *
     * @return string
     */
    public function getAgreementKey(JWKInterface $receiver_key, $encryption_key_length, array $header)
    {
        $this->checkKey($receiver_key, true);
        $sender_key = new JWK();
        $sender_key->setValues($header['epk']);
        $this->checkKey($sender_key, false);
        if ($sender_key->getValue('crv') !== $receiver_key->getValue('crv')) {
            throw new \RuntimeException('Curves are different');
        }

        $agreed_key = $this->calculateAgreementKey($receiver_key, $sender_key);

        return ConcatKDF::generate($this->convertDecToBin($agreed_key), $header['enc'], $encryption_key_length);
    }

    /**
     * @param JWKInterface $sender_key
     * @param JWKInterface $receiver_key
     * @param int          $encryption_key_length
     * @param array        $header
     *
     * @return string
     */
    public function setAgreementKey(JWKInterface $sender_key, JWKInterface $receiver_key, $encryption_key_length, array &$header)
    {
        $this->checkKey($sender_key, true);
        $this->checkKey($receiver_key, false);
        if ($sender_key->getValue('crv') !== $receiver_key->getValue('crv')) {
            throw new \RuntimeException('Curves are different');
        }

        $agreed_key = $this->calculateAgreementKey($sender_key, $receiver_key);

        $header = array_merge($header, array(
            'epk' => array(
                'kty' => $sender_key->getKeyType(),
                'crv' => $sender_key->getValue('crv'),
                'x'   => $sender_key->getValue('x'),
                'y'   => $sender_key->getValue('y'),
            ),
        ));

        return ConcatKDF::generate($this->convertDecToBin($agreed_key), $header['enc'], $encryption_key_length);
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
     * @param JWKInterface $key
     * @param $is_private
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
