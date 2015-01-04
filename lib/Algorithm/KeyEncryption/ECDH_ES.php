<?php

namespace SpomkyLabs\JOSE\Algorithm\KeyEncryption;

use Jose\JWKInterface;
use Jose\Operation\KeyAgreementInterface;
use Mdanter\Ecc\Point;
use Mdanter\Ecc\EccFactory;
use SpomkyLabs\JOSE\Util\Base64Url;
use SpomkyLabs\JOSE\Util\ConcatKDF;

class ECDH_ES implements KeyAgreementInterface
{
    private $adapter;

    public function __construct()
    {
        $this->adapter = EccFactory::getAdapter();
    }

    public function getAgreementKey(JWKInterface $sender_key, JWKInterface $receiver_key, $encryption_key_length, array &$header)
    {
        $this->checkKey($sender_key, $receiver_key);

        //We swap the keys to get sender_key the private key
        if (null === $sender_key->getValue("d")) {
            $tmp = $sender_key;
            $sender_key = $receiver_key;
            $receiver_key = $tmp;
        }

        $p     = $this->getGenerator($sender_key);
        $curve = $this->getCurve($sender_key);

        $rec_x = $this->convertBase64ToDec($receiver_key->getValue('x'));
        $rec_y = $this->convertBase64ToDec($receiver_key->getValue('y'));
        $sen_d = $this->convertBase64ToDec($sender_key->getValue('d'));

        $receiver_point = new Point($curve, $rec_x, $rec_y, $p->getOrder(), $this->adapter);
        $agreed_key = $receiver_point->mul($sen_d)->getX();

        $header = array_merge($header, array(
            "epk" => array(
                "kty" => $sender_key->getKeyType(),
                "crv" => $sender_key->getValue("crv"),
                "x"   => $sender_key->getValue("x"),
                "y"   => $sender_key->getValue("y"),
            ),
        ));

        return ConcatKDF::generate($this->convertDecToBin($agreed_key), $header["enc"], $encryption_key_length);
    }

    public function getAlgorithmName()
    {
        return "ECDH-ES";
    }

    private function checkKey(JWKInterface $key1, JWKInterface $key2)
    {
        if ("EC" !== $key1->getKeyType() || "EC" !== $key2->getKeyType()) {
            throw new \RuntimeException("The keys type must be 'EC'");
        }
        if (null === $key1->getValue('d') && null === $key2->getValue('d')) {
            throw new \RuntimeException("One of the keys must be private");
        }
        if ($key1->getValue("crv") !== $key2->getValue("crv")) {
            throw new \RuntimeException("Curves are different");
        }
    }

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

    private function convertHexToDec($value)
    {
        return $this->adapter->hexDec($value);
    }

    private function convertBase64ToDec($value)
    {
        $value = unpack('H*', Base64Url::decode($value));

        return $this->convertHexToDec($value[1]);
    }

    private function convertDecToBin($value)
    {
        $adapter = EccFactory::getAdapter();

        return hex2bin($adapter->decHex($value));
    }
}
