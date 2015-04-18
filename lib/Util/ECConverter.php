<?php

namespace SpomkyLabs\Jose\Util;

use File_ASN1;
use Base64Url\Base64Url;

/**
 * This class will help you to load an EC key (private or public) and get values to create a JWK object
 * Class ECConverter.
 */
class ECConverter
{
    /**
     *
     */
    protected static function checkRequirements()
    {
        $minVersions = array(
            '5.4' => '5.4.26',
            '5.5' => '5.5.10',
            '5.6' => '5.6.0',
        );

        if (isset($minVersions[PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION]) &&
            version_compare(PHP_VERSION, $minVersions[PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION], '<')) {
            throw new \RuntimeException('PHP '.PHP_VERSION.' does not support Elliptic Curves algorithms.');
        }
    }

    /**
     * @param $certificate
     * @param null $passphrase
     *
     * @return mixed
     *
     * @throws \Exception
     */
    protected static function loadKey($certificate, $passphrase = null)
    {
        $res = openssl_pkey_get_private($certificate, $passphrase);
        if ($res === false) {
            $res = openssl_pkey_get_public($certificate);
        }
        if ($res === false) {
            throw new \Exception('Unable to load the certificate');
        }
        $details = openssl_pkey_get_details($res);
        if ($details === false) {
            throw new \Exception('Unable to get details of the certificate');
        }
        if (!is_array($details) || !isset($details['key'])) {
            throw new \Exception('Certificate is not a valid RSA certificate');
        }

        return $details['key'];
    }

    /**
     * @param $file
     *
     * @return array|bool|void
     *
     * @throws \Exception
     */
    public static function loadKeyFromFile($file)
    {
        self::checkRequirements();
        $details = file_get_contents($file);
        $values = array();

        if (0 !== preg_match('/-----BEGIN EC PRIVATE KEY-----([^-]+)-----END EC PRIVATE KEY-----/', $details, $matches)) {
            $values += self::loadPrivateKey($matches[1]);
            $details = self::loadKey($file);
        }
        if (0 !== preg_match('/-----BEGIN PUBLIC KEY-----([^-]+)-----END PUBLIC KEY-----/', $details, $matches)) {
            $values += self::loadPublicKey($matches[1]);
        }

        return empty($values) ? false : array('kty' => 'EC') + $values;
    }

    /**
     * @param $privateKey
     *
     * @return array
     */
    protected static function loadPrivateKey($privateKey)
    {
        $asn1 = new File_ASN1();

        $asnSubjectPrivateKeyInfo = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'version' => array(
                    'type' => FILE_ASN1_TYPE_INTEGER,
                ),
                'secret' => array(
                    'type' => FILE_ASN1_TYPE_OCTET_STRING,
                ),
                'algorithm' => array(
                    'type' => FILE_ASN1_TYPE_INTEGER,
                ),
                'subjectPublicKey' => array(
                    'type' => FILE_ASN1_TYPE_INTEGER,
                ),
            ),
        );
        $decoded = $asn1->decodeBER(base64_decode($privateKey));
        $mappedDetails = $asn1->asn1map($decoded[0], $asnSubjectPrivateKeyInfo);
        if (null === $mappedDetails) {
            return array();
        }

        return array(
            'd' => Base64Url::encode(base64_decode($mappedDetails['secret'])),
        );
    }

    /**
     * @param $publicKey
     *
     * @return array|bool
     */
    protected static function loadPublicKey($publicKey)
    {
        $asn1 = new File_ASN1();

        $asnAlgorithmIdentifier = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'ansi-X9-62' => array(
                    'type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER,
                ),
                'id-ecSigType' => array(
                    'type' => FILE_ASN1_TYPE_OBJECT_IDENTIFIER,
                ),
            ),
        );

        $asnSubjectPublicKeyInfo = array(
            'type' => FILE_ASN1_TYPE_SEQUENCE,
            'children' => array(
                'algorithm' => $asnAlgorithmIdentifier,
                'subjectPublicKey' => array(
                'type' => FILE_ASN1_TYPE_BIT_STRING,
                ),
            ),
        );
        $decoded = $asn1->decodeBER(base64_decode($publicKey));
        $mappedDetails = $asn1->asn1map($decoded[0], $asnSubjectPublicKeyInfo);
        if (null === $mappedDetails) {
            return false;
        }

        $details = Base64Url::decode($mappedDetails['subjectPublicKey']);

        if (!self::isAlgorithmSupported($mappedDetails['algorithm']['id-ecSigType'])) {
            return false;
        }
        if (substr($details, 0, 1) !== "\00") {
            return false;
        }
        if (substr($details, 1, 1) !== "\04") {
            return false;
        }

        $X = substr($details, 2, (strlen($details) - 2) / 2);
        $Y = substr($details, (strlen($details) - 2) / 2 + 2, (strlen($details) - 2) / 2);

        return array(
            'x' => Base64Url::encode($X),
            'y' => Base64Url::encode($Y),
        );
    }

    /**
     * @param $algorithm
     *
     * @return bool
     */
    protected static function isAlgorithmSupported($algorithm)
    {
        return in_array($algorithm, array('1.2.840.10045.3.1.7', '1.3.132.0.34', '1.3.132.0.35'));
    }
}
