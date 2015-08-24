<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Jose\KeyConverter;

use Base64Url\Base64Url;
use phpseclib\File\ASN1;

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
        $minVersions = [
            '5.4' => '5.4.26',
            '5.5' => '5.5.10',
            '5.6' => '5.6.0',
        ];

        if (isset($minVersions[PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION]) &&
            version_compare(PHP_VERSION, $minVersions[PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION], '<')) {
            throw new \RuntimeException('PHP '.PHP_VERSION.' does not support Elliptic Curves algorithms.');
        }
    }

    /**
     * @param $certificate
     * @param null $passphrase
     *
     * @throws \Exception
     *
     * @return mixed
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
     * @throws \Exception
     *
     * @return array|bool|void
     */
    public static function loadKeyFromFile($file)
    {
        self::checkRequirements();
        $content = file_get_contents($file);
        $values = [];

        if (0 !== preg_match('/-----BEGIN EC PRIVATE KEY-----([^-]+)-----END EC PRIVATE KEY-----/', $content, $matches)) {
            $values += self::loadPrivateKey($matches[1]);
            $content = self::loadKey($file);
        }
        if (0 !== preg_match('/-----BEGIN PUBLIC KEY-----([^-]+)-----END PUBLIC KEY-----/', $content, $matches)) {
            $values += self::loadPublicKey($matches[1]);
        }

        return empty($values) ? false : ['kty' => 'EC'] + $values;
    }

    /**
     * @param $privateKey
     *
     * @return array
     */
    protected static function loadPrivateKey($privateKey)
    {
        $asn1 = new ASN1();

        $asnSubjectPrivateKeyInfo = [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'version' => [
                    'type' => ASN1::TYPE_INTEGER,
                ],
                'secret' => [
                    'type' => ASN1::TYPE_OCTET_STRING,
                ],
                'algorithm' => [
                    'type' => ASN1::TYPE_INTEGER,
                ],
                'subjectPublicKey' => [
                    'type' => ASN1::TYPE_INTEGER,
                ],
            ],
        ];
        $decoded = $asn1->decodeBER(base64_decode($privateKey));
        $mappedDetails = $asn1->asn1map($decoded[0], $asnSubjectPrivateKeyInfo);
        if (null === $mappedDetails) {
            return [];
        }

        return [
            'd' => Base64Url::encode(base64_decode($mappedDetails['secret'])),
        ];
    }

    /**
     * @param $publicKey
     *
     * @return array|bool
     */
    protected static function loadPublicKey($publicKey)
    {
        $asn1 = new ASN1();

        $asnAlgorithmIdentifier = [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'ansi-X9-62' => [
                    'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
                ],
                'id-ecSigType' => [
                    'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
                ],
            ],
        ];

        $asnSubjectPublicKeyInfo = [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'algorithm' => $asnAlgorithmIdentifier,
                'subjectPublicKey' => [
                    'type' => ASN1::TYPE_BIT_STRING,
                ],
            ],
        ];
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

        return [
            'x' => Base64Url::encode($X),
            'y' => Base64Url::encode($Y),
        ];
    }

    /**
     * @param $algorithm
     *
     * @return bool
     */
    protected static function isAlgorithmSupported($algorithm)
    {
        return in_array($algorithm, ['1.2.840.10045.3.1.7', '1.3.132.0.34', '1.3.132.0.35']);
    }
}
