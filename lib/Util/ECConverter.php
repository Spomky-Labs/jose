<?php

namespace SpomkyLabs\Jose\Util;

use File_ASN1;
use Base64Url\Base64Url;

/**
 * Class ECConverter
 * @package SpomkyLabs\Jose\Util
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
            throw new \RuntimeException("PHP ".PHP_VERSION." does not support Elliptic Curves algorithms.");
        }
    }

    /**
     * @param $certificate
     * @param null $passphrase
     * @return mixed
     * @throws \Exception
     */
    protected static function loadKey($certificate, $passphrase = null)
    {
        $res = openssl_pkey_get_private($certificate, $passphrase);
        if ($res === false) {
            $res = openssl_pkey_get_public($certificate);
        }
        if ($res === false) {
            throw new \Exception("Unable to load the certificate");
        }
        $details = openssl_pkey_get_details($res);
        if ($details === false) {
            throw new \Exception("Unable to get details of the certificate");
        }
        if (!is_array($details) || !isset($details['key'])) {
            throw new \Exception("Certificate is not a valid RSA certificate");
        }

        return $details['key'];
    }

    /**
     * @param $file
     * @param null $passphrase
     * @return array|bool|void
     * @throws \Exception
     */
    public static function loadKeyFromFile($file, $passphrase = null)
    {
        self::checkRequirements();
        $details = self::loadKey($file, $passphrase);

        if (0 === preg_match('/-----BEGIN PUBLIC KEY-----([^-]+)-----END PUBLIC KEY-----/', $details, $matches)) {
            return false;
        }
        $publicKey = $matches[1];

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
        $details = Base64Url::decode($mappedDetails["subjectPublicKey"]);
//Check algorithm here
        if (substr($details, 0, 1) !== "\00") {
            return;
        }
        if (substr($details, 1, 1) !== "\04") {
            return;
        }

        $X = substr($details, 2, (strlen($details)-2)/2);
        $Y = substr($details, (strlen($details)-2)/2+2, (strlen($details)-2)/2);

        return array(
            "kty" => "EC",
            "x" => Base64Url::encode($X),
            "y" => Base64Url::encode($Y),
        );
    }
}
