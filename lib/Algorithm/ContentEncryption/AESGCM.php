<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

use Crypto\Cipher;
use Base64Url\Base64Url;
use Jose\Operation\ContentEncryptionInterface;

/**
 *
 */
abstract class AESGCM implements ContentEncryptionInterface
{
    /**
     *
     */
    public function __construct()
    {
        if (!class_exists("\Crypto\Cipher")) {
            throw new \RuntimeException("The PHP extension 'Crypto' is required to use AES GCM based algorithms");
        }
    }

    /**
     * @inheritdoc
     */
    public function encryptContent($input, $cek, $iv, $aad, array &$header, &$tag)
    {
        $cipher = Cipher::aes(Cipher::MODE_GCM, $this->getKeySize());
        $calculated_aad = Base64Url::encode(json_encode($header));
        if (null !== $aad) {
            $calculated_aad .= $aad;
        }

        $cipher->setAAD($calculated_aad);
        $cyphertext = $cipher->encrypt($input, $cek, $iv);
        $tag = $cipher->getTag(16);

        return $cyphertext;
    }

    /**
     * @param $input
     * @param $cek
     * @param $iv
     * @param $aad
     * @param array $header
     * @param $tag
     *
     * @return mixed
     */
    public function decryptContent($input, $cek, $iv, $aad, array $header, $tag)
    {
        $cipher = Cipher::aes(Cipher::MODE_GCM, $this->getKeySize());
        $calculated_aad = Base64Url::encode(json_encode($header));
        if (null !== $aad) {
            $calculated_aad .= $aad;
        }
        $cipher->setTag($tag);
        $cipher->setAAD($calculated_aad);

        $plaintext = $cipher->decrypt($input, $cek, $iv);

        return $plaintext;
    }

    /**
     * @return int
     */
    public function getIVSize()
    {
        return 96;
    }

    /**
     * @return mixed
     */
    public function getCEKSize()
    {
        return $this->getKeySize();
    }
}
