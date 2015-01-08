<?php

namespace SpomkyLabs\Jose\Algorithm\ContentEncryption;

use Crypto\Cipher;
use SpomkyLabs\Jose\Util\Base64Url;
use Jose\Operation\ContentEncryptionInterface;

/**
 *
 */
abstract class AESGCM implements ContentEncryptionInterface
{
    public function __construct()
    {
        if (!class_exists("\Crypto\Cipher")) {
            throw new \RuntimeException("The PHP extension 'Crypto' is required to use AES GCM based algorithms");
        }
    }

    /**
     * @inheritdoc
     */
    public function encryptContent($input, $cek, $iv, array &$header, &$tag)
    {
        $cipher = Cipher::aes(Cipher::MODE_GCM, $this->getKeySize());
        $cipher->setAAD(Base64Url::encode(json_encode($header)));
        $cyphertext = $cipher->encrypt($input, $cek, $iv);
        $tag = $cipher->getTag(16);

        return $cyphertext;
    }

    public function decryptContent($input, $cek, $iv, array $header, $tag)
    {
        $cipher = Cipher::aes(Cipher::MODE_GCM, $this->getKeySize());
        $cipher->setTag($tag);
        $cipher->setAAD(Base64Url::encode(json_encode($header)));

        $plaintext = $cipher->decrypt($input, $cek, $iv);

        return $plaintext;
    }

    public function getIVSize()
    {
        return 96;
    }

    public function getCEKSize()
    {
        return $this->getKeySize();
    }
}
