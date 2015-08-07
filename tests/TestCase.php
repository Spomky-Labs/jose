<?php

namespace SpomkyLabs\Jose\Tests;

use SpomkyLabs\Jose\JWAManager;
use SpomkyLabs\Jose\Compression\GZip;
use SpomkyLabs\Jose\Compression\ZLib;
use SpomkyLabs\Jose\Compression\Deflate;
use SpomkyLabs\Jose\Tests\Stub\Loader;
use SpomkyLabs\Jose\Tests\Stub\Signer;
use SpomkyLabs\Jose\Tests\Stub\Encrypter;
use SpomkyLabs\Jose\Tests\Stub\JWTManager;
use SpomkyLabs\Jose\Tests\Stub\JWKManager;
use SpomkyLabs\Jose\Tests\Stub\JWKSetManager;
use SpomkyLabs\Jose\Compression\CompressionManager;
use SpomkyLabs\Jose\Algorithm\Signature\HS256;
use SpomkyLabs\Jose\Algorithm\Signature\HS384;
use SpomkyLabs\Jose\Algorithm\Signature\HS512;
use SpomkyLabs\Jose\Algorithm\Signature\ES256;
use SpomkyLabs\Jose\Algorithm\Signature\ES384;
use SpomkyLabs\Jose\Algorithm\Signature\ES512;
use SpomkyLabs\Jose\Algorithm\Signature\None;
use SpomkyLabs\Jose\Algorithm\Signature\RS256;
use SpomkyLabs\Jose\Algorithm\Signature\RS384;
use SpomkyLabs\Jose\Algorithm\Signature\RS512;
use SpomkyLabs\Jose\Algorithm\Signature\PS256;
use SpomkyLabs\Jose\Algorithm\Signature\PS384;
use SpomkyLabs\Jose\Algorithm\Signature\PS512;
use SpomkyLabs\Jose\Algorithm\ContentEncryption\A128GCM;
use SpomkyLabs\Jose\Algorithm\ContentEncryption\A192GCM;
use SpomkyLabs\Jose\Algorithm\ContentEncryption\A256GCM;
use SpomkyLabs\Jose\Algorithm\ContentEncryption\A128CBCHS256;
use SpomkyLabs\Jose\Algorithm\ContentEncryption\A192CBCHS384;
use SpomkyLabs\Jose\Algorithm\ContentEncryption\A256CBCHS512;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\A128KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\A192KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\A256KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\A128GCMKW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\A192GCMKW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\A256GCMKW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\Dir;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\ECDHES;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\ECDHESA128KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\ECDHESA192KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\ECDHESA256KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\PBES2HS256A128KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\PBES2HS384A192KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\PBES2HS512A256KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\RSA15;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\RSAOAEP;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\RSAOAEP256;

/**
 * Class TestCase.
 */
class TestCase extends \PHPUnit_Framework_TestCase
{
    /**
     * @return Loader
     */
    protected function getLoader()
    {
        $loader = new Loader();
        $loader->setCompressionManager($this->getCompressionManager())
               ->setJWTManager($this->getJWTManager())
               ->setJWKManager($this->getJWKManager())
               ->setJWKSetManager($this->getJWKSetManager())
               ->setJWAManager($this->getJWAManager());

        return $loader;
    }

    /**
     * @return Signer
     */
    protected function getSigner()
    {
        $signer = new Signer();
        $signer->setJWTManager($this->getJWTManager())
               ->setJWKManager($this->getJWKManager())
               ->setJWKSetManager($this->getJWKSetManager())
               ->setJWAManager($this->getJWAManager());

        return $signer;
    }

    /**
     * @return Encrypter
     */
    protected function getEncrypter()
    {
        $encrypter = new Encrypter();
        $encrypter->setCompressionManager($this->getCompressionManager())
                  ->setJWKManager($this->getJWKManager())
                  ->setJWKSetManager($this->getJWKSetManager())
                  ->setJWTManager($this->getJWTManager())
                  ->setJWAManager($this->getJWAManager());

        return $encrypter;
    }

    /**
     * @return JWTManager
     */
    protected function getJWTManager()
    {
        $jwt_manager = new JWTManager();

        return $jwt_manager;
    }

    /**
     * @return CompressionManager
     */
    protected function getCompressionManager()
    {
        $compression_manager = new CompressionManager();
        $compression_manager->addCompressionAlgorithm(new Deflate())
                            ->addCompressionAlgorithm(new GZip())
                            ->addCompressionAlgorithm(new ZLib());

        return $compression_manager;
    }

    /**
     * @return JWKManager
     */
    protected function getJWKManager()
    {
        $key_manager = new JWKManager();

        return $key_manager;
    }

    /**
     * @return JWKSetManager
     */
    protected function getJWKSetManager()
    {
        $keyset_manager = new JWKSetManager();
        $keyset_manager->setJWKManager($this->getJWKManager());

        return $keyset_manager;
    }

    /**
     * @return JWAManager
     */
    protected function getJWAManager()
    {
        $key_manager = new JWAManager();
        $key_manager->addAlgorithm(new HS256())
                    ->addAlgorithm(new HS384())
                    ->addAlgorithm(new HS512())
                    ->addAlgorithm(new RS256())
                    ->addAlgorithm(new RS384())
                    ->addAlgorithm(new RS512())
                    ->addAlgorithm(new PS256())
                    ->addAlgorithm(new PS384())
                    ->addAlgorithm(new PS512())
                    ->addAlgorithm(new None())
                    ->addAlgorithm(new ES256())
                    ->addAlgorithm(new ES384())
                    ->addAlgorithm(new ES512())

                    ->addAlgorithm(new A128CBCHS256())
                    ->addAlgorithm(new A192CBCHS384())
                    ->addAlgorithm(new A256CBCHS512())

                    ->addAlgorithm(new A128KW())
                    ->addAlgorithm(new A192KW())
                    ->addAlgorithm(new A256KW())
                    ->addAlgorithm(new Dir())
                    ->addAlgorithm(new ECDHES())
                    ->addAlgorithm(new ECDHESA128KW())
                    ->addAlgorithm(new ECDHESA192KW())
                    ->addAlgorithm(new ECDHESA256KW())
                    ->addAlgorithm(new PBES2HS256A128KW())
                    ->addAlgorithm(new PBES2HS384A192KW())
                    ->addAlgorithm(new PBES2HS512A256KW())
                    ->addAlgorithm(new RSA15())
                    ->addAlgorithm(new RSAOAEP())
                    ->addAlgorithm(new RSAOAEP256());

        if ($this->isCryptoExtensionAvailable()) {
            $key_manager->addAlgorithm(new A128GCM())
                        ->addAlgorithm(new A192GCM())
                        ->addAlgorithm(new A256GCM())
                        ->addAlgorithm(new A128GCMKW())
                        ->addAlgorithm(new A192GCMKW())
                        ->addAlgorithm(new A256GCMKW());
        }

        return $key_manager;
    }

    /**
     * @return bool
     */
    private function isCryptoExtensionAvailable()
    {
        return class_exists('\Crypto\Cipher');
    }
}
