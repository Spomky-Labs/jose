<?php

namespace SpomkyLabs\Jose\Tests;

use SpomkyLabs\Jose\JWAManager;
use SpomkyLabs\Jose\Compression\GZip;
use SpomkyLabs\Jose\Compression\ZLib;
use SpomkyLabs\Jose\Compression\Deflate;
use SpomkyLabs\Jose\Tests\Stub\Loader;
use SpomkyLabs\Jose\Tests\Stub\Signer;
use SpomkyLabs\Jose\Tests\Stub\Encrypter;
use SpomkyLabs\Jose\Tests\Stub\JWKManager;
use SpomkyLabs\Jose\Tests\Stub\JWTManager;
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
use SpomkyLabs\Jose\Algorithm\ContentEncryption\A128CBC_HS256;
use SpomkyLabs\Jose\Algorithm\ContentEncryption\A192CBC_HS384;
use SpomkyLabs\Jose\Algorithm\ContentEncryption\A256CBC_HS512;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\A128KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\A192KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\A256KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\A128GCMKW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\A192GCMKW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\A256GCMKW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\Dir;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\ECDH_ES;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\ECDH_ES_A128KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\ECDH_ES_A192KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\ECDH_ES_A256KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\PBES2_HS256_A128KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\PBES2_HS384_A192KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\PBES2_HS512_A256KW;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\RSA1_5;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\RSA_OAEP;
use SpomkyLabs\Jose\Algorithm\KeyEncryption\RSA_OAEP_256;

class TestCase extends \PHPUnit_Framework_TestCase
{
    protected function getLoader()
    {
        $loader = new Loader();
        $loader->setCompressionManager($this->getCompressionManager())
               ->setJWTManager($this->getJWTManager())
               ->setJWKManager($this->getJWKManager())
               ->setJWAManager($this->getJWAManager());

        return $loader;
    }

    protected function getSigner()
    {
        $signer = new Signer();
        $signer->setJWTManager($this->getJWTManager())
               ->setJWKManager($this->getJWKManager())
               ->setJWAManager($this->getJWAManager());

        return $signer;
    }

    protected function getEncrypter()
    {
        $encrypter = new Encrypter();
        $encrypter->setCompressionManager($this->getCompressionManager())
                  ->setJWTManager($this->getJWTManager())
                  ->setJWKManager($this->getJWKManager())
                  ->setJWAManager($this->getJWAManager());

        return $encrypter;
    }

    protected function getJWTManager()
    {
        $jwt_manager = new JWTManager();

        return $jwt_manager;
    }

    protected function getCompressionManager()
    {
        $compression_manager = new CompressionManager();
        $compression_manager->addCompressionAlgorithm(new Deflate())
                            ->addCompressionAlgorithm(new GZip())
                            ->addCompressionAlgorithm(new ZLib());

        return $compression_manager;
    }

    protected function getJWKManager()
    {
        $key_manager = new JWKManager();

        return $key_manager;
    }

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

                    ->addAlgorithm(new A128GCM())
                    ->addAlgorithm(new A192GCM())
                    ->addAlgorithm(new A256GCM())
                    ->addAlgorithm(new A128CBC_HS256())
                    ->addAlgorithm(new A192CBC_HS384())
                    ->addAlgorithm(new A256CBC_HS512())

                    ->addAlgorithm(new A128KW())
                    ->addAlgorithm(new A192KW())
                    ->addAlgorithm(new A256KW())
                    ->addAlgorithm(new A128GCMKW())
                    ->addAlgorithm(new A192GCMKW())
                    ->addAlgorithm(new A256GCMKW())
                    ->addAlgorithm(new Dir())
                    ->addAlgorithm(new ECDH_ES())
                    ->addAlgorithm(new ECDH_ES_A128KW())
                    ->addAlgorithm(new ECDH_ES_A192KW())
                    ->addAlgorithm(new ECDH_ES_A256KW())
                    ->addAlgorithm(new PBES2_HS256_A128KW())
                    ->addAlgorithm(new PBES2_HS384_A192KW())
                    ->addAlgorithm(new PBES2_HS512_A256KW())
                    ->addAlgorithm(new RSA1_5())
                    ->addAlgorithm(new RSA_OAEP())
                    ->addAlgorithm(new RSA_OAEP_256());

        return $key_manager;
    }
}
