<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test;

use Jose\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Algorithm\ContentEncryption\A128GCM;
use Jose\Algorithm\ContentEncryption\A192CBCHS384;
use Jose\Algorithm\ContentEncryption\A192GCM;
use Jose\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Algorithm\ContentEncryption\A256GCM;
use Jose\Algorithm\KeyEncryption\A128GCMKW;
use Jose\Algorithm\KeyEncryption\A128KW;
use Jose\Algorithm\KeyEncryption\A192GCMKW;
use Jose\Algorithm\KeyEncryption\A192KW;
use Jose\Algorithm\KeyEncryption\A256GCMKW;
use Jose\Algorithm\KeyEncryption\A256KW;
use Jose\Algorithm\KeyEncryption\Dir;
use Jose\Algorithm\KeyEncryption\ECDHES;
use Jose\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Algorithm\KeyEncryption\ECDHESA192KW;
use Jose\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Algorithm\KeyEncryption\PBES2HS256A128KW;
use Jose\Algorithm\KeyEncryption\PBES2HS384A192KW;
use Jose\Algorithm\KeyEncryption\PBES2HS512A256KW;
use Jose\Algorithm\KeyEncryption\RSA15;
use Jose\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Algorithm\Signature\ES256;
use Jose\Algorithm\Signature\ES384;
use Jose\Algorithm\Signature\ES512;
use Jose\Algorithm\Signature\HS256;
use Jose\Algorithm\Signature\HS384;
use Jose\Algorithm\Signature\HS512;
use Jose\Algorithm\Signature\None;
use Jose\Algorithm\Signature\PS256;
use Jose\Algorithm\Signature\PS384;
use Jose\Algorithm\Signature\PS512;
use Jose\Algorithm\Signature\RS256;
use Jose\Algorithm\Signature\RS384;
use Jose\Algorithm\Signature\RS512;
use Jose\Checker\AudienceChecker;
use Jose\Checker\CheckerManager;
use Jose\Checker\CriticalChecker;
use Jose\Checker\ExpirationChecker;
use Jose\Checker\IssuedAtChecker;
use Jose\Checker\NotBeforeChecker;
use Jose\Compression\CompressionManager;
use Jose\Compression\Deflate;
use Jose\Compression\GZip;
use Jose\Compression\ZLib;
use Jose\Encrypter;
use Jose\Finder\JKUFinder;
use Jose\Finder\JWKFinder;
use Jose\Finder\X5CFinder;
use Jose\Finder\X5UFinder;
use Jose\JWAManager;
use Jose\JWKManager;
use Jose\JWKSetManager;
use Jose\JWTManager;
use Jose\Loader;
use Jose\Payload\JWKConverter;
use Jose\Payload\JWKSetConverter;
use Jose\Payload\PayloadConverterManager;
use Jose\Signer;
use Jose\Test\Stub\AlgorithmFinder;
use Jose\Test\Stub\APVFinder;
use Jose\Test\Stub\IssuerChecker;
use Jose\Test\Stub\KIDFinder;
use Jose\Test\Stub\SubjectChecker;

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
               ->setJWAManager($this->getJWAManager())
               ->setCheckerManager($this->getCheckerManager())
               ->setPayloadConverter($this->getPayloadConverterManager());

        return $loader;
    }

    /**
     * @return Signer
     */
    protected function getSigner()
    {
        $signer = new Signer();
        $signer->setJWTManager($this->getJWTManager())
               ->setJWAManager($this->getJWAManager())
               ->setPayloadConverter($this->getPayloadConverterManager());

        return $signer;
    }

    /**
     * @return Encrypter
     */
    protected function getEncrypter()
    {
        $encrypter = new Encrypter();
        $encrypter->setCompressionManager($this->getCompressionManager())
                  ->setJWTManager($this->getJWTManager())
                  ->setJWAManager($this->getJWAManager())
                  ->setPayloadConverter($this->getPayloadConverterManager());

        return $encrypter;
    }

    /**
     * @return \Jose\Checker\CheckerManagerInterface
     */
    protected function getCheckerManager()
    {
        $checker_manager = new CheckerManager();

        $checker_manager->addChecker(new AudienceChecker('My service'))
                        ->addChecker(new CriticalChecker())
                        ->addChecker(new ExpirationChecker())
                        ->addChecker(new NotBeforeChecker())
                        ->addChecker(new IssuedAtChecker())
                        ->addChecker(new IssuerChecker())
                        ->addChecker(new SubjectChecker());

        return $checker_manager;
    }

    /**
     * @return \Jose\Payload\PayloadConverterManagerInterface
     */
    protected function getPayloadConverterManager()
    {
        $payload_converter_manager = new PayloadConverterManager();
        $payload_converter_manager->addConverter(new JWKConverter($this->getJWKManager()))
                                  ->addConverter(new JWKSetConverter($this->getJWKSetManager()));

        return $payload_converter_manager;
    }

    /**
     * @return \Jose\JWTManager
     */
    protected function getJWTManager()
    {
        $jwt_manager = new JWTManager();

        return $jwt_manager;
    }

    /**
     * @return \Jose\Compression\CompressionManager
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
     * @return \Jose\JWKManager
     */
    protected function getJWKManager()
    {
        $key_manager = new JWKManager();
        $key_manager->addJWKFinder(new JWKFinder())
            ->addJWKFinder(new X5CFinder())
            ->addJWKFinder(new APVFinder())
            ->addJWKFinder(new KIDFinder());

        return $key_manager;
    }

    /**
     * @return \Jose\JWKSetManager
     */
    protected function getJWKSetManager()
    {
        $keyset_manager = new JWKSetManager();
        $keyset_manager->addJWKSetFinder(new JKUFinder())
            ->addJWKSetFinder(new X5UFinder())
            ->addJWKSetFinder(new AlgorithmFinder())
            ->setJWKManager($this->getJWKManager());

        return $keyset_manager;
    }

    /**
     * @return \Jose\JWAManager
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
