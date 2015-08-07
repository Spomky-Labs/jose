<?php

namespace SpomkyLabs\Jose\Tests\Stub;

use Jose\JWAManagerInterface;
use Jose\JWTManagerInterface;
use Jose\JWKManagerInterface;
use Jose\JWKSetManagerInterface;
use Jose\Compression\CompressionManagerInterface;
use SpomkyLabs\Jose\Checker\AudienceChecker;
use SpomkyLabs\Jose\Checker\CheckerManager;
use SpomkyLabs\Jose\Checker\CriticalChecker;
use SpomkyLabs\Jose\Checker\ExpirationChecker;
use SpomkyLabs\Jose\Checker\IssuedAtChecker;
use SpomkyLabs\Jose\Checker\NotBeforeChecker;
use SpomkyLabs\Jose\Loader as Base;
use SpomkyLabs\Jose\Payload\JWKConverter;
use SpomkyLabs\Jose\Payload\JWKSetConverter;
use SpomkyLabs\Jose\Payload\PayloadConverterManager;
use SpomkyLabs\Jose\Payload\PrimitiveConverter;

/**
 * Class representing a JSON Web Signature.
 */
class Loader extends Base
{
    protected $jwt_manager;
    protected $jwa_manager;
    protected $jwk_manager;
    protected $jwkset_manager;
    protected $compression_manager;
    protected $checker_manager = null;
    protected $payload_converter_manager = null;

    /**
     * {@inheritdoc}
     */
    protected function getPayloadConverter()
    {
        if (is_null($this->payload_converter_manager)) {
            $this->payload_converter_manager = new PayloadConverterManager();
            $this->payload_converter_manager->addConverter(new JWKConverter($this->getJWKManager()))
                ->addConverter(new JWKSetConverter($this->getJWKSetManager()));
        }

        return $this->payload_converter_manager;
    }

    protected function getAudience()
    {
        return 'www.example.com';
    }

    /**
     * {@inheritdoc}
     */
    protected function getJWTManager()
    {
        return $this->jwt_manager;
    }

    public function setJWTManager(JWTManagerInterface $jwt_manager)
    {
        $this->jwt_manager = $jwt_manager;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    protected function getJWAManager()
    {
        return $this->jwa_manager;
    }

    public function setJWAManager(JWAManagerInterface $jwa_manager)
    {
        $this->jwa_manager = $jwa_manager;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    protected function getJWKManager()
    {
        return $this->jwk_manager;
    }

    public function setJWKManager(JWKManagerInterface $jwk_manager)
    {
        $this->jwk_manager = $jwk_manager;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    protected function getJWKSetManager()
    {
        return $this->jwkset_manager;
    }

    public function setJWKSetManager(JWKSetManagerInterface $jwkset_manager)
    {
        $this->jwkset_manager = $jwkset_manager;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    protected function getCompressionManager()
    {
        return $this->compression_manager;
    }

    public function setCompressionManager(CompressionManagerInterface $compression_manager)
    {
        $this->compression_manager = $compression_manager;

        return $this;
    }

    /**
     * @return \SpomkyLabs\Jose\Checker\CheckerManagerInterface
     */
    protected function getCheckerManager()
    {
        if (is_null($this->checker_manager)) {
            $this->checker_manager = new CheckerManager();
            $this->checker_manager->addChecker(new AudienceChecker('my service'))
                                  ->addChecker(new IssuedAtChecker())
                                  ->addChecker(new NotBeforeChecker())
                                  ->addChecker(new ExpirationChecker())
                                  ->addChecker(new CriticalChecker());
        }
        return $this->checker_manager;
    }
}
