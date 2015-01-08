<?php

namespace SpomkyLabs\Jose\Tests;

use SpomkyLabs\Jose\JWAManager;
use SpomkyLabs\Jose\Algorithm\Signature\ES256;
use SpomkyLabs\Jose\Algorithm\Signature\ES384;
use SpomkyLabs\Jose\Algorithm\Signature\ES512;

class JWAManagerTest extends \PHPUnit_Framework_TestCase
{
    public function testAlgorithmIsSupported()
    {
        $jwa_manager = new JWAManager();
        $jwa_manager->addAlgorithm(new ES256())
                    ->addAlgorithm(new ES384())
                    ->addAlgorithm(new ES512());

        $this->assertTrue($jwa_manager->isAlgorithmSupported("ES256"));
        $this->assertFalse($jwa_manager->isAlgorithmSupported("RS256"));

        $jwa_manager->removeAlgorithm("ES256");

        $this->assertFalse($jwa_manager->isAlgorithmSupported("ES256"));
    }
}
