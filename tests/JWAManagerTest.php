<?php

namespace SpomkyLabs\JOSE\Tests;

use SpomkyLabs\JOSE\Algorithm\JWAManager;
use SpomkyLabs\JOSE\Algorithm\Signature\ES256;
use SpomkyLabs\JOSE\Algorithm\Signature\ES384;
use SpomkyLabs\JOSE\Algorithm\Signature\ES512;

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
