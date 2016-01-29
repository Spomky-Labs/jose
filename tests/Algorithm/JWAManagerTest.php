<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Algorithm\Signature\ES384;
use Jose\Factory\AlgorithmManagerFactory;
use Jose\Test\TestCase;

/**
 * Class JWAManagerTest.
 *
 * @group JWA
 */
class JWAManagerTest extends TestCase
{
    /**
     *
     */
    public function testAlgorithmIsSupported()
    {
        $jwa_manager = AlgorithmManagerFactory::createAlgorithmManager(['ES256', 'ES384']);

        $this->assertTrue($jwa_manager->isAlgorithmSupported('ES256'));
        $this->assertTrue($jwa_manager->isAlgorithmSupported('ES384'));

        $this->assertFalse($jwa_manager->isAlgorithmSupported('ES512'));
        $this->assertFalse($jwa_manager->isAlgorithmSupported('HS384'));

        $this->assertEquals(['ES256', 'ES384'], $jwa_manager->listAlgorithms());
        $this->assertInstanceOf('\Jose\Algorithm\JWAInterface', $jwa_manager->getAlgorithm('ES256'));
        $this->assertInstanceOf('\Jose\Algorithm\JWAInterface', $jwa_manager->getAlgorithms()['ES256']);

        $jwa_manager->removeAlgorithm('ES256');
        $jwa_manager->removeAlgorithm('ES256');

        $this->assertNull($jwa_manager->getAlgorithm('ES256'));
        $this->assertEquals(['ES384'], $jwa_manager->listAlgorithms());

        $jwa_manager->removeAlgorithm(new ES384());

        $this->assertNull($jwa_manager->getAlgorithm('HS384'));
        $this->assertEquals([], $jwa_manager->listAlgorithms());
    }
}
