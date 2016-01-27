<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Algorithm\Signature\ES256;
use Jose\Algorithm\Signature\ES384;
use Jose\Factory\AlgorithmManagerFactory;
use Jose\Test\TestCase;

/**
 * Class JWAManagerTest.
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
    }
}
