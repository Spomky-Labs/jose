<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Object\RotatableJWK;

/**
 * Class RotatableJWKTest.
 *
 * @group Unit
 * @group RotatableJWK
 */
class RotatableJWKTest extends \PHPUnit_Framework_TestCase
{
    public function testKey()
    {
        $jwk = new RotatableJWK(
            sys_get_temp_dir().'/JWK.key',
            [
                'kty'   => 'EC',
                'crv' => 'P-256',
            ],
            5
        );

        $all = $jwk->getAll();
        $this->assertEquals($all, $jwk->getAll());

        sleep(10);
        $this->assertNotEquals($all, $jwk->getAll());
        $all = $jwk->getAll();
        $this->assertEquals($all, $jwk->getAll());

        sleep(10);
        $this->assertNotEquals($all, $jwk->getAll());
    }
}
