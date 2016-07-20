<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Object\StorableJWK;

/**
 * Class StorableJWKTest.
 *
 * @group Unit
 * @group StorableJWK
 */
class StorableJWKTest extends \PHPUnit_Framework_TestCase
{
    public function testKey()
    {
        @unlink(sys_get_temp_dir().'/JWK.key');
        $jwk = new StorableJWK(
            sys_get_temp_dir().'/JWK.key',
            [
                'kty'   => 'EC',
                'crv' => 'P-256',
            ]
        );

        $all = $jwk->getAll();
        $this->assertEquals($all, $jwk->getAll());

        $jwk = new StorableJWK(
            sys_get_temp_dir().'/JWK.key',
            [
                'kty'   => 'EC',
                'crv' => 'P-256',
            ]
        );
        $this->assertEquals($all, $jwk->getAll());

        // We remove the file to force to creation of a new key
        @unlink(sys_get_temp_dir().'/JWK.key');
        $jwk = new StorableJWK(
            sys_get_temp_dir().'/JWK.key',
            [
                'kty'   => 'EC',
                'crv' => 'P-256',
            ]
        );
        $this->assertNotEquals($all, $jwk->getAll());
        $all = $jwk->getAll();
        $this->assertEquals($all, $jwk->getAll());
    }
}
