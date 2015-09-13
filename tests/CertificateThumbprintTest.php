<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Test;

use SpomkyLabs\Jose\KeyConverter\X509Thumbprint;

/**
 * @group Certificate
 */
class CertificateThumbprintTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @dataProvider dataThumbprint
     */
    public function testThumbprint($hash, $pem, $expected_thumbprint)
    {
        $thumbprint = X509Thumbprint::calculateThumbprint($pem, $hash);

        $this->assertEquals($expected_thumbprint, $thumbprint);
    }

    public function dataThumbprint()
    {
        return [
            [
                'sha1',
                file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'Keys'.DIRECTORY_SEPARATOR.'Certificate'.DIRECTORY_SEPARATOR.'CACert.crt'),
                '135cec36f49cb8e93b1ab270cd80884676ce8f33'
            ],
            [
                'sha256',
                file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'Keys'.DIRECTORY_SEPARATOR.'Certificate'.DIRECTORY_SEPARATOR.'CACert.crt'),
                'ff2a65cff1149c7430101e0f65a07ec19183a3b633ef4a6510890dad18316b3a'
            ],
        ];
    }
}
