<?php

namespace SpomkyLabs\JOSE\Tests;

use SpomkyLabs\JOSE\Tests\Algorithm\None;

class NoneTest extends \PHPUnit_Framework_TestCase
{
    public function testNoneSignAndVerify()
    {
        $none = new None();
        $data = 'aaa';

        $signature = $none->sign($data, array(
            'alg' => 'none',
        ));

        $this->assertEquals($signature, '');
        $this->assertTrue($none->verify($data, $signature, array(
            'alg' => 'none',
        )));
    }
    public function testMethods()
    {
        $none = new None();

        $this->assertTrue($none->isPrivate());
        $this->assertEquals(array(
                'kty' => 'none',
        ),$none->getValues());
    }
}
