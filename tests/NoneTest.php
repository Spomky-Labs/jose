<?php

namespace SpomkyLabs\JOSE\Tests;

use SpomkyLabs\JOSE\Signature\None;

class NoneTest extends \PHPUnit_Framework_TestCase
{
    public function testNoneSignAndVerify()
    {
        $none = new None();
        $data = 'aaa';

        $signature = $none->sign($data);

        $this->assertEquals($signature, '');
        $this->assertTrue($none->verify($data, $signature));
    }
    public function testMethods()
    {
        $none = new None();

        $this->assertTrue($none->isPrivate());
        $this->assertEquals(array(
                'alg' => 'none',
        ),$none->getValues());
    }
}
