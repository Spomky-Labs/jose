<?php

namespace SpomkyLabs\JOSE\Tests;

use SpomkyLabs\JOSE\JWK;
use SpomkyLabs\JOSE\Algorithm\KeyEncryption\ECDH_ES;

class ECDHESKeyAgreementTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-39#appendix-C
     */
    public function testGetAgreementKey()
    {
        $receiver = new JWK();
        $receiver->setValue('kty', 'EC')
                 ->setValue('crv', 'P-256')
                 ->setValue('x', "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ")
                 ->setValue('y', "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck")
                 ->setValue('d', "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw");

        $sender = new JWK();
        $sender->setValue("kty", "EC")
               ->setValue("crv", "P-256")
               ->setValue("x", "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0")
               ->setValue("y", "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps")
               ->setValue("d", "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo");

        $expected = [158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196];
        foreach ($expected as $key => $value) {
            $expected[$key] = str_pad(dechex($value), 2, "0", STR_PAD_LEFT);
        }
        $expected = hex2bin(implode("", $expected));

        $ecdh_es = new ECDH_ES();
        $this->assertEquals($expected, $ecdh_es->getAgreementKey($sender, $receiver));
    }
}
