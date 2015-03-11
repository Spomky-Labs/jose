<?php

namespace SpomkyLabs\jose\tests;

use SpomkyLabs\Jose\Util\ECConverter;

class ECKeysTest extends TestCase
{
    /**
     */
    public function testLoadPublicEC256Key()
    {
        $details = ECConverter::loadKeyFromFile("file://".__DIR__.DIRECTORY_SEPARATOR."Keys".DIRECTORY_SEPARATOR."EC".DIRECTORY_SEPARATOR."public.es256.key");
        $this->assertEquals($details, array(
            'kty' => 'EC',
            'x' => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y' => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',

        ));
    }

    /**
     */
    public function testLoadPrivateEC256Key()
    {
        $details = ECConverter::loadKeyFromFile("file://".__DIR__.DIRECTORY_SEPARATOR."Keys".DIRECTORY_SEPARATOR."EC".DIRECTORY_SEPARATOR."private.es256.key");
        $this->assertEquals($details, array(
            'kty' => 'EC',
            'd' => 'q_VkzNnxTG39jHB0qkwA_SeVXud7yCHT7kb7kZv-0xQ',
            'x' => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y' => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',
        ));
    }

    /**
     */
    public function testLoadPublicEC384Key()
    {
        $details = ECConverter::loadKeyFromFile("file://".__DIR__.DIRECTORY_SEPARATOR."Keys".DIRECTORY_SEPARATOR."EC".DIRECTORY_SEPARATOR."public.es384.key");
        $this->assertEquals($details, array(
            'kty' => 'EC',
            'x' => '6f-XZsg2Tvn0EoEapQ-ylMYNtsm8CPf0cb8HI2EkfY9Bqpt3QMzwlM7mVsFRmaMZ',
            'y' => 'b8nOnRwmpmEnvA2U8ydS-dbnPv7bwYl-q1qNeh8Wpjor3VO-RTt4ce0Pn25oGGWU',

        ));
    }

    /**
     */
    public function testLoadPrivateEC384Key()
    {
        $details = ECConverter::loadKeyFromFile("file://".__DIR__.DIRECTORY_SEPARATOR."Keys".DIRECTORY_SEPARATOR."EC".DIRECTORY_SEPARATOR."private.es384.key");
        $this->assertEquals($details, array(
            'kty' => 'EC',
            'd' => 'pcSSXrbeZEOaBIs7IwqcU9M_OOM81XhZuOHoGgmS_2PdECwcdQcXzv7W8-lYL0cr',
            'x' => '6f-XZsg2Tvn0EoEapQ-ylMYNtsm8CPf0cb8HI2EkfY9Bqpt3QMzwlM7mVsFRmaMZ',
            'y' => 'b8nOnRwmpmEnvA2U8ydS-dbnPv7bwYl-q1qNeh8Wpjor3VO-RTt4ce0Pn25oGGWU',
        ));
    }

    /**
     */
    public function testLoadPublicEC512Key()
    {
        $details = ECConverter::loadKeyFromFile("file://".__DIR__.DIRECTORY_SEPARATOR."Keys".DIRECTORY_SEPARATOR."EC".DIRECTORY_SEPARATOR."public.es512.key");
        $this->assertEquals($details, array(
            'kty' => 'EC',
            'x' => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
            'y' => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',

        ));
    }

    /**
     */
    public function testLoadPrivateEC512Key()
    {
        $details = ECConverter::loadKeyFromFile("file://".__DIR__.DIRECTORY_SEPARATOR."Keys".DIRECTORY_SEPARATOR."EC".DIRECTORY_SEPARATOR."private.es512.key");
        $this->assertEquals($details, array(
            'kty' => 'EC',
            'd' => 'Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE',
            'x' => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
            'y' => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',

        ));
    }
}
