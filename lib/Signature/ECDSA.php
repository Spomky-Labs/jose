<?php

namespace SpomkyLabs\JOSE\Signature;

use Mdanter\Ecc\Point;
use Mdanter\Ecc\PublicKey;
use Mdanter\Ecc\PrivateKey;
use Mdanter\Ecc\Signature;
use Mdanter\Ecc\GmpUtils;
use Mdanter\Ecc\BcMathUtils;
use Mdanter\Ecc\ModuleConfig;
use Mdanter\Ecc\NISTcurve;
use SpomkyLabs\JOSE\Base64Url;
use SpomkyLabs\JOSE\JWKInterface;
use SpomkyLabs\JOSE\JWKSignInterface;
use SpomkyLabs\JOSE\JWKVerifyInterface;

/**
 * This class handles signatures using Elliptic Curves.
 * It supports algorithms ES256, ES384 and ES512;
 */
abstract class ECDSA implements JWKInterface, JWKSignInterface, JWKVerifyInterface
{
    public function toPrivate()
    {
        $values = $this->getValues()+array(
            'kty' => 'EC',
        );

        return $values;
    }

    public function toPublic()
    {
        $values = $this->toPrivate();

        if( isset($values['d']))
        {
            unset($values['d']);
        }

        return $values;
    }

    public function isPrivate()
    {
        return $this->getValue('d') !== null;
    }
    
    /**
     * @inheritdoc
     */
    public function sign($data)
    {
        if(!$this->isPrivate())
        {
            throw new \Exception('This is not a private JWK');
        }

        $this->checkData();

        $p     = $this->getGenerator();
        $curve = $this->getCurve();
        $x     = $this->convertBase64ToDec($this->getValue('x'));
        $y     = $this->convertBase64ToDec($this->getValue('y'));
        $d     = $this->convertBase64ToDec($this->getValue('d'));
        $hash  = $this->convertHexToDec(hash($this->getHashAlgorithm(),$data));

        if(ModuleConfig::hasGmp())
        {
            $k = GmpUtils::gmpRandom($p->getOrder());
        }
        elseif(ModuleConfig::hasBcMath())
        {
            $k = BcMathUtils::bcrand($p->getOrder());
        }

        $public_key = new PublicKey($p, new Point($curve, $x, $y));
        $private_key = new PrivateKey($public_key, $d);
        $sign = $private_key->sign($hash, $k);

        $R = $this->convertDecToHex($sign->getR());
        $S = $this->convertDecToHex($sign->getS());

        $part_length = $this->getSignaturePartLength();
        if(strlen($R)!==$part_length)
        {
            while(strlen($R)<$part_length)
            {
                $R = "0".$R;
            }
        }
        if(strlen($S)!==$part_length)
        {
            while(strlen($S)<$part_length)
            {
                $S = "0".$S;
            }
        }
        return Base64Url::encode($this->convertHextoBin($R.$S));
    }

    /**
     * @inheritdoc
     */
    public function verify($data, $signature)
    {
        $this->checkData();

        $signature = $this->convertBinToHex(Base64Url::decode($signature));
        $part_length = $this->getSignaturePartLength();
        if( strlen($signature) !== 2*$part_length)
        {
            return false;
        }


        $p     = $this->getGenerator();
        $curve = $this->getCurve();
        $x     = $this->convertBase64ToDec($this->getValue('x'));
        $y     = $this->convertBase64ToDec($this->getValue('y'));
        $R     = $this->convertHexToDec(substr($signature, 0, $part_length));
        $S     = $this->convertHexToDec(substr($signature, $part_length));
        $hash  = $this->convertHexToDec(hash($this->getHashAlgorithm(),$data));

        $public_key = new PublicKey($p, new Point($curve, $x, $y));

        return $public_key->verifies($hash, new Signature($R, $S));
    }

    protected function getHashAlgorithm()
    {
        $crv = $this->getValue('crv');
        switch ($crv) {
            case 'P-256':
                return 'SHA256';
            case 'P-384':
                return 'SHA384';
            case 'P-521':
                return 'SHA512';
            default:
                throw new \Exception("Curve $crv is not supported");
        }
    }

    protected function getSignaturePartLength()
    {
        $crv = $this->getValue('crv');
        switch ($crv) {
            case 'P-256':
                return 64;
            case 'P-384':
                return 96;
            case 'P-521':
                return 132;
            default:
                throw new \Exception("Curve $crv is not supported");
        }
    }

    protected function getCurve()
    {
        $crv = $this->getValue('crv');
        switch ($crv) {
            case 'P-256':
                return NISTcurve::curve256();
            case 'P-384':
                return NISTcurve::curve384();
            case 'P-521':
                return NISTcurve::curve521();
            default:
                throw new \Exception("Curve $crv is not supported");
        }
    }

    protected function getGenerator()
    {
        $crv = $this->getValue('crv');
        switch ($crv) {
            case 'P-256':
                return NISTcurve::generator256();
            case 'P-384':
                return NISTcurve::generator384();
            case 'P-521':
                return NISTcurve::generator521();
            default:
                throw new \Exception("Curve $crv is not supported");
        }
    }

    private function convertDecToBin($value)
    {
        return pack("H*",$this->convertDecToHex($value));
    }

    private function convertHexToBin($value)
    {
        return pack("H*",$value);
    }

    private function convertBinToHex($value)
    {
        $value = unpack('H*',$value);
        return $value[1];
    }

    private function convertBinToDec($value)
    {
        $value = unpack('H*',$value);
        return $this->convertHexToDec($value[1]);
    }

    private function convertDecToHex($value)
    {
        if(ModuleConfig::hasGmp())
        {
            return GmpUtils::gmpDecHex($value);
        }
        elseif(ModuleConfig::hasBcMath())
        {
            return BcMathUtils::bcdechex($value);
        }
        else
        {
            throw new \RuntimeException("Please install BCMATH or GMP");
        }
    }

    private function convertHexToDec($value)
    {
        if(ModuleConfig::hasGmp())
        {
            return GmpUtils::gmpHexDec($value);
        }
        elseif(ModuleConfig::hasBcMath())
        {
            return BcMathUtils::bchexdec($value);
        }
        else
        {
            throw new \RuntimeException("Please install BCMATH or GMP");
        }
    }

    private function convertBase64ToDec($value)
    {
        $value = unpack('H*',Base64Url::decode($value));
        
        return $this->convertHexToDec($value[1]);
    }

    private function checkData()
    {
        if($this->getValue('x') === null || $this->getValue('y') === null)
        {
            throw new \Exception("'x' or 'y' value is not dfined");
        }
    }
}
