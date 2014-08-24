<?php

namespace SpomkyLabs\JOSE\Algorithm;

use Mdanter\Ecc\Point;
use Mdanter\Ecc\PublicKey;
use Mdanter\Ecc\PrivateKey;
use Mdanter\Ecc\GmpUtils;
use Mdanter\Ecc\Signature;
use Mdanter\Ecc\BcMathUtils;
use Mdanter\Ecc\ModuleConfig;
use Mdanter\Ecc\NISTcurve;
use SpomkyLabs\JOSE\Util\Base64Url;
use SpomkyLabs\JOSE\JWKInterface;
use SpomkyLabs\JOSE\JWKSignInterface;
use SpomkyLabs\JOSE\JWKVerifyInterface;
use SpomkyLabs\JOSE\JWKEncryptInterface;
use SpomkyLabs\JOSE\JWKDecryptInterface;
use SpomkyLabs\JOSE\JWKContentEncryptionInterface;
use SpomkyLabs\JOSE\JWKAuthenticationTagInterface;

/**
 * This class handles
 *     - signatures using Elliptic Curves (ES256, ES384 and ES512).
 *     - encryption of text using ECDH-ES algorithm.
 */
abstract class EC implements JWKInterface, JWKSignInterface, JWKVerifyInterface, JWKEncryptInterface, JWKDecryptInterface, JWKContentEncryptionInterface, JWKAuthenticationTagInterface
{
    public function __toString()
    {
        return json_encode($this->getValues());
    }

    public function toPublic()
    {
        $values = $this->getValues();

        if ( isset($values['d'])) {
            unset($values['d']);
        }

        return $values;
    }

    public function isPrivate()
    {
        return $this->isPublic() && $this->getValue('d') !== null;
    }

    public function isPublic()
    {
        return $this->getValue('x') !== null && $this->getValue('y') !== null;
    }

    /**
     * @inheritdoc
     */
    public function sign($data, array $header = array())
    {
        if (!$this->isPrivate()) {
            throw new \Exception('This is not a private JWK');
        }

        $p     = $this->getGenerator();
        $curve = $this->getCurve();
        $x     = $this->convertBase64ToDec($this->getValue('x'));
        $y     = $this->convertBase64ToDec($this->getValue('y'));
        $d     = $this->convertBase64ToDec($this->getValue('d'));
        $hash  = $this->convertHexToDec(hash($this->getHashAlgorithm(),$data));

        if (ModuleConfig::hasGmp()) {
            $k = GmpUtils::gmpRandom($p->getOrder());
        } elseif (ModuleConfig::hasBcMath()) {
            $k = BcMathUtils::bcrand($p->getOrder());
        }

        $public_key = new PublicKey($p, new Point($curve, $x, $y));
        $private_key = new PrivateKey($public_key, $d);
        $sign = $private_key->sign($hash, $k);

        $R = $this->convertDecToHex($sign->getR());
        $S = $this->convertDecToHex($sign->getS());

        $part_length = $this->getSignaturePartLength();
        if (strlen($R)!==$part_length) {
            while (strlen($R)<$part_length) {
                $R = "0".$R;
            }
        }
        if (strlen($S)!==$part_length) {
            while (strlen($S)<$part_length) {
                $S = "0".$S;
            }
        }

        return $this->convertHextoBin($R.$S);
    }

    /**
     * @inheritdoc
     */
    public function verify($data, $signature, array $header = array())
    {
        $signature = $this->convertBinToHex($signature);
        $part_length = $this->getSignaturePartLength();
        if ( strlen($signature) !== 2*$part_length) {
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

    /**
     * @inheritdoc
     */
    public function encrypt($data, array &$header = array())
    {
        //x & y === pub key of the receiver
        //pub->x & pub->y === pub key of the sender

        $p      = $this->getGenerator();
        $curve  = $this->getCurve();
        $rec_x  = $this->convertBase64ToDec($this->getValue('x'));
        $rec_y  = $this->convertBase64ToDec($this->getValue('y'));
        $sen_x  = $header['sender_private_key']['x'];
        $sen_y  = $header['sender_private_key']['y'];
        $sen_d = $this->convertBase64ToDec($header['sender_private_key']['d']);

        $ext = new ECDHExtension($p, $sen_d);
        $ext->setReceiverPoint(new Point($curve, $rec_x, $rec_y));

        unset($header['sender_private_key']);
        $header['epk'] = array(
            "kty"=>"EC",
            "crv"=>"P-256",
            'x' => $sen_x,
            'y' => $sen_y
        );
        
        $enc = $ext->encrypt($data);
        return $enc;
    }

    /**
     * @inheritdoc
     */
    public function decrypt($data, array $header = array())
    {
        $p      = $this->getGenerator();
        $curve  = $this->getCurve();
        $rec_d  = $this->convertBase64ToDec($this->getValue('d'));
        $sen_x  = $this->convertBase64ToDec($header['epk']['x']);
        $sen_y  = $this->convertBase64ToDec($header['epk']['y']);

        $ext = new ECDHExtension($p, $rec_d);
        $ext->setReceiverPoint(new Point($curve, $sen_x, $sen_y));

        $dec = $ext->decrypt($data);
        return $dec;
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

    protected function convertDecToBin($value)
    {
        return pack("H*",$this->convertDecToHex($value));
    }

    /**
     * @param string $value
     */
    protected function convertHexToBin($value)
    {
        return pack("H*",$value);
    }

    protected function convertBinToHex($value)
    {
        $value = unpack('H*',$value);

        return $value[1];
    }

    protected function convertBinToDec($value)
    {
        $value = unpack('H*',$value);

        return $this->convertHexToDec($value[1]);
    }

    protected function convertDecToHex($value)
    {
        if (ModuleConfig::hasGmp()) {
            return GmpUtils::gmpDecHex($value);
        } elseif (ModuleConfig::hasBcMath()) {
            return BcMathUtils::bcdechex($value);
        } else {
            throw new \RuntimeException("Please install BCMATH or GMP");
        }
    }

    protected function convertHexToDec($value)
    {
        if (ModuleConfig::hasGmp()) {
            return GmpUtils::gmpHexDec($value);
        } elseif (ModuleConfig::hasBcMath()) {
            return BcMathUtils::bchexdec($value);
        } else {
            throw new \RuntimeException("Please install BCMATH or GMP");
        }
    }

    protected function convertDecToBase64($value)
    {
        return Base64Url::encode($this->convertDecToHex($value));
    }

    protected function convertBase64ToDec($value)
    {
        $value = unpack('H*',Base64Url::decode($value));

        return $this->convertHexToDec($value[1]);
    }

    public function calculateAuthenticationTag($data)
    {
        $mac_key          = substr($this->getValue('cek'), 0, strlen($this->getValue('cek'))/2);
        $auth_data        = Base64Url::encode(json_encode($data['header']));
        $auth_data_length = strlen($auth_data);

        $secured_input = implode('', array(
            $auth_data,
            $data['iv'],
            $data['encrypted_data'],
            // NOTE: PHP doesn't support 64bit big endian, so handling upper & lower 32bit.
            pack('N2', ($auth_data_length / 2147483647) * 8, ($auth_data_length % 2147483647) * 8)
        ));
        $hash = hash_hmac($this->getHashAlgorithm(), $secured_input, $mac_key, true);

        return substr($hash, 0, strlen($hash)/2);
    }

    public function checkAuthenticationTag($data)
    {
        return $data['authentication_tag'] === $this->calculateAuthenticationTag($data);
    }

    public function createIV()
    {
        $iv = null;
        $enc = $this->getValue('enc');
        switch ($enc) {
            case 'A128CBC-HS256':
                $iv = $this->generateRandomString(128 / 8);
                break;
            case 'A192CBC-HS384':
                $iv = $this->generateRandomString(192 / 8);
                break;
            case 'A256CBC-HS512':
                $iv = $this->generateRandomString(256 / 8);
                break;
            default:
                throw new \Exception("Algorithm $enc is not supported");
        }
        $this->setValue('iv', $iv);

        return $this;
    }

    public function createCEK()
    {
        $cek = null;
        $enc = $this->getValue('enc');
        switch ($enc) {
            case 'A128CBC-HS256':
                $cek = $this->generateRandomString(256 / 8);
                break;
            case 'A192CBC-HS384':
                $cek = $this->generateRandomString(384 / 8);
                break;
            case 'A256CBC-HS512':
                $cek = $this->generateRandomString(512 / 8);
                break;
            default:
                throw new \Exception("Algorithm $enc is not supported");
        }
        $this->setValue('cek', $cek);

        return $this;
    }

    /**
     * @param integer $length
     */
    protected function generateRandomString($length)
    {
        return crypt_random_string($length);
    }
}
