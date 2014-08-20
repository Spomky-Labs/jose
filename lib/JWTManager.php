<?php

namespace SpomkyLabs\JOSE;

use SpomkyLabs\JOSE\Util\Base64Url;

/**
 * Class representing a JSON Web Token Manager.
 */
abstract class JWTManager implements JWTManagerInterface
{
    abstract protected function getKeyManager();

    public function load($data)
    {
        //We try to identity if the data is a JSON object. In this case, we consider that data is a JWE or JWS Seralization object
        if (json_decode($data,true) !== null) {
            return $this->loadSerializedJson($data);
        }

        //Else, we consider that data is a JWE or JWS Compact Seralized object
        return $this->loadCompactSerializedJson($data);
    }

    public function convertToCompactSerializedJson($input, JWKInterface $jwk, array $header = array())
    {
        if (is_array($input)) {
            $input = json_encode($input);
        }
        if (!is_string($input) && !$input instanceof JWTInterface && !$input instanceof JWKInterface && !$input instanceof JWKSetInterface) {
            throw new \Exception("Unsupported input type");
        }

        if (!$jwk->isPrivate()) {
            throw new \Exception("The key is not a private key");
        }

        //We try to encrypt first
        if ($this->getKeyManager()->canEncrypt($jwk)) {

            $plaintext = '';
            if (is_string($input)) {
                $plaintext = $input;
            } elseif ($input instanceof JWKInterface || $input instanceof JWKSetInterface) {
                $header['cty'] = $input instanceof JWKInterface ? 'jwk+json' : 'jwkset+json';
                $plaintext = $input->__toString();
            }

            $header['alg'] = $jwk->getValue('alg');
            $data = array(
                'header'=>$header,
            );
            $key = $this->getKeyManager()->createJWK(array(
                "enc" =>$data['header']['enc'],
            ));
            if (!$key instanceof JWKContentEncryptionInterface) {
                throw new \Exception("The content encryption algorithm is not valid");
            }

            $key->createIV();

            if ($data['header']['alg'] === 'dir') {
                $key->setValue('cek', $jwk->getValue('dir'));
            } else {
                $key->createCEK();
            }

            $data['iv'] = $key->getValue('iv');
            $data['encrypted_cek'] = $jwk->encrypt($key->getValue('cek'));
            $data['encrypted_data'] = $key->encrypt($plaintext);
            $data['authentication_tag'] = $key->calculateAuthenticationTag($data);

            return implode(".", array(
                Base64Url::encode(json_encode($data['header'])),
                Base64Url::encode($data['encrypted_cek']),
                Base64Url::encode($data['iv']),
                Base64Url::encode($data['encrypted_data']),
                Base64Url::encode($data['authentication_tag']),
            ));
        }
        //Then we try to sign
        if ($this->getKeyManager()->canSign($jwk)) {

            if (!is_string($input)) {
                throw new \Exception("Unsupported input type");
            }

            $header = Base64Url::encode(json_encode($header));
            $payload = Base64Url::encode($input);
            $signature = Base64Url::encode($jwk->sign($header.".".$payload));

            return $header.".".$payload.".".$signature;
        }
        throw new \Exception("The key can not sign or encrypt data");
    }

    public function convertToSerializedJson(JWTInterface $jwt, JWKSetInterface $jwk_set)
    {
        throw new \Exception('Not implemented');
    }

    private function loadSerializedJson($data)
    {
        throw new \Exception('Not implemented');
    }

    private function loadCompactSerializedJson($data)
    {
        $parts = explode('.', $data);

        switch (count($parts)) {
            case 3:
                return $this->loadCompactSerializedJWS($parts);
            case 5:
                return $this->loadCompactSerializedJWE($parts);
            default:
                throw new \InvalidArgumentException('Unable to load data');
        }
    }

    private function loadCompactSerializedJWE($parts)
    {
        $data = array(
            "header" => json_decode(Base64Url::decode($parts[0]), true),
            "encrypted_cek" => Base64Url::decode($parts[1]),
            "iv" => Base64Url::decode($parts[2]),
            "encrypted_data" => Base64Url::decode($parts[3]),
            "authentication_tag" => Base64Url::decode($parts[4]),
        );

        $key_set = $this->getKeyManager()->findJWKSetByHeader($data['header']);

        foreach ($key_set->getKeys() as $key) {
            if ($this->getKeyManager()->canDecrypt($key)) {
                $cek = null;
                try {
                    $cek = $key->decrypt($data['encrypted_cek']);
                } catch (\Exception $e) {}
                if ($cek !== null) {
                    return $this->decryptContent($data, $cek);
                }
            }
        }
        throw new \InvalidArgumentException('Unable to find the key used to encrypt this token');
    }

    private function decryptContent(array $data, $cek)
    {
        $key = $this->getKeyManager()->createJWK(array(
            "enc" =>$data['header']['enc'],
            "cek" =>$cek,
            "iv"  =>$data["iv"],
        ));

        if ($key instanceof JWKAuthenticationTagInterface) {
            if (!$key->checkAuthenticationTag($data)) {
                throw new \Exception("Authentication Tag verification failed");
            }
        }
        //We must check the authentication tag here

        $dec = $key->decrypt($data['encrypted_data']);

        if (isset($data['header']['cty'])) {
            switch ($data['header']['cty']) {
                case 'jwk+json':
                    return $this->getKeyManager()->createJWK(json_decode($dec,true));
                case 'jwkset+json':
                    $values = json_decode($dec,true);

                    if (!isset($values['keys'])) {
                        throw new \Exception("Not a valid key set");
                    }

                    return $this->getKeyManager()->createJWKSet($values['keys']);
                default:
                    break;
            }
        }

        $json = json_decode($dec,true);
        if (is_array($json)) {
            return $json;
        }

        return $dec;
    }

    private function loadCompactSerializedJWS($parts)
    {
        $header    = json_decode(Base64Url::decode($parts[0]), true);
        $payload   = Base64Url::decode($parts[1]);
        $signature = Base64Url::decode($parts[2]);

        $key_set = $this->getKeyManager()->findJWKSetByHeader($header);

        if ($key_set->isEmpty()) {
            throw new \Exception('Unable to find the key used for this token');
        }

        foreach ($key_set->getKeys() as $key) {
            if ($this->getKeyManager()->canVerify($key) && $key->verify($parts[0].".".$parts[1], $signature) === true) {

                $json = json_decode($payload,true);
                if (is_array($json)) {
                    return $json;
                }

                return $payload;
            }
        }
        throw new \InvalidArgumentException('Unable to find the key used to sign this token');
    }
}
