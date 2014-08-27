<?php

namespace SpomkyLabs\JOSE;

use SpomkyLabs\JOSE\Util\Base64Url;

/**
 * Class representing a JSON Web Token Manager.
 */
abstract class JWTManager implements JWTManagerInterface
{
    abstract protected function getKeyManager();
    abstract protected function getCompressionManager();

    public function load($data)
    {
        //We try to identity if the data is a JSON object. In this case, we consider that data is a JWE or JWS Seralization object
        if (($json = json_decode($data,true)) !== null) {
            return $this->loadSerializedJson($json);
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

        //We try to encrypt first
        if ($jwk instanceof JWKEncryptInterface && $this->canEncrypt($jwk) && isset($header['enc']) && isset($header['alg'])) {

            $plaintext = '';
            if (is_string($input)) {
                $plaintext = $input;
            } elseif ($input instanceof JWKInterface || $input instanceof JWKSetInterface) {
                $header['cty'] = $input instanceof JWKInterface ? 'jwk+json' : 'jwkset+json';
                $plaintext = $input->__toString();
            }

            $data = array(
                'header'=>$header,
            );
            $type = $this->getKeyManager()->getType($data['header']['enc']);
            $key = $this->getKeyManager()->createJWK(array(
                "kty" =>$type
            ));
            if (!$key instanceof JWKContentEncryptionInterface) {
                throw new \Exception("The content encryption algorithm is not valid");
            }

            $key->createIV($data['header']);

            if ($data['header']['alg'] === 'dir') {
                $key->setValue('cek', $jwk->getValue('dir'));
            } else {
                $key->createCEK($data['header']);
            }

            $data['iv'] = $key->getValue('iv');
            $data['encrypted_cek'] = $jwk->encrypt($key->getValue('cek'), $data['header']);

            $tmp_header = array("enc" =>$data['header']['enc']);

            if (isset($data['header']['zip'])) {
                $method = $this->getCompressionManager()->getCompressionMethod($data['header']['zip']);
                if ($method === null) {
                    throw new \Exception("Compression method '".$data['header']['zip']."' not supported");
                }
                $plaintext = $method->compress($plaintext);
                if (!is_string($plaintext)) {
                    throw new \Exception("Compression failed");
                }
            }

            $data['encrypted_data'] = $key->encrypt($plaintext, $tmp_header);

            $data['authentication_tag'] = $key->calculateAuthenticationTag($data);

            return implode(".", array(
                Base64Url::encode(json_encode($data['header'])),
                Base64Url::encode($data['encrypted_cek']),
                Base64Url::encode($data['iv']),
                Base64Url::encode($data['encrypted_data']),
                Base64Url::encode($data['authentication_tag']),
            ));
        } elseif ($jwk instanceof JWKSignInterface && $this->canSign($jwk) && isset($header['alg'])) {

            if (!$jwk->isPrivate()) {
                throw new \Exception("The key is not a private key");
            }

            if (!is_string($input)) {
                throw new \Exception("Unsupported input type");
            }

            $header_ = Base64Url::encode(json_encode($header));
            $payload = Base64Url::encode($input);
            $signature = Base64Url::encode($jwk->sign($header_.".".$payload, $header));

            return $header_.".".$payload.".".$signature;
        } else {
            throw new \Exception("The key can not sign or encrypt data");
        }
    }

    public function convertToSerializedJson(JWTInterface $jwt, JWKSetInterface $jwk_set)
    {
        throw new \Exception('Not implemented');
    }

    /**
     * @param array $data
     */
    private function loadSerializedJson($data)
    {
        if (isset($data['signatures']) && is_array($data['signatures'])) {
            return $this->loadSerializedJsonJWS($data);
        } elseif (isset($data['recipients']) && is_array($data['recipients'])) {
            return $this->loadSerializedJsonJWE($data);
        }
        throw new \InvalidArgumentException('Unable to load data');
    }

    /**
     * @param array $data
     */
    private function loadSerializedJsonJWS($data)
    {
        foreach ($data['signatures'] as $signature) {

            $jwk_set = $this->getKeyManager()->findByHeader($signature['header']);

            foreach ($jwk_set->getKeys() as $jwk) {
                if ($jwk instanceof JWKVerifyInterface && $this->canVerify($jwk)) {
                    $complete_header = array_merge(json_decode(Base64Url::decode($signature['protected']), true), $signature['header']);

                    if ($jwk->verify(
                            $signature['protected'].".".$data['payload'],
                            Base64Url::decode($signature['signature']),
                            $complete_header
                        )) {

                        $payload = Base64Url::decode($data['payload']);
                        $json = json_decode($payload,true);
                        if (is_array($json)) {
                            return $json;
                        }

                        return $payload;
                    } else {
                        throw new \InvalidArgumentException('Invalid signature');
                    }
                }
            }
        }
        throw new \InvalidArgumentException('Unable to find the key used to sign this token');
    }

    /**
     * @param array $data
     */
    private function loadSerializedJsonJWE($data)
    {
        /*$data = array(
            "encrypted_cek" => Base64Url::decode($parts[1]),
        );*/

        $prepared = array(
            "header" => json_decode(Base64Url::decode($data['protected']), true),
            "iv" => Base64Url::decode($data['iv']),
            "encrypted_data" => Base64Url::decode($data['ciphertext']),
            "authentication_tag" => Base64Url::decode($data['tag']),
        );

        foreach ($data['recipients'] as $recipient) {
            $jwk_set = $this->getKeyManager()->findByHeader(array_merge($prepared['header'], $recipient['header']));

            if (!$jwk_set->isEmpty()) {
                foreach ($jwk_set->getKeys() as $jwk) {
                    if ($jwk instanceof JWKDecryptInterface && $this->canDecrypt($jwk)) {
                        $cek = null;
                        try {
                            $cek = $jwk->decrypt(Base64Url::decode($recipient['encrypted_key']), $prepared['header']);
                        } catch (\Exception $e) {} //We just need to avoid exceptions
                        if ($cek !== null) {
                            $data = array(
                                "header" => $prepared['header'],
                                "encrypted_cek" => $recipient['encrypted_key'],
                                "iv" => $prepared['iv'],
                                "encrypted_data" => $prepared['encrypted_data'],
                                "authentication_tag" => $prepared['authentication_tag'],
                            );

                            return $this->decryptContent($data, $cek);
                        }
                    }
                }
            }
        }

        throw new \InvalidArgumentException('Unable to find the key used to encrypt this token');
    }

    /**
     * @param string $data
     */
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

        $jwk_set = $this->getKeyManager()->findByHeader($data['header']);

        if ($jwk_set->isEmpty()) {
            throw new \InvalidArgumentException('Unable to find a key to decrypt this token');
        }

        foreach ($jwk_set->getKeys() as $jwk) {
            if ($jwk instanceof JWKDecryptInterface && $this->canDecrypt($jwk)) {
                $cek = null;
                try {
                    $cek = $jwk->decrypt($data['encrypted_cek'], $data['header']);
                } catch (\Exception $e) {} //We just need to avoid exceptions
                if ($cek !== null) {
                    return $this->decryptContent($data, $cek);
                }
            }
        }
        throw new \InvalidArgumentException('Unable to find a key to decrypt this token');
    }

    private function decryptContent(array $data, $cek)
    {
        $type = $this->getKeyManager()->getType($data['header']['enc']);
        $key = $this->getKeyManager()->createJWK(array(
            "kty" =>$type,
            "enc" =>$data['header']['enc'],
            "cek" =>$cek,
            "iv"  =>$data["iv"],
        ));

        if ($key instanceof JWKAuthenticationTagInterface) {
            if (!$key->checkAuthenticationTag($data)) {
                throw new \Exception("Authentication Tag verification failed");
            }
        }

        $dec = $key->decrypt($data['encrypted_data'], array('enc'=>$data['header']['enc']));

        if (isset($data['header']['zip'])) {
            $method = $this->getCompressionManager()->getCompressionMethod($data['header']['zip']);
            if ($method === null) {
                throw new \Exception("Compression method '".$data['header']['zip']."' not supported");
            }
            $dec = $method->uncompress($dec);
            if (!is_string($dec)) {
                throw new \Exception("Decompression failed");
            }
        }

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

        $jwk_set = $this->getKeyManager()->findByHeader($header);

        if ($jwk_set->isEmpty()) {
            throw new \InvalidArgumentException('Unable to find the key used to sign this token');
        }

        foreach ($jwk_set->getKeys() as $jwk) {
            if ($jwk instanceof JWKVerifyInterface && $this->canVerify($jwk) && $jwk->verify($parts[0].".".$parts[1], $signature, $header) === true) {

                $json = json_decode($payload,true);
                if (is_array($json)) {
                    return $json;
                }

                return $payload;
            }
        }
        throw new \InvalidArgumentException('Unable to find the key used to sign this token');
    }

    protected function canEncrypt(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "enc", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "enc") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "encrypt", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && strpos($key_ops, "encrypt") === -1) {
            return false;
        }

        return true;
    }

    protected function canDecrypt(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "enc", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "enc") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "decrypt", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && strpos($key_ops, "decrypt") === -1) {
            return false;
        }

        return true;
    }

    protected function canSign(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "sig", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "sig") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "sign", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && strpos($key_ops, "sign") === -1) {
            return false;
        }

        return true;
    }

    protected function canVerify(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "sig", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "sig") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "verify", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && strpos($key_ops, "verify") === -1) {
            return false;
        }

        return true;
    }
}
