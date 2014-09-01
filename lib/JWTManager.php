<?php

namespace SpomkyLabs\JOSE;

use SpomkyLabs\JOSE\Util\Base64Url;
use SpomkyLabs\JOSE\Algorithm\VerificationInterface;
use SpomkyLabs\JOSE\Algorithm\SignatureInterface;
use SpomkyLabs\JOSE\Algorithm\KeyDecryptionInterface;
use SpomkyLabs\JOSE\Algorithm\ContentDecryptionInterface;

/**
 * Class representing a JSON Web Token Manager.
 */
abstract class JWTManager implements JWTManagerInterface
{
    abstract protected function getKeyManager();
    abstract protected function getCompressionManager();
    abstract protected function createCEK($size);
    abstract protected function createIV($size);

    /**
     * {@inheritdoc}
     */
    public function load($input, array &$headers = array())
    {
        //We try to identity if the data is a JSON object. In this case, we consider that data is a JWE or JWS Seralization object
        if (is_array($data = json_decode($input,true))) {
            return $this->loadSerializedJson($data, $headers);
        }

        //Else, we consider that data is a JWE or JWS Compact Seralized object
        return $this->loadCompactSerializedJson($input, $headers);
    }

    private function loadCompactSerializedJson($input, array &$headers)
    {
        $parts = explode('.', $input);

        switch (count($parts)) {
            case 3:
                return $this->loadCompactSerializedJWS($parts, $headers);
            case 5:
                return $this->loadCompactSerializedJWE($parts, $headers);
            default:
                throw new \InvalidArgumentException('Unable to load the input');
        }
    }

    private function loadCompactSerializedJWS($parts, array &$headers)
    {
        $jwt_header    = $parts[0];
        $jwt_payload   = $parts[1];
        $jwt_signature = Base64Url::decode($parts[2]);

        $result = $this->verifySignature($jwt_header, null, $jwt_payload, $jwt_signature);

        $headers[] = $result;
        $jwt_payload = Base64Url::decode($jwt_payload);

        $this->convertJWTContent(json_decode(Base64Url::decode($jwt_header), true), $jwt_payload);

        return $jwt_payload;
    }

    /**
     * @param array $data
     */
    private function loadSerializedJsonJWS($data, array &$headers)
    {
        $jwt_payload = $data['payload'];
        foreach ($data['signatures'] as $signature) {
            $protected_header = isset($signature['protected'])?$signature['protected']:null;
            $unprotected_header = isset($signature['header'])?$signature['header']:null;
            $jwt_signature = Base64Url::decode($signature['signature']);

            $result = $this->verifySignature($protected_header, $unprotected_header, $jwt_payload, $jwt_signature);

            $headers[] = $result;
        }
        $jwt_payload = Base64Url::decode($jwt_payload);

        $this->convertJWTContent(array(), $jwt_payload);

        return $jwt_payload;
    }

    private function verifySignature($protected_header, $unprotected_header, $payload, $signature)
    {
        if($protected_header === null && $unprotected_header === null) {
            throw new \InvalidArgumentException('Invalid header.');

        }
        $header = array();
        if ($protected_header !== null) {
            $tmp = json_decode(Base64Url::decode($protected_header), true);
            if(!is_array($tmp)) {
                throw new \InvalidArgumentException('Invalid protected header');
            }
            $header['protected'] = $tmp;
        }
        if ($unprotected_header !== null) {
            $header['unprotected'] = $unprotected_header;
        }

        $complete_header = array();
        foreach ($header as $part) {
            if ($part !== null) {
                $complete_header = array_merge($complete_header, $part);
            }
        }

        $jwk_set = $this->getKeyManager()->findByHeader($complete_header);

        if (!$jwk_set->isEmpty()) {
            foreach ($jwk_set->getKeys() as $jwk) {
                if ($this->canVerify($jwk)) {
                    if ($jwk->verify(
                        $protected_header.".".$payload,
                        $signature,
                        $complete_header
                    )) {

                        return $header;
                    } else {
                        throw new \InvalidArgumentException('Invalid signature');
                    }
                }
            }
        }
    }

    private function loadCompactSerializedJWE($parts, array &$headers)
    {
        $jwt_header             = json_decode(Base64Url::decode($parts[0]), true);
        $jwk_encrypted_cek      = Base64Url::decode($parts[1]);
        $jwt_iv                 = Base64Url::decode($parts[2]);
        $jwk_encrypted_data     = Base64Url::decode($parts[3]);
        $jwt_authentication_tag = Base64Url::decode($parts[4]);

        $jwk_set = $this->getKeyManager()->findByHeader($jwt_header);

        if ($jwk_set->isEmpty()) {
            throw new \InvalidArgumentException('Unable to find a key to decrypt this token');
        }

        foreach ($jwk_set->getKeys() as $jwk) {
            if ($this->canDecryptCEK($jwk)) {
                $jwt_decrypted_cek = $jwk->decryptKey($jwk_encrypted_cek, $jwt_header);

                if ($jwt_decrypted_cek !== null) {
                    return $this->decryptContent($jwk_encrypted_data, $jwt_decrypted_cek, $jwt_iv, $jwt_authentication_tag, $jwt_header, $headers);
                }
            }
        }
        throw new \InvalidArgumentException('Unable to find a key to decrypt this token');
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
                    if ($jwk instanceof KeyDecryptionInterface && $this->canDecrypt($jwk)) {
                        $cek = null;
                        try {
                            $cek = $jwk->decryptKey(Base64Url::decode($recipient['encrypted_key']), $prepared['header']);
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
     * @param array $input
     */
    private function loadSerializedJson($input, array &$headers)
    {
        if (isset($input['signatures']) && is_array($input['signatures'])) {
            return $this->loadSerializedJsonJWS($input, $headers);
        } elseif (isset($input['recipients']) && is_array($input['recipients'])) {
            return $this->loadSerializedJsonJWE($input, $headers);
        }
        throw new \InvalidArgumentException('Unable to load the input');
    }

    private function decryptContent($jwk_encrypted_data, $jwt_decrypted_cek, $jwt_iv, $jwt_authentication_tag, array $jwt_header, array &$headers)
    {
        $type = $this->getKeyManager()->getType($jwt_header['enc']);
        $key = $this->getKeyManager()->createJWK(array(
            "kty" =>$type,
        ));

        if (!$this->canDecryptContent($key)) {
            throw new \Exception("Unable to get a key to decrypt the content");
        }

        if (!$key->checkAuthenticationTag($jwt_authentication_tag, $jwt_decrypted_cek, $jwt_iv, $jwk_encrypted_data, $jwt_header)) {
            throw new \Exception("Authentication Tag verification failed");
        }

        $jwt_payload = $key->decryptContent($jwk_encrypted_data, $jwt_decrypted_cek, $jwt_iv, $jwt_header);

        if (isset($jwt_header['zip'])) {
            $method = $this->getCompressionManager()->getCompressionMethod($jwt_header['zip']);
            if ($method === null) {
                throw new \Exception("Compression method '".$jwt_header['zip']."' not supported");
            }
            $jwt_payload = $method->uncompress($jwt_payload);
            if (!is_string($jwt_payload)) {
                throw new \Exception("Decompression failed");
            }
        }

        $headers = $jwt_header;
        $this->convertJWTContent($jwt_header, $jwt_payload);

        return $jwt_payload;
    }

    private function convertJWTContent(array $header, &$payload)
    {
        //The payload is a JWKSet or JWK object
        if (isset($header['cty'])) {
            switch ($header['cty']) {
                case 'jwk+json':
                    $payload = $this->getKeyManager()->createJWK(json_decode($payload,true));

                    return;
                case 'jwkset+json':
                    $values = json_decode($payload,true);

                    if (!isset($values['keys'])) {
                        throw new \Exception("Not a valid key set");
                    }

                    $payload = $this->getKeyManager()->createJWKSet($values['keys']);

                    return;
                default:
                    return;
            }
        }

        //The payload is a JSON array
        $json = json_decode($payload,true);
        if (is_array($json)) {
            $payload = $json;

            return;
        }
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

            $this->createIV($data['header']['alg']);

            if ($data['header']['alg'] === 'dir') {
                $key->setValue('cek', $jwk->getValue('dir'));
            } else {
                $this->createCEK($data['header']['alg']);
            }

            $data['iv'] = $key->getValue('iv');
            $data['encrypted_cek'] = $jwk->encryptKey($key->getValue('cek'), $data['header']);

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

            /*
             * Encryption of the data here
             * The key must implement JWKContentEncryptionInterface
             */
            $data['encrypted_data'] = $key->encryptContent($plaintext, $key->getValue('cek'), $key->getValue('iv'), $tmp_header);

            $data['authentication_tag'] = $key->calculateAuthenticationTag($data);

            return implode(".", array(
                Base64Url::encode(json_encode($data['header'])),
                Base64Url::encode($data['encrypted_cek']),
                Base64Url::encode($data['iv']),
                Base64Url::encode($data['encrypted_data']),
                Base64Url::encode($data['authentication_tag']),
            ));
        } elseif ($jwk instanceof SignatureInterface && $this->canSign($jwk) && isset($header['alg'])) {

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

    protected function canEncryptCEK(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "enc", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "enc") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "encrypt", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && (strpos($key_ops, "wrapKey") === -1 || strpos($key_ops, "deriveKey") === -1)) {
            return false;
        }

        return $jwk instanceof KeyEncryptionInterface;
    }

    protected function canDecryptCEK(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "enc", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "enc") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "decrypt", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && (strpos($key_ops, "wrapKey") === -1 || strpos($key_ops, "deriveKey") === -1)) {
            return false;
        }

        return $jwk instanceof KeyDecryptionInterface;
    }

    protected function canEncryptContent(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "enc", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "enc") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "decrypt", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && strpos($key_ops, "encrypt") === -1) {
            return false;
        }

        return $jwk instanceof ContentEncryptionInterface;
    }

    protected function canDecryptContent(JWKInterface $jwk)
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

        return $jwk instanceof ContentDecryptionInterface;
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

        return $jwk instanceof SignatureInterface;
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

        return $jwk instanceof VerificationInterface;
    }
}
