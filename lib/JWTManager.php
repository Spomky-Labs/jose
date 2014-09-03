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
            $protected_header = isset($signature['protected']) ? $signature['protected'] : null;
            $unprotected_header = isset($signature['header']) ? $signature['header'] : null;
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
        if ($protected_header === null && $unprotected_header === null) {
            throw new \InvalidArgumentException('Invalid header');
        }
        $header = array();
        if ($protected_header !== null) {
            $tmp = json_decode(Base64Url::decode($protected_header), true);
            if (!is_array($tmp)) {
                throw new \InvalidArgumentException('Invalid protected header');
            }
            $header['protected'] = $tmp;
        }
        if ($unprotected_header !== null) {
            $header['header'] = $unprotected_header;
        }

        $complete_header = array();
        foreach ($header as $part) {
            if ($part !== null) {
                $complete_header = array_merge($complete_header, $part);
            }
        }
        if (count($complete_header) === 0) {
            throw new \InvalidArgumentException('Invalid header');
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
                    return $this->decryptContent($jwk_encrypted_data, $jwt_decrypted_cek, $jwt_iv, $jwt_authentication_tag, $jwt_header, $jwt_header, $headers);
                }
            }
        }
        throw new \InvalidArgumentException('Unable to find a key to decrypt this token');
    }

    /**
     * @param array $data
     */
    private function loadSerializedJsonJWE($data, array &$headers = array())
    {
        $jwt_protected_header = null;
        if(isset($data['protected'])) {
            $jwt_protected_header = json_decode(Base64Url::decode($data['protected']), true);
        }
        $jwt_unprotected_header = null;
        if(isset($data['unprotected'])) {
            $jwt_unprotected_header = $data['unprotected'];
        }
        $jwt_iv = null;
        if(isset($data['iv'])) {
            $jwt_iv = Base64Url::decode($data['iv']);
        }
        $jwt_aad = null;
        if(isset($data['aad'])) {
            $jwt_aad = Base64Url::decode($data['aad']);
        }
        $jwt_tag = null;
        if(isset($data['tag'])) {
            $jwt_tag = Base64Url::decode($data['tag']);
        }
        $jwt_ciphertext = Base64Url::decode($data['ciphertext']);

        foreach ($data['recipients'] as $recipient) {
            $recipient_header = null;
            if(isset($recipient['header'])) {
                $recipient_header = $recipient['header'];
            }
            $complete_header = array();
            if($jwt_protected_header!==null) {
                $complete_header = array_merge($complete_header, $jwt_protected_header);
            }
            if($jwt_unprotected_header!==null) {
                $complete_header = array_merge($complete_header, $jwt_unprotected_header);
            }
            if($recipient_header!==null) {
                $complete_header = array_merge($complete_header, $recipient_header);
            }

            $jwk_set = $this->getKeyManager()->findByHeader($complete_header);

            if (!$jwk_set->isEmpty()) {
                foreach ($jwk_set->getKeys() as $jwk) {
                    if ($jwk instanceof KeyDecryptionInterface && $this->canDecryptCEK($jwk)) {
                        $jwt_decrypted_cek = null;
                        //try {
                            $jwt_decrypted_cek = $jwk->decryptKey(Base64Url::decode($recipient['encrypted_key']), $complete_header);
                        //} catch (\Exception $e) {} //We just need to avoid exceptions
                        if ($jwt_decrypted_cek !== null) {
                            /*$data = array(
                                "header" => $prepared['header'],
                                "encrypted_cek" => $recipient['encrypted_key'],
                                "iv" => $prepared['iv'],
                                "encrypted_data" => $prepared['encrypted_data'],
                                "authentication_tag" => $prepared['authentication_tag'],
                            );*/

                            return $this->decryptContent($jwt_ciphertext, $jwt_decrypted_cek, $jwt_iv, $jwt_tag, $jwt_protected_header, $complete_header, $headers);
                        }
                    }
                }
            }
        }

        throw new \InvalidArgumentException('Unable to find the key used to encrypt this token');
    }

    private function decryptContent($jwk_encrypted_data, $jwt_decrypted_cek, $jwt_iv, $jwt_authentication_tag, array $jwt_protected_header, array $complete_header, array &$headers)
    {
        $type = $this->getKeyManager()->getType($complete_header['enc']);
        $key = $this->getKeyManager()->createJWK(array(
            "kty" =>$type,
        ));

        if (!$this->canDecryptContent($key)) {
            throw new \Exception("Unable to get a key to decrypt the content");
        }

        if (!$key->checkAuthenticationTag($jwt_authentication_tag, $jwt_decrypted_cek, $jwt_iv, $jwk_encrypted_data, $jwt_protected_header)) {
            throw new \Exception("Authentication Tag verification failed");
        }

        $jwt_payload = $key->decryptContent($jwk_encrypted_data, $jwt_decrypted_cek, $jwt_iv, $complete_header);

        if (isset($complete_header['zip'])) {
            $method = $this->getCompressionManager()->getCompressionMethod($complete_header['zip']);
            if ($method === null) {
                throw new \Exception("Compression method '".$complete_header['zip']."' not supported");
            }
            $jwt_payload = $method->uncompress($jwt_payload);
            if (!is_string($jwt_payload)) {
                throw new \Exception("Decompression failed");
            }
        }

        $headers = $complete_header;
        $this->convertJWTContent($complete_header, $jwt_payload);

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

    /********************/
    /**** CONVERSION ****/
    /********************/

    public function signAndConvert($compact, $input, array $operation_keys)
    {
        if (is_array($input)) {
            $input = json_encode($input);
        }
        if (!is_string($input)) {
            throw new \Exception("Unsupported input type");
        }

        $jwt_payload = Base64Url::encode($input);
        foreach ($operation_keys as $operation) {
            if (!isset($operation['protected'])) {
                throw new \Exception("Invalid operation information. Index 'protected' is missing");
            }
            if (!isset($operation['protected']['alg'])) {
                throw new \Exception("Invalid protected header. Index 'alg' is missing");
            }
            if (!isset($operation['key']) || !$operation['key'] instanceof JWKInterface) {
                throw new \Exception("Invalid key. Index 'key' is missing or not a valid JWKInterface object");
            }
            $key = $operation['key'];
            if (!$this->canSign($key)) {
                throw new \Exception("Invalid key. Signature is not handled by the key");
            }

            $tmp = array();
            $tmp['protected'] = Base64Url::encode(json_encode($operation['protected']));
            if (isset($operation['header']) && is_array($operation['header'])) {
                $tmp['header'] = $operation['header'];
            }
            $tmp['signature'] = Base64Url::encode($key->sign($tmp['protected'].".".$jwt_payload, $operation['protected']));

            $signatures[] = $tmp;
        }

        if (count($signatures) === 0) {
            throw new \Exception("No signature created");
        }

        if (count($signatures) > 1 && $compact === true) {
            throw new \Exception("Can not compact when using multiple signatures");
        }

        if (count($signatures) === 1 && $compact === true) {
            return $signatures[0]['protected'].".".$jwt_payload.".".$signatures[0]['signature'];
        }

        return json_encode(array(
            'payload'    => $jwt_payload,
            'signatures' => $signatures
        ));
    }

    public function encryptAndConvert($compact, $input, array $operation_keys, array $protected_header = null, array $unprotected_header = null, JWKInterface $sender_key = null)
    {
        if($compact === false) {
            throw new \Exception("JSON Serialized representation is not supported");
        }

        if (is_array($input)) {
            $input = json_encode($input);
        } elseif ($input instanceof JWKInterface || $input instanceof JWKSetInterface) {
            $protected_header['cty'] = $input instanceof JWKInterface ? 'jwk+json' : 'jwkset+json';
            $input = $input->__toString();
        }
        if (!is_string($input)) {
            throw new \Exception("Unsupported input type");
        }

        $jwt_header = array();
        if($protected_header !== null) {
            $jwt_header = array_merge($protected_header);
        }
        if($unprotected_header !== null) {
            $jwt_header = array_merge($unprotected_header);
        }

        $type = $this->getKeyManager()->getType($jwt_header['enc']);
        $key = $this->getKeyManager()->createJWK(array(
            "kty" =>$type
        ));

        $jwt_iv = null;
        if($key->getKeySize($jwt_header) !== null) {
            $jwt_iv = $this->createIV($key->getKeySize($jwt_header));
        }

        foreach ($operation_keys as $operation) {
            
        }
    }

    /*public function convertToCompactSerializedJson($input, JWKInterface $jwk, array $header = array())
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
    }*/

    protected function canEncryptCEK(JWKInterface $jwk)
    {
        //If "use" parameter is not null and not "enc", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "enc") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "encrypt", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && (strpos($key_ops, "wrapKey") === -1 || strpos($key_ops, "deriveKey") === -1)) {
            return false;
        }

        if (!$jwk->isPublic()) {
            return false;
        }

        return $jwk instanceof KeyEncryptionInterface;
    }

    protected function canDecryptCEK(JWKInterface $jwk)
    {
        //If "use" parameter is not null and not "enc", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "enc") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "decrypt", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && (strpos($key_ops, "unwrapKey") === -1 || strpos($key_ops, "deriveBits") === -1)) {
            return false;
        }

        if (!$jwk->isPrivate()) {
            return false;
        }

        return $jwk instanceof KeyDecryptionInterface;
    }

    protected function canEncryptContent(JWKInterface $jwk)
    {
        //If "use" parameter is not null and not "enc", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "enc") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "decrypt", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && strpos($key_ops, "encrypt") === -1) {
            return false;
        }

        if (!$jwk->isPublic()) {
            return false;
        }

        return $jwk instanceof ContentEncryptionInterface;
    }

    protected function canDecryptContent(JWKInterface $jwk)
    {
        //If "use" parameter is not null and not "enc", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "enc") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "decrypt", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && strpos($key_ops, "decrypt") === -1) {
            return false;
        }

        if (!$jwk->isPrivate()) {
            return false;
        }

        return $jwk instanceof ContentDecryptionInterface;
    }

    protected function canSign(JWKInterface $jwk)
    {
        //If "use" parameter is not null and not "sig", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "sig") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "sign", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && strpos($key_ops, "sign") === -1) {
            return false;
        }

        if (!$jwk->isPrivate()) {
            return false;
        }

        return $jwk instanceof SignatureInterface;
    }

    protected function canVerify(JWKInterface $jwk)
    {
        //If "use" parameter is not null and not "sig", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "sig") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "verify", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && strpos($key_ops, "verify") === -1) {
            return false;
        }

        if (!$jwk->isPublic()) {
            return false;
        }

        return $jwk instanceof VerificationInterface;
    }
}
