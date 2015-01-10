<?php

namespace SpomkyLabs\Jose;

use SpomkyLabs\Jose\Util\Base64Url;
use Jose\JWKInterface;
use Jose\JWTInterface;
use Jose\JWKSetInterface;
use Jose\SignerInterface;
use Jose\JSONSerializationModes;
use Jose\Operation\SignatureInterface;

/**
 * Class representing a JSON Web Token Manager.
 */
abstract class Signer implements SignerInterface
{
    /**
     * @return \Jose\JWKManagerInterface
     */
    abstract protected function getJWKManager();

    /**
     * @return \Jose\JWAManagerInterface
     */
    abstract protected function getJWAManager();

    public function sign($jwt, JWKSetInterface $keys, $serialization = JSONSerializationModes::JSON_COMPACT_SERIALIZATION)
    {
        if ($jwt instanceof JWKInterface || $jwt instanceof JWKSetInterface) {
            $input = $this->createJWT();
            $input->setPayload($jwt);
            $jwt = $input;
        }
        if (!$jwt instanceof JWTInterface) {
            throw new \InvalidArgumentException("Unsupported input type");
        }

        $signatures = array();
        $jwt_payload = Base64Url::encode($jwt->getPayload());
        foreach ($keys as $key) {
            $jwt_protected = $jwt->getProtectedHeader();
            $jwt_header = $jwt->getUnprotectedHeader();
            $alg = $jwt->getAlgorithm();

            if ($alg === null) {
                $alg = $key->getAlgorithm();
            }

            if (null === $alg) {
                throw new \RuntimeException("No 'alg' parameter set in the header or the key.");
            }

            $algorithm = $this->getJWAManager()->getAlgorithm($alg);
            if (null === $algorithm) {
                throw new \RuntimeException("The algorithm '$alg' is not supported.");
            }
            if (!$algorithm instanceof SignatureInterface) {
                throw new \RuntimeException("The algorithm '$alg' is not supported.");
            }

            /*if (!$this->canSign($key)) {
                throw new \RuntimeException("Invalid key. Signature is not handled by the key");
            }*/

            $protected = Base64Url::encode(json_encode($jwt_protected));
            $signature = Base64Url::encode($algorithm->sign($key, $protected.".".$jwt_payload, $jwt_protected));
            switch ($serialization) {
                case JSONSerializationModes::JSON_COMPACT_SERIALIZATION:
                    $signatures[] = $protected.".".$jwt_payload.".".$signature;
                    break;
                case JSONSerializationModes::JSON_FLATTENED_SERIALIZATION:
                    $result = array(
                        "payload" => $jwt_payload,
                        "protected" => $protected,
                        "signature" => $signature,
                    );
                    if (!empty($jwt_header)) {
                        $result["header"] = $jwt_header;
                    }
                    $signatures[] = json_encode($result);
                    break;
                case JSONSerializationModes::JSON_SERIALIZATION:
                    $result = array(
                        "protected" => $protected,
                        "signature" => $signature,
                    );
                    if (!empty($jwt_header)) {
                        $result["header"] = $jwt_header;
                    }
                    $signatures['signatures'][] = $result;
                    break;
                default:
                    throw new \RuntimeException("The serialization methode '$serialization' is not supported");
            }
        }

        if (count($signatures) === 0) {
            throw new \RuntimeException("No signature created");
        } elseif (count($signatures) === 1) {
            if (array_key_exists("signatures", $signatures)) {
                $signatures["payload"] = $jwt_payload;

                return json_encode($signatures);
            }

            return current($signatures);
        } else {
            return $signatures;
        }
    }
}
