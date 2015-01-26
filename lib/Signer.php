<?php

namespace SpomkyLabs\Jose;

use Base64Url\Base64Url;
use Jose\JWKInterface;
use Jose\JWTInterface;
use Jose\JWKSetInterface;
use Jose\SignerInterface;
use Jose\JSONSerializationModes;
use Jose\Operation\SignatureInterface;
use Jose\SignatureInstructionInterface;

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

    /**
     * @return \Jose\JWTManagerInterface
     */
    abstract protected function getJWTManager();

    public function sign($input, array $instructions, $serialization = JSONSerializationModes::JSON_COMPACT_SERIALIZATION)
    {
        $this->checkInput($input);
        if (empty($instructions)) {
            throw new \RuntimeException("No instruction.");
        }

        $jwt_payload = Base64Url::encode($input->getPayload());

        $signatures = array();
        foreach ($instructions as $instruction) {
            if (!$instruction instanceof SignatureInstructionInterface) {
                throw new \RuntimeException("Bad instruction. Must implement SignatureInstructionInterface.");
            }
            $protected_header   = array_merge($input->getProtectedHeader(), $instruction->getProtectedHeader());
            $unprotected_header = array_merge($input->getUnprotectedHeader(), $instruction->getUnprotectedHeader());
            $complete_header = array_merge($protected_header, $protected_header);

            $jwt_protected_header   = Base64Url::encode(json_encode($protected_header));
            $alg = array_key_exists("alg", $complete_header) ? $complete_header["alg"] : null;

            if (null === $alg) {
                throw new \RuntimeException("No 'alg' parameter set in the header or the key.");
            }

            $algorithm = $this->getJWAManager()->getAlgorithm($alg);
            if (null === $algorithm || !$algorithm instanceof SignatureInterface) {
                throw new \RuntimeException("The algorithm '$alg' is not supported.");
            }

            $signature = $algorithm->sign($instruction->getKey(), $jwt_protected_header.".".$jwt_payload);
            $jwt_signature = Base64Url::encode($signature);
            switch ($serialization) {
                case JSONSerializationModes::JSON_COMPACT_SERIALIZATION:
                    $signatures[] = $jwt_protected_header.".".$jwt_payload.".".$jwt_signature;
                    break;
                case JSONSerializationModes::JSON_FLATTENED_SERIALIZATION:
                    $result = array(
                        "payload" => $jwt_payload,
                        "protected" => $jwt_protected_header,
                        "signature" => $jwt_signature,
                    );
                    if (!empty($unprotected_header)) {
                        $result["header"] = $unprotected_header;
                    }
                    $signatures[] = json_encode($result);
                    break;
                case JSONSerializationModes::JSON_SERIALIZATION:
                    $result = array(
                        "protected" => $jwt_protected_header,
                        "signature" => $jwt_signature,
                    );
                    if (!empty($unprotected_header)) {
                        $result["header"] = $unprotected_header;
                    }
                    $signatures['signatures'][] = $result;
                    break;
                default:
                    throw new \RuntimeException("The serialization methode '$serialization' is not supported");
            }
        }

        if (count($signatures) === 0) {
            throw new \RuntimeException("No signature created");
        }

        if (JSONSerializationModes::JSON_SERIALIZATION === $serialization) {
            $signatures['payload'] = $jwt_payload;

            return json_encode($signatures);
        }

        return count($signatures) === 1 ? current($signatures) : $signatures;
    }

    public function checkInput(&$input)
    {
        if ($input instanceof JWKInterface) {
            $jwt = $this->getJWTManager()->createJWT();
            $jwt->setPayload(json_encode($input))
                  ->setProtectedHeaderValue("cty", "jwk+json");
            $input = $jwt;

            return;
        }
        if ($input instanceof JWKSetInterface) {
            $jwt = $this->getJWTManager()->createJWT();
            $jwt->setPayload(json_encode($input))
                  ->setProtectedHeaderValue("cty", "jwkset+json");
            $input = $jwt;

            return;
        }
        if (is_array($input)) {
            $jwt = $this->getJWTManager()->createJWT();
            $jwt->setPayload(json_encode($input));

            return;
        }
        if (is_string($input)) {
            $jwt = $this->getJWTManager()->createJWT();
            $jwt->setPayload($input);

            return;
        }
        if (!$input instanceof JWTInterface) {
            throw new \InvalidArgumentException("Unsupported input type");
        }
    }
}
