<?php

namespace SpomkyLabs\Jose;

use Jose\JWKInterface;
use Jose\EncryptionInstructionInterface;

/**
 * Class EncryptionInstruction.
 */
class EncryptionInstruction implements EncryptionInstructionInterface
{
    /**
     * @var array
     */
    protected $recipient_unprotected_header = array();
    /**
     * @var null|\Jose\JWKInterface
     */
    protected $recipient_public_key = null;
    /**
     * @var null|\Jose\JWKInterface
     */
    protected $sender_private_key = null;

    /**
     * @param JWKInterface $recipient_public_key
     *
     * @return $this
     */
    public function setRecipientKey(JWKInterface $recipient_public_key)
    {
        $this->recipient_public_key = $recipient_public_key;

        return $this;
    }

    /**
     */
    public function getRecipientKey()
    {
        return $this->recipient_public_key;
    }

    /**
     * @param JWKInterface $sender_private_key
     *
     * @return $this
     */
    public function setSenderKey(JWKInterface $sender_private_key)
    {
        $this->sender_private_key = $sender_private_key;

        return $this;
    }

    /**
     */
    public function getSenderKey()
    {
        return $this->sender_private_key;
    }

    /**
     * @param array $recipient_unprotected_header
     *
     * @return $this
     */
    public function setRecipientUnprotectedHeader(array $recipient_unprotected_header)
    {
        $this->recipient_unprotected_header = $recipient_unprotected_header;

        return $this;
    }

    /**
     * @return array
     */
    public function getRecipientUnprotectedHeader()
    {
        return $this->recipient_unprotected_header;
    }
}
