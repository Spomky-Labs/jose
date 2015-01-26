<?php

namespace SpomkyLabs\Jose;

use Jose\JWKInterface;
use Jose\EncryptionInstructionInterface;

class EncryptionInstruction implements EncryptionInstructionInterface
{
    protected $recipient_unprotected_header = array();
    protected $recipient_public_key = null;
    protected $sender_private_key = null;

    public function setRecipientPublicKey(JWKInterface $recipient_public_key)
    {
        $this->recipient_public_key = $recipient_public_key;

        return $this;
    }

    public function getRecipientPublicKey()
    {
        return $this->recipient_public_key;
    }

    public function setSenderPrivateKey(JWKInterface $sender_private_key)
    {
        $this->sender_private_key = $sender_private_key;

        return $this;
    }

    public function getSenderPrivateKey()
    {
        return $this->sender_private_key;
    }

    public function setRecipientUnprotectedHeader(array $recipient_unprotected_header)
    {
        $this->recipient_unprotected_header = $recipient_unprotected_header;

        return $this;
    }

    public function getRecipientUnprotectedHeader()
    {
        return $this->recipient_unprotected_header;
    }
}
