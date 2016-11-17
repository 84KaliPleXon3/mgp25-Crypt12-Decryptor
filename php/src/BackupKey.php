<?php

class BackupKey
{
    public $cipher;
    public $cipherKey;
    public $hashedGoogleId;

    public function __construct($header, $keyVersion, $serverSalt, $googleIdSalt, $hashedGoogleId, $encryptionIv, $cipherKey, $gcmTag) {
        $this->cipher = new BackupCipher($header, $keyVersion, $serverSalt, $googleIdSalt, $encryptionIv, $gcmTag);
        $this->hashedGoogleId = $hashedGoogleId;
        $this->cipherKey = $cipherKey;
    }

    public function toString() {
        return "\nBackupKey [" . $this->cipher->toString() . ", hashedGoogleId=" . bin2hex($this->hashedGoogleId) . ", cipherKey=" . bin2hex($this->cipherKey) . "]";
    }
}
