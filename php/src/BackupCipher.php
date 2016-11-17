<?php

class BackupCipher
{
    public $encryptionIv;
    public $googleIdSalt;
    public $header;
    public $keyVersion;
    public $serverSalt;
    public $gcmTag;

    public function __construct($header, $keyVersion, $serverSalt, $googleIdSalt, $encryptionIv, $gcmTag) {
        $this->header = $header;
        $this->keyVersion = $keyVersion;
        $this->serverSalt = $serverSalt;
        $this->googleIdSalt = $googleIdSalt;
        $this->encryptionIv = $encryptionIv;
        $this->gcmTag = $gcmTag;
    }

    public function toString() {
        return "\nBackupCipher [cipherVersion=" . bin2hex($this->header) . " keyVersion=" . $this->keyVersion . ", serverSalt=" . bin2hex($this->serverSalt) . ", googleIdSalt=" . bin2hex($this->googleIdSalt) . ", encryptionIv=" . bin2hex($this->encryptionIv) . "]";
    }
}
