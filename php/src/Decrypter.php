<?php

require __DIR__."/BackupCipher.php";
require __DIR__."/BackupKey.php";


class Decrypter {

    const BACKUP_CIPHER_HEADER      = "\x00\x01";
    const BACKUP_CIPHER_HEADER_V1   = "\x00\x01";
    const BACKUP_CIPHER_HEADER_V2   = "\x00\x02";
    const HEADER_LENGTH             = 2;
    const SERVER_SALT_LENGTH        = 32;
    const GOOGLE_ID_SALT_LENGTH     = 16;
    const GOOGLE_HASHED_ID_LENGHT   = 32;
    const ENCRYPTION_IV_LENGTH      = 16;
    const CIPHER_KEY_LENGTH         = 32;

    protected $gcmTag;

    public function readBackupCipher($crypt12File)
    {
        $crypt12FileData = file_get_contents($crypt12File);

        $header = substr($crypt12FileData, 0, self::HEADER_LENGTH);
        if (($header != self::BACKUP_CIPHER_HEADER_V2) && ($header != self::BACKUP_CIPHER_HEADER_V1)) {
            echo "Wrong header!\n\n";
            exit();
        }

        $keyVersion = (int)bin2hex(substr($crypt12FileData, self::HEADER_LENGTH, 1));
        $serverSalt = substr($crypt12FileData, 1 + self::HEADER_LENGTH, self::SERVER_SALT_LENGTH);
        $googleIdSalt = substr($crypt12FileData, 1 + self::HEADER_LENGTH + self::SERVER_SALT_LENGTH, self::GOOGLE_ID_SALT_LENGTH);
        $encryptionIv = substr($crypt12FileData, 1 + self::HEADER_LENGTH + self::SERVER_SALT_LENGTH + self::GOOGLE_ID_SALT_LENGTH, self::ENCRYPTION_IV_LENGTH);
        $this->gcmTag = substr($crypt12FileData, -36, 16);

        return new BackupCipher($header, $keyVersion, $serverSalt, $googleIdSalt, $encryptionIv, $this->gcmTag);
    }

    public function getBackupKeyWithRandomizedIV($keyFile)
    {
        $keyFileData = file_get_contents($keyFile);

        if (strlen($keyFileData) <  32 + 16 + 32 + 16 + 32 + 1 + self::HEADER_LENGTH) {
            echo "Error: Header mismatch\n\n";
        }

        $header = substr($keyFileData, 27, self::HEADER_LENGTH);
        $keyVersion = (int)bin2hex(substr($keyFileData, 27 + self::HEADER_LENGTH, 1));
        $serverSalt = substr($keyFileData, 28 + self::HEADER_LENGTH, self::SERVER_SALT_LENGTH);
        $googleIdSalt = substr($keyFileData, 28 + self::HEADER_LENGTH + self::SERVER_SALT_LENGTH, self::GOOGLE_ID_SALT_LENGTH);
        $hashedGoogleId = substr($keyFileData, 28 + self::HEADER_LENGTH + self::SERVER_SALT_LENGTH + self::GOOGLE_ID_SALT_LENGTH, self::GOOGLE_HASHED_ID_LENGHT);
        $encryptionIv = substr($keyFileData, 28 + self::HEADER_LENGTH + self::SERVER_SALT_LENGTH + self::GOOGLE_ID_SALT_LENGTH + self::GOOGLE_HASHED_ID_LENGHT, self::ENCRYPTION_IV_LENGTH);
        $cipherKey = substr($keyFileData, 28 + self::HEADER_LENGTH + self::SERVER_SALT_LENGTH + self::GOOGLE_ID_SALT_LENGTH + self::GOOGLE_HASHED_ID_LENGHT + self::ENCRYPTION_IV_LENGTH, self::CIPHER_KEY_LENGTH);

        return new BackupKey($header, $keyVersion, $serverSalt, $googleIdSalt, $hashedGoogleId, $generateIV, $cipherKey, $this->gcmTag);
    }

    public function decrypt($crypt12File, $iv, $key)
    {
        //start: 1 + header + serverSalt + googleIdSalt + iv = 67
        //final: AES-GCM footer = 36
        $crypt12Data = substr(file_get_contents($crypt12File), 67, -36);

        $decrypted = openssl_decrypt($crypt12Data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $this->gcmTag);
        $uncompressed = gzuncompress($decrypted);
        file_put_contents(__DIR__.'/msgstore.db', $uncompressed);
    }
}
