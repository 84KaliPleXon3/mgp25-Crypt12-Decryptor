<?php

require __DIR__."/src/Decrypter.php";

$decrypter = new Decrypter();

echo "==============================\n";
echo "=                            =\n";
echo "=     CRYPT12 DECRYPTOR      =\n";
echo "=                            =\n";
echo "==============================\n\n";
echo "Author: mgp25 - https://github.com/mgp25\n\n";

if (count($argv) < 3) {
    echo "Usage: php decrypt.php msgstore.db.crypt12 key\n";
    exit();
}

$crypt12File = $argv[1];
$keyFile = $argv[2];

$crypt12Data = $decrypter->readBackupCipher($crypt12File);
$iv = $crypt12Data->encryptionIv;

$keyData = $decrypter->getBackupKeyWithRandomizedIV($keyFile);
$key = $keyData->cipherKey;

echo $keyData->toString();

echo "IV: ".strtoupper(bin2hex($iv));
echo "\nKEY: ".strtoupper(bin2hex($key) . "\n\n");

$decrypter->decrypt($crypt12File, $iv, $key);

echo "Success! msgstore.db generated!\n\n";
