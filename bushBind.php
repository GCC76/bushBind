<?php

declare(strict_types=1); // Abilita il controllo rigoroso dei tipi per una maggiore robustezza

// 	*****************************************
// 	Strong string obfuscation with password encryption and decryption By Gian Carlo Ciaccolini
//	https://github.com/GCC76
//	Not for commercial use
// 	*****************************************

class bushBind
{
    private int $cycleCount = 4;
    private string $token = '';

    // Struttura della risposta unificata
    private array $respTemplate = [
        "header" => [
            "name" => "Bush Bind by GCC",
            "description" => "Not for commercial use. Encryption is the result of character obfuscation using the given password. A security token is generated to keep and provide upon decryption. Bush Bind cannot guarantee the security of data recovery protection. It is recommended to only extract the encryption result and its token. Don't keep the entire JSON document!",
            "version" => "1.2.0 (Optimized)", // Versione aggiornata
        ],
        "response" => [
            "value" => false,
            "security_token" => null,
            "data" => "",
        ]
    ];

    /**
     * Crea un token di sicurezza basato sulla lunghezza della password.
     */
    private function tokenGen(int $length): string
    {
        $token = "";
        $charPool = '1234567abc'; // Pool di caratteri predefinito per evitare chiamate rand() multiple
        $poolLength = strlen($charPool) - 1;

        $totalLength = $length * $this->cycleCount;
        for ($i = 0; $i < $totalLength; $i++) {
            $token .= $charPool[rand(0, $poolLength)];
        }

        return $token;
    }

    /**
     * Controlla la robustezza della password.
     */
    private function keyCheck(string $key): bool|string
    {
        if (strlen($key) < 8) {
            return "Password must contain at least 8 characters";
        }
        if (!preg_match('/[\'^£$%&*()}{@#~?><>,|=_+¬-]/', $key)) {
            return "Password must contain at least a special character";
        }
        if (!preg_match('~[0-9]+~', $key)) {
            return "Password must contain at least a number";
        }
        if (!preg_match('/[A-Z]/', $key)) {
            return "Password must contain at least an uppercase character";
        }
        return true;
    }
    
    /**
     * Genera la mappa di caratteri (charset) usata per l'offuscamento.
     */
    private function generateKeyCharset(string $key, string $token): array
    {
        // Utilizzo di sha256 invece di md5 per una maggiore sicurezza (anche se ancora non ideale per derivare chiavi)
        $combinedKey = hash('sha256', strrev($key)) . $token;
        return array_values(array_unique(str_split($combinedKey)));
    }

    /**
     * Offusca i valori ASCII e genera lo schema per la decrittazione.
     */
     private function getScheme(array $asciiArray, array $keyCharset): array
    {
        $coded = "";
        $scheme = "";

        foreach ($asciiArray as $asciiValue) {
            
            if ($asciiValue === '') continue;

            $digits = str_split((string)$asciiValue); 
            
            $length = count($digits);

            foreach ($digits as $digit) {

                $coded .= $keyCharset[$digit] ?? $digit;
            }
            $scheme .= $keyCharset[$length] ?? $length;
        }

        return [$scheme, $coded];
    }

    /**
     * De-offusca i dati utilizzando lo schema e il charset.
     */
    private function getDecoded(array $obfuscatedChunks, array $keyCharset): string
    {
        $result = "";
        $reversedKeyCharset = array_flip($keyCharset); // Usa array_flip per ricerche O(1) invece di O(n)

        foreach ($obfuscatedChunks as $chunk) {
            if ($chunk === '') continue;
            
            $chars = str_split($chunk);
            $asciiValue = "";
            foreach ($chars as $char) {
                // Ricerca inversa molto più veloce
                $asciiValue .= $reversedKeyCharset[$char] ?? $char;
            }
            $result .= chr((int)$asciiValue);
        }
        
        return $result;
    }
    
    /**
     * Costruisce e ritorna la risposta JSON.
     */
    private function _buildResponse(bool $success, string $data, ?string $token = null): string
    {
        $response = $this->respTemplate;
        $response['response']['value'] = $success;
        $response['response']['security_token'] = $token;
        $response['response']['data'] = $data;
        return json_encode($response, JSON_UNESCAPED_UNICODE);
    }

    /**
     * Funzione di offuscamento (ex "Encrypting").
     */
    public function bushEncrypt(?string $text, ?string $key): string
    {
        if (empty($text) || empty($key)) {
             return $this->_buildResponse(false, "Text and key are mandatory");
        }
        
        try {
            $keyCheck = $this->keyCheck($key);
            if ($keyCheck !== true) {
                throw new Exception($keyCheck);
            }

            $token = $this->tokenGen(strlen($key));
            $keyCharset = $this->generateKeyCharset($key, $token);
            
            // Converte il testo in un array di valori ASCII
            $asciiArray = array_map('ord', str_split($text));

            // Genera la stringa offuscata e lo schema
            [$scheme, $coded] = $this->getScheme($asciiArray, $keyCharset);
            
            // Unisce le parti e codifica in base64
            $finalData = base64_encode($token . '||' . $coded . '||' . $scheme);

            return $this->_buildResponse(true, $finalData, $token);

        } catch (Exception $e) {
            return $this->_buildResponse(false, $e->getMessage());
        }
    }

    /**
     * Funzione di de-offuscamento (ex "Decrypting").
     */
    public function bushDecrypt(?string $text, ?string $key, ?string $securityToken): string
    {
        if (empty($text) || empty($key) || empty($securityToken)) {
            return $this->_buildResponse(false, "Data to be converted, password and security token are mandatory", $securityToken);
        }

        try {
            $decodedText = base64_decode($text, true);
            if ($decodedText === false) {
                throw new Exception("Invalid Base64 input.");
            }

            // Estrae token, dati e schema usando un delimitatore chiaro
            $parts = explode('||', $decodedText);
            if (count($parts) !== 3) {
                throw new Exception("Malformed data structure.");
            }
            [$this->token, $codedData, $scheme] = $parts;

            // Controllo del token
            if (!hash_equals($this->token, $securityToken)) {
                 throw new Exception("Security token or password mismatch");
            }
            
            $keyCharset = $this->generateKeyCharset($key, $this->token);
            $reversedKeyCharset = array_flip($keyCharset);
            
            $schemeChars = str_split($scheme);
            $lengths = [];
            foreach($schemeChars as $char) {
                // Ricostruisce le lunghezze originali dei valori ASCII
                $lengths[] = (int)($reversedKeyCharset[$char] ?? $char);
            }
            

            // Ricostruisce l'array di blocchi offuscati senza manipolare stringhe
            $obfuscatedChunks = [];
            $offset = 0;
            foreach ($lengths as $length) {
                $obfuscatedChunks[] = substr($codedData, $offset, $length);
                $offset += $length;
            }
            
            $result = $this->getDecoded($obfuscatedChunks, $keyCharset);

            return $this->_buildResponse(true, base64_encode($result), $securityToken);

        } catch (Exception $e) {
            return $this->_buildResponse(false, $e->getMessage(), $securityToken);
        }
    }
}