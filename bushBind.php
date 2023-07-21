<?php

// 	*****************************************
// 	Strong string obfuscation with password encryption and decription By Gian Carlo Ciaccolini
//	https://github.com/GCC76
//	Not for commercial use
// 	*****************************************

class bushBind{
	
	private $cycleCount = 4;
	private $token = '';
	
	//Array for response
	private $resp = array(
		"header" => array(
			"name"=> "Bush Bind by GCC",
			"description" => "Not for commercial use. Encryption is the result of character obfuscation using the given password. A security token is generated to keep and provide upon decryption. Bush Bind cannot guarantee the security of data recovery protection. It is recommended to only extract the encryption result and its token. Don't keep the entire JSON document!",
			"version" => "1.1.0",
		),
		"response" => array(
			"value" => "",
			"security_token" => "",
			"data" => "",
		)
	);
	
	
	//Create a security token base on the length of the given password
	private function tokenGen($length=null){
	
		$token = "";

		for($a=1; $a <= $this->cycleCount; $a++){
			for ($x=1; $x<=$length; $x++){
				$rand = chr(rand(49,57));
				$token .= ( $rand < 8 ) ? $rand : chr(rand(97,99));
			};
		}
		
		return($token);
	}
	
	
	//Check the password security
	private function keyCheck($key=null){
		
		try{
			
			if(!$key or $key == ''){
				throw new Exception("Password must contain at least 8 characters, one of which uppercase, a number and special characters");
			}
			
			if(strlen($key) < 8){
				throw new Exception("Password must contain at least 8 characters");
			}
			
			if(!preg_match('/[\'^£$%&*()}{@#~?><>,|=_+¬-]/', $key)){
				throw new Exception("Password must contain at least a special character");
			}
			
			if(!preg_match('~[0-9]+~', $key)){
				throw new Exception("Password must contain at least a number");
			}
			
			if(!preg_match('/[A-Z]/', $key)){
				throw new Exception("Password must contain at least an uppercase character");
			}
			
			return true;
			
		}
		catch(Exception $e){
			return $e->getMessage();
		}
		
	}
	
	
	//Try to match the given token with the one saved on string
	private function checkToken($token=null){
		
		try{
			
			if(!$token){
				throw new Exception("Security token is required to proceed");
			}
			if($token !== $this->token){
				throw new Exception("Security token or password mismatch");
			}
			return true;
		}
		catch(Exception $e){
			return $e->getMessage();
		}
	}
	
	
	
	//Encripting function
	public function bushEncrypt($text=null,$key=null){
		
		try{
			
			//Verify given password for consistency
			$keyCheck = $this->keyCheck($key);
			if($keyCheck !== true){
				throw new Exception($keyCheck);
			}
			$keyLength = strlen($key);
			
			//Generate a new token
			$token = $this->tokenGen($keyLength);
			
			//Join the reversed and converted given password with generated token.
			//Every single change in password will generate a complete new string
			$key	= md5(strrev($key)).$token; 	
			
			
			//Split the new key in array and remove duplicate
			$key 	= str_split($key);
			$key 	= array_values(array_unique($key));
			
			//Split the given text to an array
			$chars 	= str_split($text);		

			$i=0;
			$ascii = "";
			$coded = "";
			$scheme = "";
			
			//Convert the array value into ascii code
			foreach($chars as $char){
				$ascii .= ord($char).".";
				$i++;
			}
			

			$asciiArray = explode(".",$ascii);
			foreach($asciiArray as $value){
			
				$values = str_split($value);
				$length = strlen($value);
				$i=1;
				
				foreach($values as $num){
					
					//Replace the ascii value with the key of the password generated array
					$coded .= isset($key[$num]) ? $key[$num] : $num;
					
					if($i == $length){
						
						//Create a scheme
						$scheme .= isset($key[$length]) ? $key[$length] : $length;
					}
					$i++;
				}
			}
			
			//Include the token and the scheme to the new generated string and convert it to base64
			$coded = base64_encode($token.$coded.".".$scheme);
			
			$this->resp['response']['value'] = true;
			$this->resp['response']['security_token'] = $token;
			$this->resp['response']['data'] = $coded;
			return json_encode($this->resp);
			
		}
		catch(Exception $e){
			
			$this->resp['reponse']['value'] = false;
			$this->resp['response']['data'] = $e->getMessage();
			return json_encode($this->resp);
			
		}
	
	}
	
	
	
	//Decripting string
	public function bushDecrypt($text=null,$key=null,$securityToken=null){
		
		
		try{
			
			if(!$text or !$key or !$securityToken){
				throw new Exception("Data to be converted, password and security token are mandatory");
			}
			
			$text = base64_decode($text);
			$keyLength = strlen($key) * $this->cycleCount;
			$this->token = substr($text,0,$keyLength);
			$response = $this->checkToken($securityToken);

			if($response !== true){
				throw new Exception($response);
			}
			
			$text 	= substr($text,$keyLength);
			$schemeNumber = explode(".",$text);
			$scheme = end($schemeNumber);
			$text 	= reset($schemeNumber);
			$schemeSplit = str_split($scheme);
			
			$key	= md5(strrev($key)).$this->token;
			$key 	= str_split($key);
			$key 	= array_values(array_unique($key));
			
			$encoded = "";
			$string	 = "";
			$result	 = "";
			$sum     = 0;
			$i		 = 0;
			
			foreach($schemeSplit as $num){
				
				$encodedNum = in_array($num,$key) ? array_search($num,$key) : $num;
				$sum += $encodedNum + $i;
				$text = substr_replace($text, ".", $sum, 0);
				$i=1;
			}
			
			$asciiArray = explode(".",$text);
			
			foreach($asciiArray as $value){
				
				$length = strlen($value);
				$string = str_split($value);

				$i=1;
				foreach($string as $char){
					$encoded .= in_array($char,$key) ? array_search($char,$key) : $char;
					
					if($i == $length){
						$encoded .= ".";
					}
					$i++;
				}
			}
		
			$encoded = explode(".",$encoded);
			foreach($encoded as $char){
				$result .= is_numeric($char) ? chr($char) : null;
			}
			
			$this->resp['response']['value'] = true;
			$this->resp['response']['security_token'] = $securityToken;
			$this->resp['response']['data'] = base64_encode($result);
			return json_encode($this->resp);
			
		}
		catch(Exception $e){
			$this->resp['response']['value'] = false;
			$this->resp['response']['security_token'] = $securityToken;
			$this->resp['response']['data'] = $e->getMessage();
			return json_encode($this->resp);
		}
	}
}
?>