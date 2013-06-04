<?php
// Prevent inclusion of itself.
if(defined("CSRFBLOCK_INCLUDE")) {
  exit;
}
define('CSRFBLOCK_INCLUDE', true);

/**
 * CSRFBlock adds token protection to every request made, unless the
 * requested page is found in a whitelist of pages that can be called
 * without a CSRF token attached.
 * 
 * @author Pieter Hiele
 * @version 0.0.1
 */

class CSRFBlock {
	
	/**
	 * The $CONFIG array defines placeholders and their values for the file
	 * Owasp.CsrfGuard.js.
	 */
	private static $CONFIG = array(
		"DOMAIN_STRICT" => true,
		"INJECT_FORMS" => true,
		"INJECT_ATTRIBUTES" => true,
		"INJECT_XHR" => true,
		"DOMAIN_ORIGIN" => "unset",
		"X_REQUESTED_WITH" => "unset",
		"CONTEXT_PATH" => "unset",
		"SERVLET_PATH" => "unset" // enable this to allow page-specific tokens. cfr. CSRFGuard
	);
	
	/**
	 * Select whether you want to use sessions or a database to store
	 * the tokens. Using sessions is highly encouraged. Only choose the
	 * database option in case sessions result in 
	 */
	const STORAGE = self::STORAGE_DATABASE;
	
	/**
	 * The following array should be edited in case the above STORAGE
	 * setting is set to STORAGE_DATABASE.
	 */
	private static $DBSETTINGS = array(
		"localhost",		// database host
		"root",				// database username
		"password",			// database password
		"database_name",	// database name
		"table_name"		// database table
	);
	
	private static $SECRET_SALT = "m@is€¢ret";
	
	/*+++++++++++++++++++++++++++++++++++++++
	++ DON'T EDIT ANYTHING BELOW THIS LINE ++
	++++++++++++++++++++++++++++++++++++++++*/
	
	const STORAGE_SESSION = 0;
	const STORAGE_DATABASE = 1;
	
	/**
	 * Save a freshly generated token so that it can be checked later.
	 * 
	 * @param string $name
	 * 			| The name of the token.
	 * @param string $value
	 * 			| The value of the token.
	 * @param int generated
	 * 			| The unix timestamp of the moment the token was generated.
	 */
	public static function saveToken($name, $value, $generated) {
		if(self::STORAGE == self::STORAGE_SESSION) {
			$_SESSION[$name]=array($value, time());
		} elseif (self::STORAGE == self::STORAGE_DATABASE) {
			self::debug("CSRFBLOCKID=".CSRFBLOCKID);
			self::getDatabase()->query("INSERT INTO ".self::$DBSETTINGS[4]." (userid, name, value, generated) VALUES ('".self::getDatabase()->real_escape_string(CSRFBLOCKID)."', '$name', '$value', '$generated')") or die(self::getDatabase()->error);
		} else {
			throw new Exception('Invalid storage specified.');
		}
	}
	
	/**
	 * Remove a token so that it cannot be used again.
	 * 
	 * @param string tokenName
	 * 			| The name of the token to remove.
	 */
	public static function removeToken($tokenName) {
		self::debug("Removing token ".$tokenName);
		if(self::STORAGE == self::STORAGE_SESSION) {
			unset($_SESSION[$tokenName]);
		} elseif (self::STORAGE == self::STORAGE_DATABASE) {
			$t = self::loadToken($tokenName);
			
			self::getDatabase()->query("DELETE FROM ".self::$DBSETTINGS[4]." WHERE name='{$tokenName}'") or die(self::getDatabase()->error);
			// When removing a token, also remove all tokens that are more than 10 minutes older than the token just removed.
			self::getDatabase()->query("DELETE FROM ".self::$DBSETTINGS[4]." WHERE generated<".($t[1]-60*10)) or die(self::getDatabase()->error);
		} else {
			throw new Exception('Invalid storage specified.');
		}
	}
	
	/**
	 * Get the mysqli object of the database. It will always return the same
	 * instance and initialize it if it's being used for the first time.
	 */
	private static function getDatabase() {
		if(self::STORAGE == self::STORAGE_DATABASE) {
			if(self::$DB == null) {
				self::$DB = new mysqli(self::$DBSETTINGS[0], self::$DBSETTINGS[1], self::$DBSETTINGS[2], self::$DBSETTINGS[3]);
			}
			return self::$DB;
		}
		return null;
	}
	
	private static $DB = null;
	
	/**
	 * Load a token from the memory by its name.
	 * 
	 * @param string $name
	 * 			| The name of the token to return.
	 */
	public static function loadToken($name) {
		if(self::STORAGE == self::STORAGE_SESSION) {
			return $_SESSION[$name];
		} elseif (self::STORAGE == self::STORAGE_DATABASE) {
			$token = self::getDatabase()->query("SELECT value, generated FROM ".self::$DBSETTINGS[4]." WHERE userid='".self::getDatabase()->real_escape_string(CSRFBLOCKID)."' AND name='$name'") or die(self::getDatabase()->error);
			$token = $token->fetch_assoc();
			if($token != null) {
				return array($token['value'], $token['generated']);
			}
		} else {
			throw new Exception('Invalid storage specified.');
		}
		
	}
	
	/**
	 * Check if the current visited page is whitelisted by the user by 
	 * checking the file csrfblock.lib.
	 */
	public static function isWhitelisted() {
		$whitelist = file(__DIR__."/csrfblock.lib");
		$whitelist = array_filter($whitelist, function($el){
			return (trim($el)!="" && substr(trim($el),0,1)!="?");
		});
		CSRFBlock::debug("Whitelist loaded. Contains ". count($whitelist)." pages.");
		
		foreach($whitelist as $w) {
			$w = trim($w);
			if(!strncmp($_SERVER['REQUEST_URI'], $w, strlen($w))) {
				return true;
			}
		}
	}
	
	/**
	 * Output a debug line to the webpage. This only works if the GET
	 * parameter '_csrfdebug' is set.
	 */
	public static function debug($string) {
		if(isset($_GET['_csrfdebug'])) echo "<code>[CSRFBlock] ". htmlentities($string)."</code><br />\n";
	}
	
	/**
	 * Check if the current visited page was accessed through a POST request.
	 */
	public static function isPostRequest() {
		return (count($_POST)>0);
	}
	
	/**
	 * Check if the current visited page contains GET parameters. The
	 * parameters _csrfdebug and _csrftoken are ignored.
	 */
	public static function containsGetParameters() {
		if(!strpos($_SERVER['REQUEST_URI'], "?")) return false;
		
		$params = substr($_SERVER['REQUEST_URI'], strpos($_SERVER['REQUEST_URI'], "?")+1);
		$arr_params = array_filter(explode("&", $params), function($el){$parts = explode("=",$el,2); return ($parts[0]!="_csrfdebug" && substr($parts[0],0,10)!="_csrftoken");});
		return (count($arr_params)>0);
	}
	
	/**
	 * Generate a CSRF prevention token and insert it at the right places in the document
	 * by loading a freshly generated version of the Owasp.CsrfGuard.js file in which placeholders
	 * are replaced by their corresponding values defined in CSRFBlock::$CONFIG.
	 * The javascript is responsible for putting the token at all the right places and heavily
	 * based on the CSRFGuard implementation by OWASP.
	 * 
	 * @param string $content
	 * 			| The HTML content of the page that will soon be displayed. It is first modified to
	 * 			| include the necessary javascript file.
	 * @see https://www.owasp.org/index.php/CSRFGuard_3_Token_Injection
	 * @uses CSRFBlock::insertConfiguration();
	 */
	public static function injectTokens($content) {
		// Try injecting javascript to detect places to inject the tokens.
		// But how will the javascript know what tokens to use?
		$javascript = file_get_contents(__DIR__."/Owasp.CsrfGuard.js");
		
		$token = self::generateToken();
		self::$CONFIG["DOMAIN_ORIGIN"] = parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST);
		self::$CONFIG["X_REQUESTED_WITH"] = $_SERVER['HTTP_X_REQUESTED_WITH'];
		self::$CONFIG["CONTEXT_PATH"] = dirname($_SERVER['PHP_SELF']);
		self::$CONFIG["SERVLET_PATH"] = dirname($_SERVER['PHP_SELF'])."/csrfblock.php";
		$javascript = self::insertConfiguration($javascript);
		if(strpos($content, "</body") > -1)
			$content = str_replace("</body>", "<script>$javascript</script>\n</body>", $content);
		else {
			// Find out if the mimetype is something different from "text/html".
			// If it is, the csrfblock() script shouldn't be called again.
			$noHtml = false;
			$headers = headers_list();
			foreach ($headers as $hdr) {
				if (stripos($hdr, "Content-Type") !== false) {
					$v = explode(": ",$hdr);
					if($v[1] != "text/html") {
						$noHtml = true;
					}
				}
			}
			if(!$noHtml) $content .= "\n<script>csrfblock(true);</script>";
		}
		return $content;
	}
	
	/**
	 * Generate a random CSRF prevention token based on the current page.
	 * This function can be edited to generate tokens of a different kind.
	 * When the token is generated, save it for later use.
	 * 
	 * @see CSRFBlock::saveToken()
	 */
	public static function generateToken() {
		$key = substr(md5(mt_rand()),0,10);
		$name = "_csrftoken_".$key;
		$value = substr(md5($key.$_SERVER['REQUEST_URI'].self::$SECRET_SALT),12);
		
		self::saveToken($name, $value, time());
		
		return array("name"=>$name, "value"=>$value);
	}
	
	/**
	 * Check if the token that was passed to this page is valid and handle
	 * the result accordingly. This function should only be called if the
	 * page requires a valid token to be sent (e.g.: cannot be found on the
	 * whitelist or isn't requested using a GET without parameters).
	 * 
	 * If no valid token is found, the loaded page will be terminated early.
	 * If a valid token is found, it is removed so that it cannot be used again.
	 */
	public static function checkToken() {
		$token = array();
		
		// Get token that was passed.
		if(count($_POST)) {
			foreach($_POST as $p=>$v) {
				if(strpos($p, "_csrftoken") > -1) {
					$token["name"] = $p;
					$token["value"] = $_POST[$p];
				}
			}
		}
		// If not POST, try GET
		if(!count($token)) {
			foreach($_GET as $g=>$v) {
				if(strpos($g, "_csrftoken") > -1) {
					$token["name"] = $g;
					$token["value"] = $_GET[$g];
				}	
			}
		}
		// If not POST or GET, check AJAX.
		if(!count($token) && strpos($_REQUEST['X-Requested-With'], "XMLHttpRequest")==0) {
			foreach($_SERVER as $k=>$v) {
				if(strpos($k, "HTTP__CSRFTOKEN") > -1) {
					$token["name"] = strtolower(substr($k,5));
					$token["value"] = $_SERVER[$k];
				}	
			}
		}
		
		if(!count($token)) {
			self::debug("No CSRF prevention token could be found. Exiting.");
			die("<h3>CSRFBlock</h3><p>No token was added to this request.</p>");
			exit();
		}
		
		self::debug("CSRF prevention token found: ".$token['name']);	
		
		$loadToken = self::loadToken($token['name']);
		if($loadToken[0] != $token['value']) {
			self::debug("CSRF prevention token invalid because it was not recognized.");
			die("<h3>CSRFBlock</h3><p>The CSRF prevention token was invalid. That means you came here from the wrong place.</p>");
			exit();
		} else {
			
			// check timeliness of the request. If more than 10 minutes old, don't accept.
			$time = $loadToken[1];
			if(time() - $time > 600) {
				self::debug("CSRF prevention token timed out. It is ".(time() - $time)." seconds old.");
				die("<h3>CSRFBlock</h3><p>The CSRF prevention token timed out. Please try again.</p>");
				exit();
			}
			
			self::debug("CSRF prevention token accepted!");
			self::removeToken($token['name']);
		}
	}
	
	/**
	 * This function is called by CSRFBlock::injectTokens() to replace
	 * the placeholders in the javascript file by their corresponding
	 * values in CSRFBlock::$CONFIG. It returns a freshly generated
	 * custom version of the passed javascript.
	 * 
	 * @param string $javascript
	 * 			| The javascript containing placeholders to replace.
	 */
	private static function insertConfiguration($javascript) {
		foreach(self::$CONFIG as $k=>$v) {
			$javascript = str_replace("%$k%", $v, $javascript);
		}
		return $javascript;
	}
	
}

// If CSRFBlock should be used using sessions (as recommended), just start
// a new session. If it should make use of a database, generate a random
// identifier for the visitor by using cookies to simulate a session in 
// the database.
if(CSRFBlock::STORAGE == CSRFBlock::STORAGE_SESSION) {
	session_start();
} else {
	if(!isset($_COOKIE["CSRFBLOCKID"])) {
		define("CSRFBLOCKID", md5(time()."some.seed"));
		setcookie("CSRFBLOCKID", CSRFBLOCKID, time()+60*60, "/"); // expire the session in an hour.
	} else {
		define("CSRFBLOCKID", $_COOKIE["CSRFBLOCKID"]);
	}	
}

// Handle a specific action "requestTokens".
// This is called by the added javascript and specifies the amount of
// tokens a page needs. The requested tokens are then randomly assigned
// to the actions on a page to limit the risk of using the same token
// twice, which would result in a rejected request.
// Moreover, every time an ajax request is executed, a new token is requested
// and assigned to the request. This makes it possible to execute an ajax
// request any amount of time, without the requests being rejected.
if(intval($_POST['requestTokens']) > 0) {
	
	$tokens = array();
	for($i=0; $i<intval($_POST['requestTokens']); $i++) {
		$tokens[] = CSRFBlock::generateToken();
	}
	echo json_encode($tokens);
	exit;
}

// Save the current working directory, because register_shutdown_function
// is known to reset that to /. Later, change the working directory again
// to avoid problems. 
// We start output buffering, so that we can inject the tokens before
// displaying the eventual HTML. The injecting happens by pointing to the
// CSRFBlock::injectTokens() in register_shutdown_function, which is called
// after the page is done loading.
$initialDir = getcwd();
ob_start();
register_shutdown_function( function() {
	global $initialDir;
	chdir($initialDir);
	echo CSRFBlock::injectTokens(ob_get_clean());
} );

// Check whether the current page is in the whitelist, and if not, check
// whether a CSRF protection token is found if it's a POST request or 
// contains URL parameters.
// Based on the secure default policy from CsFire.

CSRFBlock::debug("CSRFBlock loaded succesfully.");
CSRFBlock::debug(dirname($_SERVER['PHP_SELF']));

// Check if this page is whitelisted.
if(!CSRFBlock::isWhitelisted()) {
	
	CSRFBlock::debug("Current page is not whitelisted. (".$_SERVER['REQUEST_URI'].")");
	
	// If not, check if it's a POST request or a GET request containing
	// parameters.
	if(CSRFBlock::isPostRequest() || CSRFBlock::containsGetParameters()) {
		
		CSRFBlock::debug("It is a POST request or contains GET parameters and is considered an unsafe request.");
		
		// Check whether a valid CSRF protection token is available.
		CSRFBlock::checkToken();
		
	} else {
		CSRFBlock::debug("It is considered a safe request.");
	}
} else {
	CSRFBlock::debug("Current page is whitelisted.");
}
?>
