<?php
App::uses('Security', 'Utility');

/**
 * Cipher Behavior for encrypting/decrypting fields
 *
 * For use with CakePHP
 *
 * @author J. Miller j@jmillerdesign.com
 */
class CipherBehavior extends ModelBehavior {

/**
 * Default settings
 *
 * @var array
 *      - fields array Fields to cipher.								DEFAULT: none
 *      - autoDecrypt boolean Decrypt ciphered value automatically.		DEFAULT: true
 *      - key string Key to encrypt with.								DEFAULT: Security.key
 *      - hmac salt to encrypt aes with.                                DEFAULT: Security.salt
 *      - cipher string Cipher method to use. (rijndael|aes)		    DEFAULT: aes
 */
	var $_defaults = array(
		'fields' => array(),
		'autoDecrypt' => true,
		'key' => '',
		'hmacSalt' => '',
		'cipher' => 'aes'
	);

/**
 * Behavior initialization
 *
 * @param mixed $Model Current model
 * @param array $config Config settings
 * @return void
 */
	function setup(Model $Model, $config = array()) {
		if (!$this->_cipherSeedValidates()) {
			trigger_error('Security.cipherSeed is invalid', E_USER_ERROR);
		}

		// Use security key as default key value
		$this->_defaults['key'] = Configure::read('Security.key');

        // Use security salt as default hmacSalt value
        $this->_defaults['hmacSalt'] = Configure::read('Security.salt');

		// Merge config settings with defaults
		$this->settings[$Model->name] = array_merge($this->_defaults, $config);

		// Set valid values for config settings
		$this->settings[$Model->name]['fields'] = (array) $this->settings[$Model->name]['fields'];
		$this->settings[$Model->name]['autoDecrypt'] = (boolean) $this->settings[$Model->name]['autoDecrypt'];
		$this->settings[$Model->name]['cipher'] = (string) $this->settings[$Model->name]['cipher'];
	}

/**
 * Encrypt data on save
 *
 * @param mixed $Model Current model
 * @return boolean True to save data
 */
	function beforeSave(Model $Model, $options = array()) {
		if (!array_key_exists($Model->name, $this->settings)) {
			// This model does not use this behavior
			return true;
		}

		// Encrypt each field
		foreach ($this->settings[$Model->name]['fields'] as $field) {
			if (!empty($Model->data[$Model->name][$field])) {
				// Encrypt value
				$Model->data[$Model->name][$field] = $this->encrypt($Model->data[$Model->name][$field], $this->settings[$Model->name]);
			}
		}

		return true;
	}

/**
 * Decrypt data on find
 *
 * @param mixed $Model Current model
 * @param mixed $results The results of the find operation
 * @param boolean $primary Whether this model is being queried directly (vs. being queried as an association)
 * @return mixed Result of the find operation
 */
	function afterFind(Model $Model, $results, $primary = false) {
		if (!$results || !array_key_exists('fields', $this->settings[$Model->name])) {
			// No fields to decrypt
			return $results;
		}

		if ($primary && $this->settings[$Model->name]['autoDecrypt']) {
			// Process all results
			foreach ($results as &$result) {
				if (!array_key_exists($Model->name, $result)) {
					// Result does not have this model
					continue;
				}

				foreach ($result[$Model->name] as $field => &$value) {
					if (in_array($field, $this->settings[$Model->name]['fields'])) {
						$value = $this->decrypt($value, $this->settings[$Model->name]);
					}
				}
			}
		}

		return $results;
	}

/**
 * Encrypt value
 *
 * @param string $value Value to encrypt
 * @param array $settings Config settings
 * @return string Encrypted value
 */
	public function encrypt($value, $settings) {
		if ($settings['cipher'] == 'rijndael') {
			return Security::rijndael($value, $settings['key'], 'encrypt');
		}

		return Security::encrypt($value, $settings['key'], $settings['hmacSalt']);
	}

/**
 * Decrypt value
 *
 * @param string $value Value to decrypt
 * @param array $settings Config settings
 * @return string Decrypted value
 */
	public function decrypt($value, $settings) {
		if ($settings['cipher'] == 'rijndael') {
			return Security::cipher($value, $settings['key'], 'decrypt');
		}

		return Security::decrypt($value, $settings['key'], $settings['hmacSalt']);
	}

/**
 * Validate cipher seed
 *
 * @return boolean True if validates
 */
	private function _cipherSeedValidates() {
		$seed = Configure::read('Security.cipherSeed');
		return ($seed && is_numeric($seed));
	}

}
