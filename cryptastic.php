<?php

/*
 * Cryptastic performs two-way encryption and pbkdf2 hashing.
 *
 * @author Andrew Johnson <notices@riverscapeweb.com>
 * @copyright Andrew Johnson
 *
 * Copyright (c) 2009 Andrew Johnson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

class cryptastic
{
	/**
	 * Encryption Procedure
	 *
	 * @param   mixed    msg      message/data
	 * @param   string   k        encryption key
	 * @param   boolean  base64   base64 encode result
	 *
	 * @return  string   iv+ciphertext+mac or
	 *          boolean  false on error
	*/
	public function encrypt( $msg, $k, $base64 = false )
	{
		# open cipher module (do not change cipher/mode)
		if ( ! $td = mcrypt_module_open('rijndael-256', '', 'ctr', '') )
			return false;

		$msg = serialize($msg);                         # serialize
		$iv  = mcrypt_create_iv(32, MCRYPT_RAND);       # create iv

		if ( mcrypt_generic_init($td, $k, $iv) !== 0 )  # initialize buffers
			return false;

		$msg  = mcrypt_generic($td, $msg);              # encrypt
		$msg  = $iv . $msg;                             # prepend iv
		$mac  = $this->pbkdf2($msg, $k, 1000, 32);      # create mac
		$msg .= $mac;                                   # append mac

		mcrypt_generic_deinit($td);                     # clear buffers
		mcrypt_module_close($td);                       # close cipher module

		if ( $base64 ) $msg = base64_encode($msg);      # base64 encode?

		return $msg;                                    # return iv+ciphertext+mac
	}
	/**
	 * Decryption Procedure
	 *
	 * @param   string   msg      output from encrypt()
	 * @param   string   k        encryption key
	 * @param   boolean  base64   base64 decode msg
	 *
	 * @return  string   original message/data or
	 *          boolean  false on error
	*/
	public function decrypt( $msg, $k, $base64 = false )
	{
		if ( $base64 ) $msg = base64_decode($msg);          # base64 decode?

		# open cipher module (do not change cipher/mode)
		if ( ! $td = mcrypt_module_open('rijndael-256', '', 'ctr', '') )
			return false;

		$iv  = substr($msg, 0, 32);                         # extract iv
		$mo  = strlen($msg) - 32;                           # mac offset
		$em  = substr($msg, $mo);                           # extract mac
		$msg = substr($msg, 32, strlen($msg)-64);           # extract ciphertext
		$mac = $this->pbkdf2($iv . $msg, $k, 1000, 32);     # create mac

		if ( $em !== $mac )                                 # authenticate mac
			return false;

		if ( mcrypt_generic_init($td, $k, $iv) !== 0 )      # initialize buffers
			return false;

		$msg = mdecrypt_generic($td, $msg);                 # decrypt
		$msg = unserialize($msg);                           # unserialize

		mcrypt_generic_deinit($td);                         # clear buffers
		mcrypt_module_close($td);                           # close cipher module

		return $msg;                                        # return original msg
	}
	/**
	 * PBKDF2 Implementation (as described in RFC 2898);
	 *
	 * @param   string  p   password
	 * @param   string  s   salt
	 * @param   int     c   iteration count (use 1000 or higher)
	 * @param   int     kl  derived key length
	 * @param   string  a   hash algorithm
	 *
	 * @return  string  derived key
	*/
	public function pbkdf2( $p, $s, $c, $kl, $a = 'sha256' )
	{
		$hl = strlen(hash($a, null, true)); # Hash length
		$kb = ceil($kl / $hl);              # Key blocks to compute
		$dk = '';                           # Derived key

		# Create key
		for ( $block = 1; $block <= $kb; $block ++ )
		{
			# Initial hash for this block
			$ib = $b = hash_hmac($a, $s . pack('N', $block), $p, true);

			# Perform block iterations
			for ( $i = 1; $i < $c; $i ++ ) 

				# XOR each iterate
				$ib ^= ($b = hash_hmac($a, $b, $p, true));

			$dk .= $ib; # Append iterated block
		}

		# Return derived key of correct length
		return substr($dk, 0, $kl);
	}
}

?>
