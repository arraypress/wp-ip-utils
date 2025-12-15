<?php
/**
 * Global IP Helper Functions
 *
 * Provides convenient global functions for common IP operations.
 * These functions are wrappers around the ArrayPress\IPUtils\IP class.
 *
 * Functions included:
 * - get_user_ip() - Get the current user's IP address
 * - anonymize_ip() - Anonymize an IP address for GDPR compliance
 *
 * @package ArrayPress\IPUtils
 * @since   1.0.0
 */

// Exit if accessed directly
defined( 'ABSPATH' ) || exit;

use ArrayPress\IPUtils\IP;

if ( ! function_exists( 'get_user_ip' ) ) {
	/**
	 * Get the current user's IP address.
	 *
	 * Attempts to determine the actual client IP address by checking various
	 * HTTP headers, taking into account proxy servers and CDN configurations.
	 *
	 * @return string|null The user's IP address, or null if not found.
	 * @since 1.0.0
	 *
	 */
	function get_user_ip(): ?string {
		return IP::get();
	}
}

if ( ! function_exists( 'anonymize_ip' ) ) {
	/**
	 * Anonymize an IP address for GDPR compliance.
	 *
	 * Zeroes out the last octet for IPv4 addresses or the last group for IPv6.
	 *
	 * @param string $ip The IP address to anonymize.
	 *
	 * @return string|null The anonymized IP address, or null if invalid.
	 * @since 1.0.0
	 *
	 */
	function anonymize_ip( string $ip ): ?string {
		return IP::anonymize( $ip );
	}
}

if ( ! function_exists( 'sanitize_ip_list' ) ) {
	/**
	 * Sanitize an IP pattern list.
	 *
	 * @param string|array $input     Raw input.
	 * @param bool         $as_string Return as string (default) or array.
	 *
	 * @return string|array Sanitized patterns.
	 */
	function sanitize_ip_list( $input, bool $as_string = true ) {
		return IP::sanitize_pattern_list( $input, $as_string );
	}
}