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
	 * @since 1.0.0
	 *
	 * @return string|null The user's IP address, or null if not found.
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
	 * @since 1.0.0
	 *
	 * @param string $ip The IP address to anonymize.
	 *
	 * @return string|null The anonymized IP address, or null if invalid.
	 */
	function anonymize_ip( string $ip ): ?string {
		return IP::anonymize( $ip );
	}
}