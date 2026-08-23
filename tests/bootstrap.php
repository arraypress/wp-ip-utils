<?php
/**
 * PHPUnit bootstrap.
 *
 * This is a library, not a plugin: there is no WordPress to load. The handful
 * of WordPress functions the testable paths touch are stubbed here, kept as
 * close to core's real behaviour as the tests depend on and no closer.
 *
 * @package ArrayPress\IPUtils
 */

declare( strict_types=1 );

require_once dirname( __DIR__ ) . '/vendor/autoload.php';

if ( ! function_exists( 'sanitize_text_field' ) ) {
	function sanitize_text_field( $str ) {
		return trim( strip_tags( (string) $str ) );
	}
}

if ( ! function_exists( 'apply_filters' ) ) {
	function apply_filters( $tag, $value, ...$args ) {
		return $value;
	}
}
