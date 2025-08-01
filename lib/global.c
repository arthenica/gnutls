/*
 * Copyright (C) 2001-2016 Free Software Foundation, Inc.
 * Copyright (C) 2015-2016 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#include "gnutls_int.h"
#include "errors.h"
#include <libtasn1.h>
#include "dh.h"
#include "compress.h"
#include "random.h"
#include <gnutls/pkcs11.h>

#include "hello_ext.h" /* for _gnutls_hello_ext_init */
#include "supplemental.h" /* for _gnutls_supplemental_deinit */
#include "locks.h"
#include "system.h"
#include "accelerated/cryptodev.h"
#include "accelerated/afalg.h"
#include "accelerated/accelerated.h"
#include "fips.h"
#include "atfork.h"
#include "system-keys.h"
#include "str.h"
#include "global.h"
#ifdef HAVE_LEANCRYPTO
#include <leancrypto.h>
#endif

#ifdef ENABLE_PKCS11
#include "pkcs11/p11_provider.h"
#endif

/* Minimum library versions we accept. */
#define GNUTLS_MIN_LIBTASN1_VERSION "0.3.4"

#ifdef __sun
#pragma fini(lib_deinit)
#pragma init(lib_init)
#define _CONSTRUCTOR
#define _DESTRUCTOR
#else
#define _CONSTRUCTOR __attribute__((constructor))
#define _DESTRUCTOR __attribute__((destructor))
#endif

#ifndef _WIN32
int __attribute__((weak)) _gnutls_global_init_skip(void);
int _gnutls_global_init_skip(void)
{
	return 0;
}
#else
inline static int _gnutls_global_init_skip(void)
{
	return 0;
}
#endif

/* created by asn1c */
extern const asn1_static_node gnutls_asn1_tab[];
extern const asn1_static_node pkix_asn1_tab[];

asn1_node _gnutls_pkix1_asn = NULL;
asn1_node _gnutls_gnutls_asn = NULL;

gnutls_log_func _gnutls_log_func = NULL;
gnutls_audit_log_func _gnutls_audit_log_func = NULL;
int _gnutls_log_level = 0; /* default log level */

unsigned int _gnutls_global_version = GNUTLS_VERSION_NUMBER;

static int _gnutls_global_init(unsigned constructor);
static void _gnutls_global_deinit(unsigned destructor);

static void default_log_func(int level, const char *str)
{
	fprintf(stderr, "gnutls[%d]: %s", level, str);
}

/**
 * gnutls_global_set_log_function:
 * @log_func: it's a log function
 *
 * This is the function where you set the logging function gnutls is
 * going to use.  This function only accepts a character array.
 * Normally you may not use this function since it is only used for
 * debugging purposes.
 *
 * @gnutls_log_func is of the form,
 * void (*gnutls_log_func)( int level, const char*);
 **/
void gnutls_global_set_log_function(gnutls_log_func log_func)
{
	_gnutls_log_func = log_func;
}

/**
 * gnutls_global_set_audit_log_function:
 * @log_func: it is the audit log function
 *
 * This is the function to set the audit logging function. This
 * is a function to report important issues, such as possible
 * attacks in the protocol. This is different from gnutls_global_set_log_function()
 * because it will report also session-specific events. The session
 * parameter will be null if there is no corresponding TLS session.
 *
 * @gnutls_audit_log_func is of the form,
 * void (*gnutls_audit_log_func)( gnutls_session_t, const char*);
 *
 * Since: 3.0
 **/
void gnutls_global_set_audit_log_function(gnutls_audit_log_func log_func)
{
	_gnutls_audit_log_func = log_func;
}

static void gettime_from_time(struct timespec *t)
{
	t->tv_sec = gnutls_time(NULL);
	t->tv_nsec = 0;
}

/**
 * gnutls_global_set_time_function:
 * @time_func: it's the system time function, a gnutls_time_func() callback.
 *
 * This is the function where you can override the default system time
 * function.  The application provided function should behave the same
 * as the standard function.
 *
 * Since: 2.12.0
 **/
void gnutls_global_set_time_function(gnutls_time_func time_func)
{
	gnutls_time = time_func;

	/* When the time function is overridden, also override the
	 * gettime function to use the derived value, even if its
	 * resolution is lower.
	 */
	_gnutls_global_set_gettime_function(gettime_from_time);
}

/**
 * gnutls_global_set_log_level:
 * @level: it's an integer from 0 to 99.
 *
 * This is the function that allows you to set the log level.  The
 * level is an integer between 0 and 9.  Higher values mean more
 * verbosity. The default value is 0.  Larger values should only be
 * used with care, since they may reveal sensitive information.
 *
 * Use a log level over 10 to enable all debugging options.
 **/
void gnutls_global_set_log_level(int level)
{
	_gnutls_log_level = level;
}

/**
 * gnutls_global_set_mem_functions:
 * @alloc_func: it's the default memory allocation function. Like malloc().
 * @secure_alloc_func: This is the memory allocation function that will be used for sensitive data.
 * @is_secure_func: a function that returns 0 if the memory given is not secure. May be NULL.
 * @realloc_func: A realloc function
 * @free_func: The function that frees allocated data. Must accept a NULL pointer.
 *
 * Deprecated: since 3.3.0 it is no longer possible to replace the internally used 
 *  memory allocation functions
 *
 * This is the function where you set the memory allocation functions
 * gnutls is going to use. By default the libc's allocation functions
 * (malloc(), free()), are used by gnutls, to allocate both sensitive
 * and not sensitive data.  This function is provided to set the
 * memory allocation functions to something other than the defaults
 *
 * This function must be called before gnutls_global_init() is called.
 * This function is not thread safe.
 **/
void gnutls_global_set_mem_functions(gnutls_alloc_function alloc_func,
				     gnutls_alloc_function secure_alloc_func,
				     gnutls_is_secure_function is_secure_func,
				     gnutls_realloc_function realloc_func,
				     gnutls_free_function free_func)
{
	_gnutls_debug_log(
		"called the deprecated gnutls_global_set_mem_functions()\n");
}

GNUTLS_STATIC_MUTEX(global_init_mutex);
static int _gnutls_init = 0;

/* cache the return code */
static int _gnutls_init_ret = 0;

/**
 * gnutls_global_init:
 *
 * Since GnuTLS 3.3.0 this function is no longer necessary to be explicitly
 * called. To disable the implicit call (in a library constructor) of this
 * function set the environment variable %GNUTLS_NO_IMPLICIT_INIT to 1.
 *
 * This function performs any required precalculations, detects
 * the supported CPU capabilities and initializes the underlying
 * cryptographic backend. In order to free any resources 
 * taken by this call you should gnutls_global_deinit() 
 * when gnutls usage is no longer needed.
 *
 * This function increments a global counter, so that
 * gnutls_global_deinit() only releases resources when it has been
 * called as many times as gnutls_global_init().  This is useful when
 * GnuTLS is used by more than one library in an application.  This
 * function can be called many times, but will only do something the
 * first time. It is thread safe since GnuTLS 3.3.0.
 *
 * A subsequent call of this function if the initial has failed will
 * return the same error code.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned,
 *   otherwise a negative error code is returned.
 **/
int gnutls_global_init(void)
{
	return _gnutls_global_init(0);
}

static int _gnutls_global_init(unsigned constructor)
{
	int ret = 0, res;
	int level;
	const char *e;
#if defined(ENABLE_PKCS11) && defined(ENABLE_FIPS140)
	const char *p11_provider_path = NULL;
	const char *p11_provider_pin = NULL;
#endif

	if (!constructor) {
		ret = gnutls_static_mutex_lock(&global_init_mutex);
		if (ret < 0) {
			return gnutls_assert_val(ret);
		}
	}

	_gnutls_init++;
	if (_gnutls_init > 1) {
		ret = _gnutls_init_ret;
		goto out;
	}

	_gnutls_switch_lib_state(LIB_STATE_INIT);

	e = secure_getenv("GNUTLS_DEBUG_LEVEL");
	if (e != NULL) {
		level = atoi(e);
		gnutls_global_set_log_level(level);
		if (_gnutls_log_func == NULL)
			gnutls_global_set_log_function(default_log_func);
		_gnutls_debug_log("Enabled GnuTLS " VERSION " logging...\n");
	}

#ifdef HAVE_DCGETTEXT
	bindtextdomain(PACKAGE, LOCALEDIR);
#endif

	e = secure_getenv("GNUTLS_BUFFER_RECLAIM");
	if (e != NULL) {
		bool reclaiming = e[0] == '1' && e[1] == '\0';
		_gnutls_debug_log("Using %s buffer allocator...\n",
				  reclaiming ? "reclaiming" : "non-reclaiming");
		_gnutls_buffer_set_reclaiming(reclaiming);
	}

	res = gnutls_crypto_init();
	if (res != 0) {
		gnutls_assert();
		ret = GNUTLS_E_CRYPTO_INIT_FAILED;
		goto out;
	}

	ret = _gnutls_system_key_init();
	if (ret != 0) {
		gnutls_assert();
	}

	/* initialize ASN.1 parser
	 */
	if (asn1_check_version(GNUTLS_MIN_LIBTASN1_VERSION) == NULL) {
		gnutls_assert();
		_gnutls_debug_log("Checking for libtasn1 failed: %s < %s\n",
				  asn1_check_version(NULL),
				  GNUTLS_MIN_LIBTASN1_VERSION);
		ret = GNUTLS_E_INCOMPATIBLE_LIBTASN1_LIBRARY;
		goto out;
	}

	_gnutls_pkix1_asn = NULL;
	res = asn1_array2tree(pkix_asn1_tab, &_gnutls_pkix1_asn, NULL);
	if (res != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(res);
		goto out;
	}

	res = asn1_array2tree(gnutls_asn1_tab, &_gnutls_gnutls_asn, NULL);
	if (res != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(res);
		goto out;
	}

	/* Initialize the random generator */
	ret = _gnutls_rnd_preinit();
	if (ret < 0) {
		gnutls_assert();
		goto out;
	}

	/* Initialize the default TLS extensions */
	ret = _gnutls_hello_ext_init();
	if (ret < 0) {
		gnutls_assert();
		goto out;
	}

	ret = gnutls_system_global_init();
	if (ret < 0) {
		gnutls_assert();
		goto out;
	}

#ifndef _WIN32
	ret = _gnutls_register_fork_handler();
	if (ret < 0) {
		gnutls_assert();
		goto out;
	}
#endif

#ifdef ENABLE_FIPS140
	res = _gnutls_fips_mode_enabled();
	/* res == 1 -> fips140-2 mode enabled
	 * res == 2 -> only self checks performed - but no failure
	 * res == not in fips140 mode
	 */
	if (res != 0) {
		_gnutls_debug_log("FIPS140-2 mode: %d\n", res);
		_gnutls_priority_update_fips();

		/* first round of self checks, these are done on the
		 * nettle algorithms which are used internally */
		_gnutls_switch_lib_state(LIB_STATE_SELFTEST);
		ret = _gnutls_fips_perform_self_checks1();
		if (ret < 0) {
			_gnutls_switch_lib_state(LIB_STATE_ERROR);
			_gnutls_audit_log(
				NULL, "FIPS140-2 self testing part1 failed\n");
			if (res != 2) {
				gnutls_assert();
				goto out;
			}
		}
	}
#endif

	_gnutls_register_accel_crypto();
	_gnutls_cryptodev_init();
	_gnutls_afalg_init();
#ifdef HAVE_LEANCRYPTO
	lc_init(0);
#endif

#ifdef ENABLE_FIPS140
	/* These self tests are performed on the overridden algorithms
	 * (e.g., AESNI overridden AES). They are after _gnutls_register_accel_crypto()
	 * intentionally */
	if (res != 0) {
		_gnutls_switch_lib_state(LIB_STATE_SELFTEST);
		ret = _gnutls_fips_perform_self_checks2();
		if (ret < 0) {
			_gnutls_switch_lib_state(LIB_STATE_ERROR);
			_gnutls_audit_log(
				NULL, "FIPS140-2 self testing part 2 failed\n");
			if (res != 2) {
				gnutls_assert();
				goto out;
			}
		}
		_gnutls_fips_mode_reset_zombie();
	}
#endif

	_gnutls_prepare_to_load_system_priorities();

#if defined(ENABLE_PKCS11) && defined(ENABLE_FIPS140)
	p11_provider_path = _gnutls_config_get_p11_provider_path();
	p11_provider_pin = _gnutls_config_get_p11_provider_pin();

	if (res == 1 && p11_provider_path != NULL) {
		ret = _p11_provider_init(p11_provider_path,
					 (const uint8_t *)p11_provider_pin,
					 strlen(p11_provider_pin));
		if (ret < 0) {
			gnutls_assert();
			goto out;
		}
	}
#endif

	_gnutls_switch_lib_state(LIB_STATE_OPERATIONAL);
	ret = 0;

out:
	_gnutls_init_ret = ret;
	if (!constructor) {
		(void)gnutls_static_mutex_unlock(&global_init_mutex);
	}
	return ret;
}

static void _gnutls_global_deinit(unsigned destructor)
{
	if (!destructor) {
		if (gnutls_static_mutex_lock(&global_init_mutex) < 0) {
			return;
		}
	}

	if (_gnutls_init == 1) {
		_gnutls_init = 0;
		if (_gnutls_init_ret < 0) {
			/* only deinitialize if gnutls_global_init() has
			 * succeeded */
			gnutls_assert();
			goto fail;
		}

		_gnutls_system_key_deinit();
		gnutls_crypto_deinit();
		_gnutls_compression_deinit();
		_gnutls_rnd_deinit();
		_gnutls_hello_ext_deinit();
		asn1_delete_structure(&_gnutls_gnutls_asn);
		asn1_delete_structure(&_gnutls_pkix1_asn);

		_gnutls_crypto_deregister();
		gnutls_system_global_deinit();
		_gnutls_cryptodev_deinit();

		_gnutls_supplemental_deinit();
		_gnutls_unload_system_priorities();

#if defined(ENABLE_PKCS11) && defined(ENABLE_FIPS140)
		_p11_provider_deinit();
#endif

#ifdef ENABLE_PKCS11
		/* Do not try to deinitialize the PKCS #11 libraries
		 * from the destructor. If we do and the PKCS #11 modules
		 * are already being unloaded, we may crash.
		 */
		if (destructor == 0) {
			gnutls_pkcs11_deinit();
		}
#endif
#ifdef HAVE_TROUSERS
		_gnutls_tpm_global_deinit();
#endif
#ifdef HAVE_TPM2
		_gnutls_tpm2_deinit();
#endif

		_gnutls_nss_keylog_deinit();
	} else {
		if (_gnutls_init > 0)
			_gnutls_init--;
	}

fail:
	if (!destructor) {
		(void)gnutls_static_mutex_unlock(&global_init_mutex);
	}
}

/**
 * gnutls_global_deinit:
 *
 * This function deinitializes the global data, that were initialized
 * using gnutls_global_init().
 *
 * Since GnuTLS 3.3.0 this function is no longer necessary to be explicitly
 * called. GnuTLS will automatically deinitialize on library destructor. See
 * gnutls_global_init() for disabling the implicit initialization/deinitialization.
 *
 **/
void gnutls_global_deinit(void)
{
	_gnutls_global_deinit(0);
}

/**
 * gnutls_check_version:
 * @req_version: version string to compare with, or %NULL.
 *
 * Check the GnuTLS Library version against the provided string.
 * See %GNUTLS_VERSION for a suitable @req_version string.
 *
 * See also gnutls_check_version_numeric(), which provides this
 * functionality as a macro.
 *
 * Returns: Check that the version of the library is at
 *   minimum the one given as a string in @req_version and return the
 *   actual version string of the library; return %NULL if the
 *   condition is not met.  If %NULL is passed to this function no
 *   check is done and only the version string is returned.
  **/
const char *gnutls_check_version(const char *req_version)
{
	if (!req_version || strverscmp(req_version, VERSION) <= 0)
		return VERSION;

	return NULL;
}

static void _CONSTRUCTOR lib_init(void)
{
	int ret;
	const char *e;

	if (_gnutls_global_init_skip() != 0)
		return;

	e = secure_getenv("GNUTLS_NO_IMPLICIT_INIT");
	if (e != NULL) {
		ret = atoi(e);
		if (ret == 1)
			return;
	}

	e = secure_getenv("GNUTLS_NO_EXPLICIT_INIT");
	if (e != NULL) {
		_gnutls_debug_log(
			"GNUTLS_NO_EXPLICIT_INIT is deprecated; use GNUTLS_NO_IMPLICIT_INIT\n");
		ret = atoi(e);
		if (ret == 1)
			return;
	}

	ret = _gnutls_global_init(1);
	if (ret < 0) {
		fprintf(stderr, "Error in GnuTLS initialization: %s\n",
			gnutls_strerror(ret));
		_gnutls_switch_lib_state(LIB_STATE_ERROR);
	}
}

static void _DESTRUCTOR lib_deinit(void)
{
	int ret;
	const char *e;

	if (_gnutls_global_init_skip() != 0)
		return;

	e = secure_getenv("GNUTLS_NO_IMPLICIT_INIT");
	if (e != NULL) {
		ret = atoi(e);
		if (ret == 1)
			return;
	}

	e = secure_getenv("GNUTLS_NO_EXPLICIT_INIT");
	if (e != NULL) {
		_gnutls_debug_log(
			"GNUTLS_NO_EXPLICIT_INIT is deprecated; use GNUTLS_NO_IMPLICIT_INIT\n");
		ret = atoi(e);
		if (ret == 1)
			return;
	}

	_gnutls_global_deinit(1);
}

static const struct gnutls_library_config_st _gnutls_library_config[] = {
#ifdef FIPS_MODULE_NAME
	{ "fips-module-name", FIPS_MODULE_NAME },
#endif
#ifdef FIPS_MODULE_VERSION
	{ "fips-module-version", FIPS_MODULE_VERSION },
#endif
#ifdef GNUTLS_LIBRARY_SONAME
	{ "libgnutls-soname", GNUTLS_LIBRARY_SONAME },
#endif
#ifdef NETTLE_LIBRARY_SONAME
	{ "libnettle-soname", NETTLE_LIBRARY_SONAME },
#endif
#ifdef HOGWEED_LIBRARY_SONAME
	{ "libhogweed-soname", HOGWEED_LIBRARY_SONAME },
#endif
#ifdef GMP_LIBRARY_SONAME
	{ "libgmp-soname", GMP_LIBRARY_SONAME },
#endif
	{ "hardware-features", HW_FEATURES },
	{ "tls-features", TLS_FEATURES },
#ifdef DEFAULT_TRUST_STORE_PKCS11
	{ "default-trust-store-pkcs11", DEFAULT_TRUST_STORE_PKCS11 },
#endif
#ifdef DEFAULT_TRUST_STORE_DIR
	{ "default-trust-store-dir", DEFAULT_TRUST_STORE_DIR },
#endif
#ifdef DEFAULT_TRUST_STORE_FILE
	{ "default-trust-store-file", DEFAULT_TRUST_STORE_FILE },
#endif
	{ "default-system-config", SYSTEM_PRIORITY_FILE },
	{ NULL, NULL }
};

/**
 * gnutls_get_library_config:
 *
 * Returns the library configuration as key value pairs.
 * Currently defined keys are:
 *
 *  - fips-module-name: the name of the FIPS140 module
 *
 *  - fips-module-version: the version of the FIPS140 module
 *
 *  - libgnutls-soname: the SONAME of the library itself
 *
 *  - libnettle-soname: the library SONAME of linked libnettle
 *
 *  - libhogweed-soname: the library SONAME of linked libhogweed
 *
 *  - libgmp-soname: the library SONAME of linked libgmp
 *
 *  - hardware-features: enabled hardware support features
 *
 *  - tls-features: enabled TLS protocol features
 *
 * Returns: a NUL-terminated %gnutls_library_config_st array
 *
 * Since: 3.7.3
 */
const gnutls_library_config_st *gnutls_get_library_config(void)
{
	return _gnutls_library_config;
}
