# Keep exit status authoritative while also requiring the fixture's result text.
function(dssh_add_output_test name target required_output)
	set(command "$<TARGET_FILE:${target}>" ${ARGN})
	get_target_property(emulator ${target} CROSSCOMPILING_EMULATOR)
	if(emulator)
		list(PREPEND command ${emulator})
	endif()
	get_target_property(launcher ${target} TEST_LAUNCHER)
	if(launcher)
		list(PREPEND command ${launcher})
	endif()
	add_test(NAME "${name}" COMMAND "${CMAKE_COMMAND}"
		"-DTEST_COMMAND=${command}" "-DTEST_REQUIRED_OUTPUT=${required_output}"
		-P "${CMAKE_CURRENT_SOURCE_DIR}/check_output.cmake")
endfunction()

add_test(NAME dssh_test_output_policy COMMAND "${CMAKE_COMMAND}"
	-P "${CMAKE_CURRENT_SOURCE_DIR}/check_output_test.cmake")

add_test(NAME dssh_c_standard COMMAND "${CMAKE_COMMAND}"
	"-DTEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/c-standard-tests"
	-P "${CMAKE_CURRENT_SOURCE_DIR}/c_standard.cmake")

# Cached key files for test runs — avoids repeated RSA keygen.
# These are stored in the build directory and reused across runs.
set(DSSH_TEST_KEY_ENV
	"DSSH_TEST_ED25519_KEY=${CMAKE_CURRENT_BINARY_DIR}/test_ed25519.pem"
	"DSSH_TEST_RSA_KEY=${CMAKE_CURRENT_BINARY_DIR}/test_rsa.pem")

# Fresh-process production-library consumers must not use the test registry
# reset, which would otherwise hide first-use publication behavior.
foreach(kind IN ITEMS static shared)
	if(TARGET deucessh_${kind})
		set(target dssh_test_session_init_${kind})
		add_executable(${target} test_session_init.c)
		# A shared-library consumer supplies its own C11 thread facility;
		# the library's private dependency is not part of its public API.
		foreach(shim IN LISTS DSSH_THREADS_SHIM_SOURCES)
			target_sources(${target} PRIVATE "${PROJECT_SOURCE_DIR}/${shim}")
		endforeach()
		set_property(TARGET ${target} PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
		set_property(TARGET ${target} PROPERTY C_STANDARD_REQUIRED ON)
		target_compile_options(${target} PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
		target_link_libraries(${target} PRIVATE deucessh_${kind} ${THREADS_LINK_LIB})
		if(DSSH_THREADS_SHIM_INCLUDE)
			target_include_directories(${target} BEFORE PRIVATE ${DSSH_THREADS_SHIM_INCLUDE})
		endif()
		dssh_add_output_test(dssh_session_init_${kind}_default ${target} "workers=8 sessions=256 failures=0 frozen=1")
		dssh_add_output_test(dssh_session_init_${kind}_configured ${target} "workers=8 sessions=256 failures=0 frozen=1"
			configured)
		set_tests_properties(dssh_session_init_${kind}_default dssh_session_init_${kind}_configured
			PROPERTIES TIMEOUT 60)
		set(release_target dssh_test_release_entry_${kind})
		add_executable(${release_target} test_release_entry.c)
		set_property(TARGET ${release_target} PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
		set_property(TARGET ${release_target} PROPERTY C_STANDARD_REQUIRED ON)
		target_compile_options(${release_target} PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
		target_link_libraries(${release_target} PRIVATE deucessh_${kind})
		dssh_add_output_test(dssh_release_entry_${kind} ${release_target} "release_entries=48 releases=4 before=1 after=1 restored=1")
		set_tests_properties(dssh_release_entry_${kind} PROPERTIES TIMEOUT 60)
		if(DEUCESSH_CRYPTO_BACKEND STREQUAL "OpenSSL")
			set(rng_target dssh_test_rng_provider_${kind})
			add_executable(${rng_target} test_rng_provider.c)
			set_property(TARGET ${rng_target} PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
			set_property(TARGET ${rng_target} PROPERTY C_STANDARD_REQUIRED ON)
			target_compile_options(${rng_target} PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
			target_link_libraries(${rng_target} PRIVATE deucessh_${kind} OpenSSL::Crypto)
			foreach(mode IN ITEMS aes128 aes192 aes256 invalid)
				dssh_add_output_test(dssh_rng_provider_${kind}_${mode} ${rng_target}
					"rng_policy=1 mode=${mode} production=1" ${mode})
			endforeach()
		endif()
		if(UNIX)
			set(event_target dssh_test_event_peer_${kind})
			add_executable(${event_target} test_event_peer.c mock_io.c)
			foreach(shim IN LISTS DSSH_THREADS_SHIM_SOURCES)
				target_sources(${event_target} PRIVATE "${PROJECT_SOURCE_DIR}/${shim}")
			endforeach()
			set_property(TARGET ${event_target} PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
			set_property(TARGET ${event_target} PROPERTY C_STANDARD_REQUIRED ON)
			target_compile_options(${event_target} PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
			# This application fixture uses the host socket test driver,
			# including its nonblocking drain helper; it is not library code.
			target_compile_definitions(${event_target} PRIVATE _DEFAULT_SOURCE)
			target_link_libraries(${event_target} PRIVATE deucessh_${kind} ${THREADS_LINK_LIB})
			if(DSSH_THREADS_SHIM_INCLUDE)
				target_include_directories(${event_target} BEFORE PRIVATE ${DSSH_THREADS_SHIM_INCLUDE})
			endif()
			dssh_add_output_test(dssh_event_peer_${kind} ${event_target} "events=130 queue=0 positions=3/2 production=1")
			set_tests_properties(dssh_event_peer_${kind} PROPERTIES TIMEOUT 60)
			set(callback_target dssh_test_accept_callback_peer_${kind})
			add_executable(${callback_target} test_accept_callback_peer.c mock_io.c)
			foreach(shim IN LISTS DSSH_THREADS_SHIM_SOURCES)
				target_sources(${callback_target} PRIVATE "${PROJECT_SOURCE_DIR}/${shim}")
			endforeach()
			set_property(TARGET ${callback_target} PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
			set_property(TARGET ${callback_target} PROPERTY C_STANDARD_REQUIRED ON)
			target_compile_options(${callback_target} PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
			target_compile_definitions(${callback_target} PRIVATE _DEFAULT_SOURCE)
			target_link_libraries(${callback_target} PRIVATE deucessh_${kind} ${THREADS_LINK_LIB})
			if(DSSH_THREADS_SHIM_INCLUDE)
				target_include_directories(${callback_target} BEFORE PRIVATE ${DSSH_THREADS_SHIM_INCLUDE})
			endif()
			foreach(mode RANGE 0 5)
				dssh_add_output_test(dssh_accept_callback_peer_${kind}_${mode} ${callback_target} "setup_contract=1 kind=${mode}.*production=1"
					${mode})
				set_tests_properties(dssh_accept_callback_peer_${kind}_${mode} PROPERTIES TIMEOUT 60)
			endforeach()

		endif()
	endif()
endforeach()

# Prepend project root to source paths (they're relative to ssh/, not test/)
set(DSSH_TEST_LIB_SOURCES "")
foreach(src ${DEUCESSH_SOURCES})
	list(APPEND DSSH_TEST_LIB_SOURCES "${PROJECT_SOURCE_DIR}/${src}")
endforeach()

# Test-instrumented static library (exposes DSSH_TESTABLE functions)
add_library(deucessh_test_lib STATIC ${DSSH_TEST_LIB_SOURCES})
set_property(TARGET deucessh_test_lib PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
set_property(TARGET deucessh_test_lib PROPERTY C_STANDARD_REQUIRED ON)
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "Botan")
	set_property(TARGET deucessh_test_lib PROPERTY CXX_STANDARD 20)
	set_property(TARGET deucessh_test_lib PROPERTY CXX_STANDARD_REQUIRED ON)
endif()
target_compile_definitions(deucessh_test_lib PRIVATE DSSH_TESTING
	$<$<COMPILE_LANGUAGE:C>:_POSIX_C_SOURCE=200809L>
	$<$<STREQUAL:${DEUCESSH_CRYPTO_BACKEND},OpenSSL>:DSSH_CRYPTO_OPENSSL>
	$<$<STREQUAL:${DEUCESSH_CRYPTO_BACKEND},Botan>:DSSH_CRYPTO_BOTAN>)
target_include_directories(deucessh_test_lib
	PUBLIC ${PROJECT_SOURCE_DIR}
	PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
if(DSSH_THREADS_SHIM_INCLUDE)
	target_include_directories(deucessh_test_lib BEFORE
		PUBLIC ${DSSH_THREADS_SHIM_INCLUDE})
endif()
target_include_directories(deucessh_test_lib SYSTEM
	PRIVATE ${DSSH_CRYPTO_INCLUDE})
target_link_libraries(deucessh_test_lib
	INTERFACE ${DSSH_CRYPTO_LIB_INTERFACE} ${THREADS_LINK_LIB}
		${DSSH_PRIVATE_KEY_FILE_LIB} ${DSSH_MATH_LINK_LIB})
target_compile_options(deucessh_test_lib PRIVATE
	${DEUCESSH_COMPILE_OPTIONS}
	$<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>,$<C_COMPILER_ID:GNU>>:
		-Wno-unused-function>)

# Mock I/O library
add_library(dssh_mock_io STATIC mock_io.c)
set_property(TARGET dssh_mock_io PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
set_property(TARGET dssh_mock_io PROPERTY C_STANDARD_REQUIRED ON)
target_include_directories(dssh_mock_io PUBLIC
	${PROJECT_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(dssh_mock_io PRIVATE deucessh_test_lib)

# Library-only test allocator (macro-based, doesn't affect OpenSSL)
add_library(dssh_test_allocator STATIC dssh_test_alloc.c)
set_property(TARGET dssh_test_allocator PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
set_property(TARGET dssh_test_allocator PROPERTY C_STANDARD_REQUIRED ON)
target_include_directories(dssh_test_allocator PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR})
# Crypto + C11 threads failure injection library
add_library(dssh_test_ossl STATIC dssh_test_ossl.c)
if(UNIX)
	target_compile_definitions(dssh_test_ossl PRIVATE _POSIX_C_SOURCE=200809L)
endif()
set_property(TARGET dssh_test_ossl PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
set_property(TARGET dssh_test_ossl PROPERTY C_STANDARD_REQUIRED ON)
target_include_directories(dssh_test_ossl PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR})
if(DSSH_THREADS_SHIM_INCLUDE)
	target_include_directories(dssh_test_ossl BEFORE
		PRIVATE ${DSSH_THREADS_SHIM_INCLUDE})
endif()
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "OpenSSL")
	target_link_libraries(dssh_test_ossl PRIVATE OpenSSL::Crypto)
	target_compile_definitions(dssh_test_ossl PRIVATE DSSH_CRYPTO_OPENSSL)
elseif(DEUCESSH_CRYPTO_BACKEND STREQUAL "Botan")
	target_compile_definitions(dssh_test_ossl PRIVATE DSSH_CRYPTO_BOTAN)
endif()

# Link allocator and injection into the test library
# so all test executables get the definitions library code references.
target_link_libraries(deucessh_test_lib INTERFACE
	dssh_test_allocator dssh_test_ossl)
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "Botan")
	add_library(dssh_test_botan_hash STATIC dssh_test_botan_hash.cpp)
	set_property(TARGET dssh_test_botan_hash PROPERTY CXX_STANDARD 20)
	set_property(TARGET dssh_test_botan_hash PROPERTY CXX_STANDARD_REQUIRED ON)
	target_include_directories(dssh_test_botan_hash PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
	target_link_libraries(dssh_test_botan_hash PRIVATE PkgConfig::BOTAN3)
	target_compile_options(dssh_test_botan_hash PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
	target_link_libraries(deucessh_test_lib INTERFACE dssh_test_botan_hash)
endif()

# External test providers compiled against public headers only.
add_library(dssh_mock_comp STATIC test_comp.c test_comp_zlib.c test_stateless.c)
set_property(TARGET dssh_mock_comp PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
set_property(TARGET dssh_mock_comp PROPERTY C_STANDARD_REQUIRED ON)
target_include_directories(dssh_mock_comp PUBLIC
	${PROJECT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(dssh_mock_comp PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
target_link_libraries(dssh_mock_comp PRIVATE deucessh_test_lib)
find_package(ZLIB QUIET)
if(ZLIB_FOUND)
	target_sources(dssh_mock_comp PRIVATE ../examples/zlib-comp.c)
	target_compile_definitions(dssh_mock_comp PRIVATE DSSH_TEST_HAVE_ZLIB DSSH_EXAMPLE_ZLIB_TESTING)
	target_link_libraries(dssh_mock_comp PRIVATE ZLIB::ZLIB)
	if(UNIX AND TARGET deucessh_static)
		# Separate production-library consumer: no DSSH_TESTING/internal headers.
		add_executable(dssh_compression_peer_server
			compression_peer_server.c test_comp_zlib.c ../examples/zlib-comp.c)
		set_property(TARGET dssh_compression_peer_server PROPERTY C_STANDARD 17)
		set_property(TARGET dssh_compression_peer_server PROPERTY C_STANDARD_REQUIRED ON)
		target_compile_definitions(dssh_compression_peer_server PRIVATE
			_POSIX_C_SOURCE=200809L DSSH_TEST_HAVE_ZLIB DSSH_EXAMPLE_ZLIB_TESTING)
		target_compile_options(dssh_compression_peer_server PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
		target_link_libraries(dssh_compression_peer_server PRIVATE deucessh_static ZLIB::ZLIB)
		find_package(PkgConfig QUIET)
		if(PkgConfig_FOUND)
			pkg_check_modules(DSSH_INTEROP_LIBSSH QUIET IMPORTED_TARGET libssh)
			if(DSSH_INTEROP_LIBSSH_FOUND)
				add_executable(dssh_compression_libssh_client compression_libssh_client.c)
				set_property(TARGET dssh_compression_libssh_client PROPERTY C_STANDARD 17)
				set_property(TARGET dssh_compression_libssh_client PROPERTY C_STANDARD_REQUIRED ON)
				target_compile_definitions(dssh_compression_libssh_client PRIVATE _POSIX_C_SOURCE=200809L)
				target_compile_options(dssh_compression_libssh_client PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
				target_link_libraries(dssh_compression_libssh_client PRIVATE PkgConfig::DSSH_INTEROP_LIBSSH)
				add_test(NAME dssh_compression_libssh
					COMMAND dssh_compression_libssh_client $<TARGET_FILE:dssh_compression_peer_server>)
				set_tests_properties(dssh_compression_libssh PROPERTIES TIMEOUT 60)
				foreach(direction IN ITEMS c2s s2c)
					add_test(NAME dssh_compression_libssh_${direction}
						COMMAND dssh_compression_libssh_client $<TARGET_FILE:dssh_compression_peer_server> ${direction})
					set_tests_properties(dssh_compression_libssh_${direction} PROPERTIES TIMEOUT 60)
				endforeach()
			endif()
		endif()
	endif()
endif()

# Mock allocator library (--wrap based, for process-wide injection).
# Apple's Mach-O linker does not support the GNU --wrap option.
if(NOT APPLE)
	add_library(dssh_mock_alloc STATIC mock_alloc.c)
	set_property(TARGET dssh_mock_alloc PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
	set_property(TARGET dssh_mock_alloc PROPERTY C_STANDARD_REQUIRED ON)
	target_include_directories(dssh_mock_alloc PUBLIC
		${CMAKE_CURRENT_SOURCE_DIR})

	set(DSSH_WRAP_FLAGS
		-Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free)
endif()

# This exercises the bundled C glue directly without a provider, registry or
# library test hooks. The runner uses only standard C library facilities.
add_executable(dssh_test_vendor_glue test_vendor_glue.c)
set_property(TARGET dssh_test_vendor_glue PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
set_property(TARGET dssh_test_vendor_glue PROPERTY C_STANDARD_REQUIRED ON)
target_include_directories(dssh_test_vendor_glue PRIVATE ${PROJECT_SOURCE_DIR})
target_compile_options(dssh_test_vendor_glue PRIVATE ${DEUCESSH_COMPILE_OPTIONS}
	$<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>,$<C_COMPILER_ID:GNU>>:-Wno-unused-function>)
add_test(NAME dssh_unit_vendor_glue COMMAND dssh_test_vendor_glue)
set_tests_properties(dssh_unit_vendor_glue PROPERTIES TIMEOUT 60)

# Pinned official NIST answers, shared by the actual bundled and native roots.
add_library(dssh_mlkem_acvp_data STATIC mlkem_acvp_data.c)
set_property(TARGET dssh_mlkem_acvp_data PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
set_property(TARGET dssh_mlkem_acvp_data PROPERTY C_STANDARD_REQUIRED ON)
target_compile_options(dssh_mlkem_acvp_data PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
add_executable(dssh_test_mlkem_acvp test_mlkem_acvp.c)
set_property(TARGET dssh_test_mlkem_acvp PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
set_property(TARGET dssh_test_mlkem_acvp PROPERTY C_STANDARD_REQUIRED ON)
target_include_directories(dssh_test_mlkem_acvp PRIVATE ${PROJECT_SOURCE_DIR})
target_compile_options(dssh_test_mlkem_acvp PRIVATE ${DEUCESSH_COMPILE_OPTIONS}
	$<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:AppleClang>,$<C_COMPILER_ID:GNU>>:-Wno-unused-function>)
target_link_libraries(dssh_test_mlkem_acvp PRIVATE dssh_mlkem_acvp_data)
dssh_add_output_test(dssh_mlkem_acvp_bundled dssh_test_mlkem_acvp
	"ML-KEM ACVP bundled: 145 passed, 0 failed")
set_tests_properties(dssh_mlkem_acvp_bundled PROPERTIES TIMEOUT 120)
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "Botan")
	add_executable(dssh_test_mlkem_acvp_botan test_mlkem_acvp_botan.cpp)
	set_property(TARGET dssh_test_mlkem_acvp_botan PROPERTY CXX_STANDARD 20)
	set_property(TARGET dssh_test_mlkem_acvp_botan PROPERTY CXX_STANDARD_REQUIRED ON)
	target_compile_options(dssh_test_mlkem_acvp_botan PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
	target_link_libraries(dssh_test_mlkem_acvp_botan PRIVATE dssh_mlkem_acvp_data PkgConfig::BOTAN3)
	dssh_add_output_test(dssh_mlkem_acvp_botan dssh_test_mlkem_acvp_botan
		"ML-KEM ACVP Botan: 145 passed, 0 failed")
	set_tests_properties(dssh_mlkem_acvp_botan PROPERTIES TIMEOUT 120)
endif()

# Helper function for adding provider-backed test executables
function(dssh_add_test test_name source_file)
	add_executable(dssh_test_${test_name} ${source_file})
	# Test clocks, mkstemp(), and strdup() need the POSIX namespace in
	# strict C modes. Leave C++'s native library namespace unchanged.
	target_compile_definitions(dssh_test_${test_name} PRIVATE
		$<$<COMPILE_LANGUAGE:C>:_POSIX_C_SOURCE=200809L>)
	set_property(TARGET dssh_test_${test_name} PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
	set_property(TARGET dssh_test_${test_name} PROPERTY C_STANDARD_REQUIRED ON)
	target_include_directories(dssh_test_${test_name} PRIVATE
		${PROJECT_SOURCE_DIR}
		${CMAKE_CURRENT_SOURCE_DIR})
	target_include_directories(dssh_test_${test_name} SYSTEM
		PRIVATE ${DSSH_CRYPTO_INCLUDE})
	target_link_libraries(dssh_test_${test_name} PRIVATE
		deucessh_test_lib ${DSSH_CRYPTO_LIB_INTERFACE} ${THREADS_LINK_LIB})
	target_compile_options(dssh_test_${test_name} PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
	if(DEUCESSH_CRYPTO_BACKEND STREQUAL "OpenSSL")
		target_compile_definitions(dssh_test_${test_name} PRIVATE DSSH_CRYPTO_OPENSSL)
	elseif(DEUCESSH_CRYPTO_BACKEND STREQUAL "Botan")
		target_compile_definitions(dssh_test_${test_name} PRIVATE DSSH_CRYPTO_BOTAN)
	endif()
endfunction()

# Exercise the exact production packet arithmetic under unsigned size models.
foreach(model IN ITEMS native u16 u32 u64)
	add_executable(dssh_test_packet_sizes_${model} test_packet_sizes.c)
	set_property(TARGET dssh_test_packet_sizes_${model} PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
	set_property(TARGET dssh_test_packet_sizes_${model} PROPERTY C_STANDARD_REQUIRED ON)
	target_include_directories(dssh_test_packet_sizes_${model} PRIVATE ${PROJECT_SOURCE_DIR})
	target_compile_options(dssh_test_packet_sizes_${model} PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
	target_compile_definitions(dssh_test_packet_sizes_${model} PRIVATE DSSH_PACKET_MODEL_NAME="${model}")
	if(NOT model STREQUAL "native")
		string(SUBSTRING ${model} 1 -1 bits)
		target_compile_definitions(dssh_test_packet_sizes_${model} PRIVATE
			DSSH_PACKET_SIZE_TYPE=uint${bits}_t DSSH_PACKET_SIZE_LIMIT=UINT${bits}_MAX
			DSSH_PACKET_MODEL_BITS=${bits})
	endif()
	dssh_add_output_test(dssh_packet_sizes_${model} dssh_test_packet_sizes_${model}
		"packet_sizes model=${model} width=[0-9]+ checks=[1-9][0-9]* failed=0")
endforeach()

# Exercise the exact production time arithmetic under different C type models.
foreach(model IN ITEMS i16 u16 i32 u32 i64 u64 f32 f64 fwide)
	if(model STREQUAL "i16")
		set(time_type int16_t)
		set(time_max INT16_MAX)
		set(time_min INT16_MIN)
	elseif(model STREQUAL "u16")
		set(time_type uint16_t)
		set(time_max UINT16_MAX)
		set(time_min 0)
	elseif(model STREQUAL "i32")
		set(time_type int32_t)
		set(time_max INT32_MAX)
		set(time_min INT32_MIN)
	elseif(model STREQUAL "u32")
		set(time_type uint32_t)
		set(time_max UINT32_MAX)
		set(time_min 0)
	elseif(model STREQUAL "i64")
		set(time_type int64_t)
		set(time_max INT64_MAX)
		set(time_min INT64_MIN)
	elseif(model STREQUAL "u64")
		set(time_type uint64_t)
		set(time_max UINT64_MAX)
		set(time_min 0)
	elseif(model STREQUAL "f32")
		set(time_type float)
		set(time_max FLT_MAX)
		set(time_min -FLT_MAX)
	elseif(model STREQUAL "f64")
		set(time_type double)
		set(time_max DBL_MAX)
		set(time_min -DBL_MAX)
	else()
		set(time_type "long double")
		set(time_max LDBL_MAX)
		set(time_min -LDBL_MAX)
	endif()
	dssh_add_test(time_${model} test_time.c)
	target_compile_definitions(dssh_test_time_${model} PRIVATE
		DSSH_TIME_MODEL_TYPE=${time_type}
		DSSH_TIME_MODEL_MAX=${time_max} DSSH_TIME_MODEL_MIN=${time_min})
	if(model MATCHES "^u")
		target_compile_definitions(dssh_test_time_${model} PRIVATE DSSH_TIME_MODEL_SIGNED=0)
	else()
		target_compile_definitions(dssh_test_time_${model} PRIVATE DSSH_TIME_MODEL_SIGNED=1)
	endif()
	if(model MATCHES "^f")
		target_compile_definitions(dssh_test_time_${model} PRIVATE DSSH_TIME_MODEL_FLOAT=1)
	else()
		target_compile_definitions(dssh_test_time_${model} PRIVATE DSSH_TIME_MODEL_FLOAT=0)
	endif()
	if(model MATCHES "16$")
		target_compile_definitions(dssh_test_time_${model} PRIVATE DSSH_TIME_MODEL_NARROW=1)
	else()
		target_compile_definitions(dssh_test_time_${model} PRIVATE DSSH_TIME_MODEL_NARROW=0)
	endif()
	add_test(NAME dssh_unit_time_${model} COMMAND dssh_test_time_${model})
endforeach()

# The assertion hook must run before stack-owned contexts go out of scope.
dssh_add_test(framework test_framework.c)
add_test(NAME dssh_test_framework COMMAND dssh_test_framework)

# A shared cache needs a single writer before parallel tests start.  Unit key
# tests also load these files without going through test_generate_host_key().
dssh_add_test(key_setup test_key_setup.c)
add_test(NAME dssh_test_keys COMMAND dssh_test_key_setup)
set_tests_properties(dssh_test_keys PROPERTIES
	FIXTURES_SETUP dssh_cached_keys ENVIRONMENT "${DSSH_TEST_KEY_ENV}")

# Helper: register one executable × 16 KEX/key/MAC variants as CTest entries.
# Each entry runs the full executable (all tests in one process).
macro(dssh_add_variant_tests test_name executable)
	add_test(NAME ${test_name} COMMAND ${executable})
	set_tests_properties(${test_name} PROPERTIES
		ENVIRONMENT "${DSSH_TEST_KEY_ENV}")
	add_test(NAME ${test_name}_hmac256 COMMAND ${executable})
	set_tests_properties(${test_name}_hmac256 PROPERTIES
		ENVIRONMENT "DSSH_TEST_MAC=hmac256;${DSSH_TEST_KEY_ENV}")
	add_test(NAME ${test_name}_dhgex COMMAND ${executable})
	set_tests_properties(${test_name}_dhgex PROPERTIES
		ENVIRONMENT "DSSH_TEST_KEX=dh-gex;${DSSH_TEST_KEY_ENV}")
	add_test(NAME ${test_name}_rsa COMMAND ${executable})
	set_tests_properties(${test_name}_rsa PROPERTIES
		ENVIRONMENT "DSSH_TEST_KEY=rsa;${DSSH_TEST_KEY_ENV}")
	add_test(NAME ${test_name}_rsa512 COMMAND ${executable})
	set_tests_properties(${test_name}_rsa512 PROPERTIES
		ENVIRONMENT "DSSH_TEST_KEY=rsa512;${DSSH_TEST_KEY_ENV}")
	add_test(NAME ${test_name}_dhgex_rsa COMMAND ${executable})
	set_tests_properties(${test_name}_dhgex_rsa PROPERTIES
		ENVIRONMENT "DSSH_TEST_KEX=dh-gex;DSSH_TEST_KEY=rsa;${DSSH_TEST_KEY_ENV}")
	add_test(NAME ${test_name}_dhgex_rsa512 COMMAND ${executable})
	set_tests_properties(${test_name}_dhgex_rsa512 PROPERTIES
		ENVIRONMENT "DSSH_TEST_KEX=dh-gex;DSSH_TEST_KEY=rsa512;${DSSH_TEST_KEY_ENV}")
	add_test(NAME ${test_name}_sntrup COMMAND ${executable})
	set_tests_properties(${test_name}_sntrup PROPERTIES
		ENVIRONMENT "DSSH_TEST_KEX=sntrup;${DSSH_TEST_KEY_ENV}")
	add_test(NAME ${test_name}_sntrup_rsa COMMAND ${executable})
	set_tests_properties(${test_name}_sntrup_rsa PROPERTIES
		ENVIRONMENT "DSSH_TEST_KEX=sntrup;DSSH_TEST_KEY=rsa;${DSSH_TEST_KEY_ENV}")
	add_test(NAME ${test_name}_sntrup_rsa512 COMMAND ${executable})
	set_tests_properties(${test_name}_sntrup_rsa512 PROPERTIES
		ENVIRONMENT "DSSH_TEST_KEX=sntrup;DSSH_TEST_KEY=rsa512;${DSSH_TEST_KEY_ENV}")
	add_test(NAME ${test_name}_mlkem COMMAND ${executable})
	set_tests_properties(${test_name}_mlkem PROPERTIES
		ENVIRONMENT "DSSH_TEST_KEX=mlkem;${DSSH_TEST_KEY_ENV}")
	add_test(NAME ${test_name}_mlkem_rsa COMMAND ${executable})
	set_tests_properties(${test_name}_mlkem_rsa PROPERTIES
		ENVIRONMENT "DSSH_TEST_KEX=mlkem;DSSH_TEST_KEY=rsa;${DSSH_TEST_KEY_ENV}")
	add_test(NAME ${test_name}_mlkem_rsa512 COMMAND ${executable})
	set_tests_properties(${test_name}_mlkem_rsa512 PROPERTIES
		ENVIRONMENT "DSSH_TEST_KEX=mlkem;DSSH_TEST_KEY=rsa512;${DSSH_TEST_KEY_ENV}")
	add_test(NAME ${test_name}_rsa_hmac256 COMMAND ${executable})
	set_tests_properties(${test_name}_rsa_hmac256 PROPERTIES
		ENVIRONMENT "DSSH_TEST_KEY=rsa;DSSH_TEST_MAC=hmac256;${DSSH_TEST_KEY_ENV}")
	add_test(NAME ${test_name}_dhgex_hmac256 COMMAND ${executable})
	set_tests_properties(${test_name}_dhgex_hmac256 PROPERTIES
		ENVIRONMENT "DSSH_TEST_KEX=dh-gex;DSSH_TEST_MAC=hmac256;${DSSH_TEST_KEY_ENV}")
	add_test(NAME ${test_name}_sntrup_hmac256 COMMAND ${executable})
	set_tests_properties(${test_name}_sntrup_hmac256 PROPERTIES
		ENVIRONMENT "DSSH_TEST_KEX=sntrup;DSSH_TEST_MAC=hmac256;${DSSH_TEST_KEY_ENV}")
endmacro()

# Helper: register one test per name × KEX/key/MAC variants as separate
# CTest entries.  Each entry runs one test in its own process.
# Use for test suites where per-test parallelism matters (e.g. auth
# with expensive sntrup handshakes).
macro(dssh_add_individual_tests executable prefix test_list)
	foreach(t ${${test_list}})
		add_test(NAME ${prefix}_${t}
			COMMAND ${executable} --exact ${t})
		set_tests_properties(${prefix}_${t} PROPERTIES
			ENVIRONMENT "${DSSH_TEST_KEY_ENV}")
		add_test(NAME ${prefix}_${t}_dhgex
			COMMAND ${executable} --exact ${t})
		set_tests_properties(${prefix}_${t}_dhgex PROPERTIES
			ENVIRONMENT "DSSH_TEST_KEX=dh-gex;${DSSH_TEST_KEY_ENV}")
		add_test(NAME ${prefix}_${t}_rsa
			COMMAND ${executable} --exact ${t})
		set_tests_properties(${prefix}_${t}_rsa PROPERTIES
			ENVIRONMENT "DSSH_TEST_KEY=rsa;${DSSH_TEST_KEY_ENV}")
		add_test(NAME ${prefix}_${t}_rsa512
			COMMAND ${executable} --exact ${t})
		set_tests_properties(${prefix}_${t}_rsa512 PROPERTIES
			ENVIRONMENT "DSSH_TEST_KEY=rsa512;${DSSH_TEST_KEY_ENV}")
		add_test(NAME ${prefix}_${t}_dhgex_rsa
			COMMAND ${executable} --exact ${t})
		set_tests_properties(${prefix}_${t}_dhgex_rsa PROPERTIES
			ENVIRONMENT "DSSH_TEST_KEX=dh-gex;DSSH_TEST_KEY=rsa;${DSSH_TEST_KEY_ENV}")
		add_test(NAME ${prefix}_${t}_dhgex_rsa512
			COMMAND ${executable} --exact ${t})
		set_tests_properties(${prefix}_${t}_dhgex_rsa512 PROPERTIES
			ENVIRONMENT "DSSH_TEST_KEX=dh-gex;DSSH_TEST_KEY=rsa512;${DSSH_TEST_KEY_ENV}")
		add_test(NAME ${prefix}_${t}_sntrup
			COMMAND ${executable} --exact ${t})
		set_tests_properties(${prefix}_${t}_sntrup PROPERTIES
			ENVIRONMENT "DSSH_TEST_KEX=sntrup;${DSSH_TEST_KEY_ENV}")
		add_test(NAME ${prefix}_${t}_sntrup_rsa
			COMMAND ${executable} --exact ${t})
		set_tests_properties(${prefix}_${t}_sntrup_rsa PROPERTIES
			ENVIRONMENT "DSSH_TEST_KEX=sntrup;DSSH_TEST_KEY=rsa;${DSSH_TEST_KEY_ENV}")
		add_test(NAME ${prefix}_${t}_sntrup_rsa512
			COMMAND ${executable} --exact ${t})
		set_tests_properties(${prefix}_${t}_sntrup_rsa512 PROPERTIES
			ENVIRONMENT "DSSH_TEST_KEX=sntrup;DSSH_TEST_KEY=rsa512;${DSSH_TEST_KEY_ENV}")
		add_test(NAME ${prefix}_${t}_mlkem
			COMMAND ${executable} --exact ${t})
		set_tests_properties(${prefix}_${t}_mlkem PROPERTIES
			ENVIRONMENT "DSSH_TEST_KEX=mlkem;${DSSH_TEST_KEY_ENV}")
		add_test(NAME ${prefix}_${t}_mlkem_rsa
			COMMAND ${executable} --exact ${t})
		set_tests_properties(${prefix}_${t}_mlkem_rsa PROPERTIES
			ENVIRONMENT "DSSH_TEST_KEX=mlkem;DSSH_TEST_KEY=rsa;${DSSH_TEST_KEY_ENV}")
		add_test(NAME ${prefix}_${t}_mlkem_rsa512
			COMMAND ${executable} --exact ${t})
		set_tests_properties(${prefix}_${t}_mlkem_rsa512 PROPERTIES
			ENVIRONMENT "DSSH_TEST_KEX=mlkem;DSSH_TEST_KEY=rsa512;${DSSH_TEST_KEY_ENV}")
		add_test(NAME ${prefix}_${t}_hmac256
			COMMAND ${executable} --exact ${t})
		set_tests_properties(${prefix}_${t}_hmac256 PROPERTIES
			ENVIRONMENT "DSSH_TEST_MAC=hmac256;${DSSH_TEST_KEY_ENV}")
		add_test(NAME ${prefix}_${t}_rsa_hmac256
			COMMAND ${executable} --exact ${t})
		set_tests_properties(${prefix}_${t}_rsa_hmac256 PROPERTIES
			ENVIRONMENT "DSSH_TEST_KEY=rsa;DSSH_TEST_MAC=hmac256;${DSSH_TEST_KEY_ENV}")
		add_test(NAME ${prefix}_${t}_dhgex_hmac256
			COMMAND ${executable} --exact ${t})
		set_tests_properties(${prefix}_${t}_dhgex_hmac256 PROPERTIES
			ENVIRONMENT "DSSH_TEST_KEX=dh-gex;DSSH_TEST_MAC=hmac256;${DSSH_TEST_KEY_ENV}")
		add_test(NAME ${prefix}_${t}_sntrup_hmac256
			COMMAND ${executable} --exact ${t})
		set_tests_properties(${prefix}_${t}_sntrup_hmac256 PROPERTIES
			ENVIRONMENT "DSSH_TEST_KEX=sntrup;DSSH_TEST_MAC=hmac256;${DSSH_TEST_KEY_ENV}")
	endforeach()
endmacro()

# ================================================================
# Tier 1: Unit tests
# ================================================================

dssh_add_test(chan test_chan.c)
add_test(NAME dssh_unit_chan COMMAND dssh_test_chan)

dssh_add_test(crypto test_crypto.c)
add_test(NAME dssh_unit_crypto COMMAND dssh_test_crypto)
dssh_add_test(sntrup test_sntrup.c)
foreach(mode IN ITEMS native generic)
	dssh_add_test(sntrup_arithmetic_${mode} test_sntrup_arithmetic.c)
	if(mode STREQUAL "generic")
		target_compile_definitions(dssh_test_sntrup_arithmetic_${mode} PRIVATE DSSH_TEST_SNTRUP_GENERIC)
	endif()
	foreach(part IN ITEMS masks16 minmax_sort shifts64 field_reduction division_encoding kem)
		dssh_add_output_test(dssh_sntrup_arithmetic_${mode}_${part} dssh_test_sntrup_arithmetic_${mode}
			"1 tests: 1 passed, 0 failed, 0 skipped" --exact arithmetic/${part})
	endforeach()
endforeach()
dssh_add_output_test(dssh_sntrup_roundtrip dssh_test_sntrup "1 tests: 1 passed, 0 failed, 0 skipped"
	--exact sntrup/roundtrip)
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "OpenSSL")
	dssh_add_output_test(dssh_sntrup_rng_retirement dssh_test_sntrup "1 tests: 1 passed, 0 failed, 0 skipped"
		--exact sntrup/rng_retirement)
	dssh_add_output_test(dssh_sntrup_provider_errors dssh_test_sntrup "1 tests: 1 passed, 0 failed, 0 skipped"
		--exact sntrup/provider_errors)
endif()
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "Botan")
	dssh_add_test(crypto_botan_faults test_crypto_botan_faults.cpp)
	set_property(TARGET dssh_test_crypto_botan_faults PROPERTY CXX_STANDARD 20)
	set_property(TARGET dssh_test_crypto_botan_faults PROPERTY CXX_STANDARD_REQUIRED ON)
	add_test(NAME dssh_unit_crypto_botan_faults COMMAND dssh_test_crypto_botan_faults)
endif()

# Algorithm validation tests — reference helpers are backend-conditional
dssh_add_test(signature_storage test_signature_storage.c)
add_test(NAME dssh_unit_signature_storage COMMAND dssh_test_signature_storage)

dssh_add_test(kex_workspace test_kex_workspace.c)
add_test(NAME dssh_unit_kex_workspace COMMAND dssh_test_kex_workspace)

dssh_add_test(curve_storage test_curve_storage.c)
add_test(NAME dssh_unit_curve_storage COMMAND dssh_test_curve_storage)

dssh_add_test(hybrid_storage test_hybrid_storage.c)
foreach(method IN ITEMS sntrup mlkem)
	add_test(NAME dssh_unit_hybrid_storage_${method} COMMAND dssh_test_hybrid_storage)
	set_tests_properties(dssh_unit_hybrid_storage_${method} PROPERTIES
		ENVIRONMENT "DSSH_TEST_HYBRID=${method}")
endforeach()

dssh_add_test(dhgex_storage test_dhgex_storage.c)
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "Botan")
	foreach(storage IN ITEMS curve_storage hybrid_storage dhgex_storage)
		target_sources(dssh_test_${storage} PRIVATE key_context_fixture_botan.cpp)
		set_target_properties(dssh_test_${storage} PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
	endforeach()
endif()
add_test(NAME dssh_unit_dhgex_storage COMMAND dssh_test_dhgex_storage dh/)
set_tests_properties(dssh_unit_dhgex_storage PROPERTIES TIMEOUT 180)
set(fixed_dh_parts native_reuse failures retired_state parallel_sessions allocations bounds)
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "OpenSSL")
	list(APPEND fixed_dh_parts provider_failures constructor_failures)
endif()
foreach(group IN ITEMS 14 16)
	foreach(part IN LISTS fixed_dh_parts)
		add_test(NAME dssh_dh_group${group}_${part} COMMAND dssh_test_dhgex_storage --exact group${group}/${part})
		set_tests_properties(dssh_dh_group${group}_${part} PROPERTIES TIMEOUT 600)
	endforeach()
endforeach()


if(DEUCESSH_CRYPTO_BACKEND STREQUAL "OpenSSL")
	dssh_add_test(hash_provider test_hash_provider.c)
	add_test(NAME dssh_hash_provider_lifetime COMMAND dssh_test_hash_provider)
endif()

dssh_add_test(algo_enc test_algo_enc.c)
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "OpenSSL")
	target_link_libraries(dssh_test_algo_enc PRIVATE OpenSSL::Crypto)
elseif(DEUCESSH_CRYPTO_BACKEND STREQUAL "Botan")
	target_link_libraries(dssh_test_algo_enc PRIVATE PkgConfig::BOTAN3)
endif()
add_test(NAME dssh_unit_algo_enc COMMAND dssh_test_algo_enc)
foreach(part IN ITEMS module_vectors inputs registration)
	dssh_add_output_test(dssh_cipher_cbc_${part} dssh_test_algo_enc
		"1 tests: 1 passed, 0 failed, 0 skipped" --exact enc/aes128_cbc/${part})
endforeach()
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "OpenSSL")
	foreach(part IN ITEMS provider_failures module_extents)
		dssh_add_output_test(dssh_cipher_cbc_${part} dssh_test_algo_enc
			"1 tests: 1 passed, 0 failed, 0 skipped" --exact enc/aes128_cbc/${part})
	endforeach()
endif()

dssh_add_test(algo_mac test_algo_mac.c)
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "OpenSSL")
	target_link_libraries(dssh_test_algo_mac PRIVATE OpenSSL::Crypto)
elseif(DEUCESSH_CRYPTO_BACKEND STREQUAL "Botan")
	target_link_libraries(dssh_test_algo_mac PRIVATE PkgConfig::BOTAN3)
endif()
add_test(NAME dssh_unit_algo_mac COMMAND dssh_test_algo_mac)
foreach(part IN ITEMS registration_contract module_rfc4231_vectors test_module_ownership test_module_failures)
	dssh_add_output_test(dssh_mac_${part} dssh_test_algo_mac
		"1 tests: 1 passed, 0 failed, 0 skipped" --exact mac/${part})
endforeach()
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "OpenSSL")
	dssh_add_output_test(dssh_mac_native_failures dssh_test_algo_mac
		"1 tests: 1 passed, 0 failed, 0 skipped" --exact mac/native_failures)
endif()

dssh_add_test(algo_key test_algo_key.c)
foreach(result_case IN ITEMS ed25519 rsa256 rsa512 concurrent)
	add_test(NAME dssh_signature_result_${result_case}
		COMMAND dssh_test_algo_key --exact result/${result_case})
	set_tests_properties(dssh_signature_result_${result_case} PROPERTIES
		ENVIRONMENT "${DSSH_TEST_KEY_ENV}")
endforeach()
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "Botan")
	target_sources(dssh_test_algo_key PRIVATE key_context_fixture_botan.cpp)
	set_property(TARGET dssh_test_algo_key PROPERTY CXX_STANDARD 20)
	set_property(TARGET dssh_test_algo_key PROPERTY CXX_STANDARD_REQUIRED ON)
endif()
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "OpenSSL")
	target_link_libraries(dssh_test_algo_key PRIVATE OpenSSL::Crypto)
elseif(DEUCESSH_CRYPTO_BACKEND STREQUAL "Botan")
	target_link_libraries(dssh_test_algo_key PRIVATE PkgConfig::BOTAN3)
endif()
add_test(NAME dssh_unit_algo_key COMMAND dssh_test_algo_key)
dssh_add_test(rsa_cache test_rsa_cache.c)
dssh_add_test(key_generation test_key_generation.c)
dssh_add_test(key_publication test_key_publication.c)
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "Botan")
	target_sources(dssh_test_key_publication PRIVATE key_publication_cpp.cpp key_file_cpp_alloc.cpp)
	set_target_properties(dssh_test_key_publication PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
	add_test(NAME dssh_key_cpp_password_encrypted COMMAND dssh_test_key_publication --exact cpp_password_encrypted)
	add_test(NAME dssh_key_cpp_counts_full_password COMMAND dssh_test_key_publication --exact cpp_counts_full_password)
	set_tests_properties(dssh_key_cpp_password_encrypted dssh_key_cpp_counts_full_password PROPERTIES ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 300)
	foreach(part IN ITEMS generation plain encrypted)
		add_test(NAME dssh_key_cpp_counts_${part} COMMAND dssh_test_key_publication --exact cpp_counts_${part})
		set_tests_properties(dssh_key_cpp_counts_${part} PROPERTIES ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 300)
		foreach(scope IN ITEMS prefix late context)
			add_test(NAME dssh_key_cpp_${scope}_${part} COMMAND dssh_test_key_publication --exact cpp_${scope}_${part})
			set_tests_properties(dssh_key_cpp_${scope}_${part} PROPERTIES ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 1200)
		endforeach()
	endforeach()
endif()
foreach(part IN ITEMS generation plain encrypted preflight)
	add_test(NAME dssh_key_publication_${part} COMMAND dssh_test_key_publication --exact ${part})
	set_tests_properties(dssh_key_publication_${part} PROPERTIES ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 300)
endforeach()
dssh_add_test(config_setup test_config_setup.c)
dssh_add_test(native_key_pool test_native_key_pool.c)
dssh_add_test(frozen_keys test_frozen_keys.c)
add_test(NAME dssh_frozen_keys_readers COMMAND dssh_test_frozen_keys --exact readers)
set_tests_properties(dssh_frozen_keys_readers PROPERTIES ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 300 RUN_SERIAL TRUE)
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "OpenSSL")
	# The portable owner helper is a Botan production dependency. Compile the
	# same source separately for OpenSSL sanitizer ownership tests only.
	add_library(dssh_test_native_key_helper STATIC ../key_algo/native-key-pool.c)
	set_property(TARGET dssh_test_native_key_helper PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
	set_property(TARGET dssh_test_native_key_helper PROPERTY C_STANDARD_REQUIRED ON)
	target_compile_definitions(dssh_test_native_key_helper PRIVATE DSSH_TESTING DSSH_CRYPTO_OPENSSL)
	target_include_directories(dssh_test_native_key_helper PRIVATE ${PROJECT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
	target_include_directories(dssh_test_native_key_helper SYSTEM PRIVATE ${DSSH_CRYPTO_INCLUDE})
	target_compile_options(dssh_test_native_key_helper PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
	target_link_libraries(dssh_test_native_key_helper PUBLIC deucessh_test_lib)
	target_link_libraries(dssh_test_native_key_pool PRIVATE dssh_test_native_key_helper)
endif()
foreach(part IN ITEMS reuse failures retirement concurrent)
	add_test(NAME dssh_native_key_pool_${part} COMMAND dssh_test_native_key_pool --exact ${part})
	set_tests_properties(dssh_native_key_pool_${part} PROPERTIES TIMEOUT 120)
endforeach()
set_tests_properties(dssh_native_key_pool_concurrent PROPERTIES RUN_SERIAL TRUE)
foreach(part IN ITEMS allocation_failures native_failures clock_failure success callback_entry)
	add_test(NAME dssh_config_setup_${part} COMMAND dssh_test_config_setup --exact ${part})
	set_tests_properties(dssh_config_setup_${part} PROPERTIES TIMEOUT 120)
endforeach()
set(key_generation_parts invalid_sizes)
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "OpenSSL")
	list(APPEND key_generation_parts native_errors native_cancel)
endif()
foreach(part IN LISTS key_generation_parts)
	add_test(NAME dssh_key_generation_${part} COMMAND dssh_test_key_generation --exact ${part})
	set_tests_properties(dssh_key_generation_${part} PROPERTIES ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 180)
endforeach()
find_package(Python3 3.9 QUIET COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND AND UNIX AND NOT APPLE)
	# Compile the canonical application sources with GNU linker controls;
	# both variants continue to link the actual production libraries.
	foreach(kind IN ITEMS static shared)
		foreach(peer IN ITEMS event accept_callback)
			set(consumer dssh_test_${peer}_peer_${kind})
			if(NOT TARGET ${consumer})
				continue()
			endif()
			set(control ${consumer}_failures)
			get_target_property(consumer_sources ${consumer} SOURCES)
			add_executable(${control} ${consumer_sources} peer_thread_failures.c)
			set_property(TARGET ${control} PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
			set_property(TARGET ${control} PROPERTY C_STANDARD_REQUIRED ON)
			target_compile_options(${control} PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
			target_compile_definitions(${control} PRIVATE _DEFAULT_SOURCE)
			target_link_libraries(${control} PRIVATE deucessh_${kind} ${THREADS_LINK_LIB})
			if(DSSH_THREADS_SHIM_INCLUDE)
				target_include_directories(${control} BEFORE PRIVATE ${DSSH_THREADS_SHIM_INCLUDE})
			endif()
			target_link_options(${control} PRIVATE
				-Wl,--wrap=thrd_create,--wrap=thrd_join,--wrap=mock_tx_client)
			if(peer STREQUAL "event")
				set(profiles event)
			else()
				set(profiles accept nested)
			endif()
			foreach(profile IN LISTS profiles)
				set(modes plain tx)
				if(profile STREQUAL "nested")
					set(last_worker 3)
				else()
					set(last_worker 1)
				endif()
				foreach(index RANGE 0 ${last_worker})
					list(APPEND modes create-${index} join-${index}-retained join-${index}-released)
				endforeach()
				foreach(mode IN LISTS modes)
					set(name dssh_peer_ownership_${kind}_${profile}_${mode})
					add_test(NAME ${name} COMMAND ${Python3_EXECUTABLE}
						${CMAKE_CURRENT_SOURCE_DIR}/peer_thread_failures.py
						$<TARGET_FILE:${control}> ${profile} ${mode})
					set_tests_properties(${name} PROPERTIES TIMEOUT 60)
				endforeach()
			endforeach()
		endforeach()
	endforeach()
endif()
if(Python3_Interpreter_FOUND)
	dssh_add_test(key_validation test_key_validation.c)
	if(DEUCESSH_CRYPTO_BACKEND STREQUAL "OpenSSL")
		add_test(NAME dssh_key_validation_native_errors COMMAND dssh_test_key_validation --exact native_errors)
		set_tests_properties(dssh_key_validation_native_errors PROPERTIES ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 180)
	endif()
	foreach(part IN ITEMS valid invalid)
		add_test(NAME dssh_key_validation_${part} COMMAND ${Python3_EXECUTABLE}
			${CMAKE_CURRENT_SOURCE_DIR}/key_validation.py $<TARGET_FILE:dssh_test_key_validation> ${part})
		set_tests_properties(dssh_key_validation_${part} PROPERTIES ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 300)
	endforeach()
endif()
set(rsa_cache_parts number_models layout_models)
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "OpenSSL")
	list(APPEND rsa_cache_parts native_numbers public_values zero_modulus zero_exponent publication_errors)
endif()
foreach(part IN LISTS rsa_cache_parts)
	add_test(NAME dssh_rsa_cache_${part} COMMAND dssh_test_rsa_cache --exact ${part})
	set_tests_properties(dssh_rsa_cache_${part} PROPERTIES ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 180)
endforeach()
dssh_add_test(key_text test_key_text.c)
set(key_text_parts formats file_stages extent_models chunk_boundaries)
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "OpenSSL")
	list(APPEND key_text_parts encoder_reports)
endif()
foreach(part IN LISTS key_text_parts)
	add_test(NAME dssh_key_text_${part} COMMAND dssh_test_key_text --exact ${part})
	set_tests_properties(dssh_key_text_${part} PROPERTIES ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 180)
endforeach()
dssh_add_test(key_file_import test_key_file_import.c)
if(UNIX)
	target_compile_definitions(dssh_test_key_file_import PRIVATE _XOPEN_SOURCE=700)
endif()
set(key_file_import_parts callback_replacement file_length_models close_success close_failure password_errors password_binary password_full password_empty no_implicit_password)
list(APPEND key_file_import_parts stdio_control stdio_success stdio_setup_failure stdio_close_failure)
if(UNIX)
	list(APPEND key_file_import_parts stdio_native_flush stdio_native_write_zero
		stdio_native_write_partial stdio_small_buffer_control)
endif()
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "Botan")
	list(APPEND key_file_import_parts input_retirement stdio_short_read)
else()
	list(APPEND key_file_import_parts reference_failure)
endif()
foreach(part IN LISTS key_file_import_parts)
	add_test(NAME dssh_key_file_import_${part} COMMAND dssh_test_key_file_import --exact ${part})
	set_tests_properties(dssh_key_file_import_${part} PROPERTIES
		ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 180)
endforeach()
if(UNIX)
	add_executable(dssh_key_fd_exec_probe key_fd_exec_probe.c)
	set_target_properties(dssh_key_fd_exec_probe PROPERTIES C_STANDARD ${DEUCESSH_C_STANDARD} C_STANDARD_REQUIRED ON)
	target_compile_options(dssh_key_fd_exec_probe PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
	target_compile_definitions(dssh_key_fd_exec_probe PRIVATE _POSIX_C_SOURCE=200809L)
	dssh_add_test(key_save_policy test_key_save_policy.c)
	foreach(part IN ITEMS identity rejected nonblocking)
		add_test(NAME dssh_key_save_policy_${part} COMMAND dssh_test_key_save_policy --exact ${part})
		set_tests_properties(dssh_key_save_policy_${part} PROPERTIES ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 180)
	endforeach()
	if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
		foreach(part IN ITEMS acl_owner_only acl_failures acl_capability_absent acl_workspace)
			add_test(NAME dssh_key_save_policy_${part} COMMAND dssh_test_key_save_policy --exact ${part})
			set_tests_properties(dssh_key_save_policy_${part} PROPERTIES ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 180)
		endforeach()
	endif()
	if(APPLE)
		foreach(part IN ITEMS darwin_acl_owner_only darwin_acl_failures darwin_acl_workspace)
			add_test(NAME dssh_key_save_policy_${part} COMMAND dssh_test_key_save_policy --exact ${part})
			set_tests_properties(dssh_key_save_policy_${part} PROPERTIES ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 180)
		endforeach()
	endif()
	dssh_add_test(key_descriptors test_key_descriptors.c)
	target_compile_definitions(dssh_test_key_descriptors PRIVATE _POSIX_C_SOURCE=200809L
		DSSH_FD_EXEC_PROBE="$<TARGET_FILE:dssh_key_fd_exec_probe>")
	add_dependencies(dssh_test_key_descriptors dssh_key_fd_exec_probe)
	foreach(part IN ITEMS modes invalid_paths association_failure native_open_failure exec_controls
	    private_stages private_metadata helper_errno helper_metadata_errno native_controls)
		add_test(NAME dssh_key_descriptors_${part} COMMAND dssh_test_key_descriptors --exact ${part})
		set_tests_properties(dssh_key_descriptors_${part} PROPERTIES ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 180)
	endforeach()
endif()
dssh_add_test(key_wire test_key_wire.c)
foreach(part IN ITEMS known_answers ed_metadata rsa_metadata rsa_framing metadata_allocations callback_parameters bit_limits)
	add_test(NAME dssh_key_wire_${part} COMMAND dssh_test_key_wire --exact ${part})
	set_tests_properties(dssh_key_wire_${part} PROPERTIES TIMEOUT 120)
endforeach()
set_tests_properties(dssh_unit_algo_key PROPERTIES COST 20
	ENVIRONMENT "${DSSH_TEST_KEY_ENV}")
add_test(NAME dssh_targeted_dhgex_null_ka
	COMMAND dssh_test_algo_key dhgex_handler_null_ka)
add_test(NAME dssh_targeted_c25519_null_ka
	COMMAND dssh_test_algo_key c25519_handler_null_ka)
add_test(NAME dssh_targeted_sntrup761_null_ka
	COMMAND dssh_test_algo_key sntrup761_handler_null_ka)
add_test(NAME dssh_targeted_mlkem768_null_ka
	COMMAND dssh_test_algo_key mlkem768_handler_null_ka)

# Botan-specific C++ unit tests
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "Botan")
	dssh_add_test(mlkem_parity test_mlkem_parity.cpp)
	target_sources(dssh_test_mlkem_parity PRIVATE ${PROJECT_SOURCE_DIR}/kex/mlkem768.c)
	set_property(TARGET dssh_test_mlkem_parity PROPERTY CXX_STANDARD 20)
	set_property(TARGET dssh_test_mlkem_parity PROPERTY CXX_STANDARD_REQUIRED ON)
	add_test(NAME dssh_unit_mlkem_parity COMMAND dssh_test_mlkem_parity)

	add_executable(dssh_test_botan_algo_key test_botan_algo_key.cpp key_file_cpp_alloc.cpp key_file_cpp_bridge.c)
	set_property(TARGET dssh_test_botan_algo_key PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
	set_property(TARGET dssh_test_botan_algo_key PROPERTY C_STANDARD_REQUIRED ON)
	set_property(TARGET dssh_test_botan_algo_key PROPERTY CXX_STANDARD 20)
	set_property(TARGET dssh_test_botan_algo_key PROPERTY CXX_STANDARD_REQUIRED ON)
	target_include_directories(dssh_test_botan_algo_key PRIVATE
		${PROJECT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
	target_include_directories(dssh_test_botan_algo_key SYSTEM
		PRIVATE ${DSSH_CRYPTO_INCLUDE})
	target_link_libraries(dssh_test_botan_algo_key PRIVATE
		deucessh_test_lib PkgConfig::BOTAN3 ${THREADS_LINK_LIB})
	target_compile_options(dssh_test_botan_algo_key PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
	target_compile_definitions(dssh_test_botan_algo_key PRIVATE DSSH_CRYPTO_BOTAN)
	add_test(NAME dssh_unit_botan_algo_key COMMAND dssh_test_botan_algo_key)
	add_test(NAME dssh_native_key_pool_native COMMAND dssh_test_botan_algo_key --exact native_key_owners)
	set_tests_properties(dssh_native_key_pool_native PROPERTIES ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 180)
	add_test(NAME dssh_rsa_cache_native COMMAND dssh_test_botan_algo_key --exact rsa_cache_native)
	set_tests_properties(dssh_rsa_cache_native PROPERTIES ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 180)
	add_test(NAME dssh_key_text_native_reuse COMMAND dssh_test_botan_algo_key --exact key_text_reuse)
	set_tests_properties(dssh_key_text_native_reuse PROPERTIES ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 180)
	add_test(NAME dssh_key_file_import_cpp_oom COMMAND dssh_test_botan_algo_key --exact key_file_cpp_oom)
	set_tests_properties(dssh_key_file_import_cpp_oom PROPERTIES
		ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 180)
	set_tests_properties(dssh_unit_botan_algo_key PROPERTIES COST 20
		ENVIRONMENT "${DSSH_TEST_KEY_ENV}")

	add_executable(dssh_test_botan_transport test_botan_transport.cpp)
	set_property(TARGET dssh_test_botan_transport PROPERTY CXX_STANDARD 20)
	set_property(TARGET dssh_test_botan_transport PROPERTY CXX_STANDARD_REQUIRED ON)
	target_include_directories(dssh_test_botan_transport PRIVATE
		${PROJECT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
	target_include_directories(dssh_test_botan_transport SYSTEM
		PRIVATE ${DSSH_CRYPTO_INCLUDE})
	target_link_libraries(dssh_test_botan_transport PRIVATE
		deucessh_test_lib PkgConfig::BOTAN3 ${THREADS_LINK_LIB})
	target_compile_options(dssh_test_botan_transport PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
	target_compile_definitions(dssh_test_botan_transport PRIVATE DSSH_CRYPTO_BOTAN)
	add_test(NAME dssh_unit_botan_transport COMMAND dssh_test_botan_transport)
endif()

# ================================================================
# Tier 2: Layer tests (need mock I/O) — one process per variant
# ================================================================

dssh_add_test(transport test_transport.c)
dssh_add_test(kex_failure test_kex_failure.c)
target_link_libraries(dssh_test_kex_failure PRIVATE dssh_mock_io)
dssh_add_output_test(dssh_mock_io_shutdown dssh_test_kex_failure "1 tests: 1 passed, 0 failed, 0 skipped"
	--exact kex_failure/io_shutdown)
set_tests_properties(dssh_mock_io_shutdown PROPERTIES TIMEOUT 60
	FAIL_REGULAR_EXPRESSION "AddressSanitizer;ThreadSanitizer;UndefinedBehaviorSanitizer;runtime error:")
foreach(key IN ITEMS ed25519 rsa rsa512)
	foreach(part IN ITEMS control module inputs send_errors stopped)
		dssh_add_output_test(dssh_kex_failure_${part}_${key} dssh_test_kex_failure "1 tests: 1 passed, 0 failed, 0 skipped"
			--exact kex_failure/${part})
		set_tests_properties(dssh_kex_failure_${part}_${key} PROPERTIES
			ENVIRONMENT "DSSH_TEST_KEY=${key};${DSSH_TEST_KEY_ENV}"
			FIXTURES_REQUIRED dssh_cached_keys TIMEOUT 600
			FAIL_REGULAR_EXPRESSION "AddressSanitizer;ThreadSanitizer;UndefinedBehaviorSanitizer;runtime error:")
	endforeach()
endforeach()
dssh_add_test(kex_framing test_kex_framing.c)
add_test(NAME dssh_unit_kex_framing COMMAND dssh_test_kex_framing)
dssh_add_test(module_contract test_module_contract.c)
add_test(NAME dssh_unit_module_contract COMMAND dssh_test_module_contract)
foreach(part IN ITEMS receive_extents receive_length_refusal)
	dssh_add_output_test(dssh_packet_${part} dssh_test_module_contract
		"1 tests: 1 passed, 0 failed, 0 skipped" --exact packet/${part})
endforeach()
dssh_add_test(dhgex_contract test_dhgex_contract.c)
add_test(NAME dssh_unit_dhgex_contract COMMAND dssh_test_dhgex_contract)
target_link_libraries(dssh_test_transport PRIVATE dssh_mock_io dssh_mock_comp)
target_sources(dssh_test_transport PRIVATE dh_group_result_provider.c)
foreach(part IN ITEMS group_selection group_validation peer_validation mpint_validation provider_contract group_result_handshake group_result_reuse)
	dssh_add_output_test(dssh_dhgex_${part} dssh_test_transport "1 tests: 1 passed, 0 failed, 0 skipped"
		--exact release/dhgex_${part})
	set_tests_properties(dssh_dhgex_${part} PROPERTIES
		ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys)
endforeach()
dssh_add_variant_tests(dssh_transport dssh_test_transport)
foreach(part IN ITEMS local bounds storage wire handshake_rekey concurrent entry_failures)
	dssh_add_output_test(dssh_language_${part} dssh_test_transport
		"1 tests: 1 passed, 0 failed, 0 skipped" --exact language/${part})
	set_tests_properties(dssh_language_${part} PROPERTIES
		ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys TIMEOUT 180)
endforeach()
foreach(method IN ITEMS dh-gex group14 group16 sntrup mlkem)
	dssh_add_output_test(dssh_language_handshake_rekey_${method} dssh_test_transport
		"1 tests: 1 passed, 0 failed, 0 skipped" --exact language/handshake_rekey)
	set_tests_properties(dssh_language_handshake_rekey_${method} PROPERTIES
		ENVIRONMENT "${DSSH_TEST_KEY_ENV};DSSH_TEST_KEX=${method}"
		FIXTURES_REQUIRED dssh_cached_keys TIMEOUT 180)
endforeach()
foreach(key IN ITEMS ed25519 rsa512)
	dssh_add_output_test(dssh_cipher_cbc_rekey_${key} dssh_test_transport
		"1 tests: 1 passed, 0 failed, 0 skipped" --exact release/rekey_changes_algorithms)
	set_tests_properties(dssh_cipher_cbc_rekey_${key} PROPERTIES
		ENVIRONMENT "DSSH_TEST_KEY=${key};${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys
		TIMEOUT 180)
endforeach()
foreach(key IN ITEMS ed25519 rsa rsa512)
	add_test(NAME dssh_fixed_rekey_${key} COMMAND dssh_test_transport --exact release/fixed_rekey_methods)
	set_tests_properties(dssh_fixed_rekey_${key} PROPERTIES
		ENVIRONMENT "DSSH_TEST_KEY=${key};${DSSH_TEST_KEY_ENV}"
		FIXTURES_REQUIRED dssh_cached_keys TIMEOUT 180)
endforeach()

foreach(part IN ITEMS codec packet_bound offers advertisement receive_positions receive_rejections send_failure)
	add_test(NAME dssh_transport_ext_info_${part}
		COMMAND dssh_test_transport --exact ext_info/${part})
	set_tests_properties(dssh_transport_ext_info_${part} PROPERTIES
		ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys
		TIMEOUT 180)
endforeach()
foreach(part IN ITEMS notifications auth_callbacks hostkey nested demux joinable)
	dssh_add_output_test(dssh_transport_receive_entry_${part} dssh_test_transport "1 tests: 1 passed, 0 failed, 0 skipped"
		--exact receive_entry/${part})
	set_tests_properties(dssh_transport_receive_entry_${part} PROPERTIES
		ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys
		TIMEOUT 180)
endforeach()
dssh_add_output_test(dssh_transport_key_material dssh_test_transport "7 tests: 7 passed, 0 failed, 0 skipped"
	key_material/)
set_tests_properties(dssh_transport_key_material PROPERTIES
	ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys
	TIMEOUT 180)
foreach(provider IN ITEMS none test-growth zlib)
	if(provider STREQUAL "zlib" AND NOT ZLIB_FOUND)
		continue()
	endif()
	dssh_add_output_test(dssh_transport_rekey_control_${provider} dssh_test_transport "1 tests: 1 passed, 0 failed, 0 skipped"
		--exact rekey/control_traffic)
	set_tests_properties(dssh_transport_rekey_control_${provider} PROPERTIES
		ENVIRONMENT "${DSSH_TEST_KEY_ENV};DSSH_TEST_REKEY_COMP=${provider}"
		FIXTURES_REQUIRED dssh_cached_keys
		TIMEOUT 240)
	dssh_add_output_test(dssh_transport_rekey_global_pipeline_${provider} dssh_test_transport "1 tests: 1 passed, 0 failed, 0 skipped"
		--exact rekey/global_pipeline)
	set_tests_properties(dssh_transport_rekey_global_pipeline_${provider} PROPERTIES
		ENVIRONMENT "${DSSH_TEST_KEY_ENV};DSSH_TEST_REKEY_COMP=${provider}"
		FIXTURES_REQUIRED dssh_cached_keys
		TIMEOUT 240)
endforeach()

dssh_add_output_test(dssh_transport_modules_stateless dssh_test_transport "1 passed, 0 failed, 0 skipped"
	--exact modules/stateless)
set_tests_properties(dssh_transport_modules_stateless PROPERTIES
	ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys)
foreach(part IN ITEMS grammar bytes bounds setters output)
	add_test(NAME dssh_transport_identification_${part}
		COMMAND dssh_test_transport --exact identification/${part})
endforeach()
dssh_add_output_test(dssh_transport_query_snapshot dssh_test_transport "1 tests: 1 passed, 0 failed, 0 skipped"
	--exact release/query_snapshot)
set_tests_properties(dssh_transport_query_snapshot PROPERTIES TIMEOUT 120
	FAIL_REGULAR_EXPRESSION "AddressSanitizer;UndefinedBehaviorSanitizer;runtime error:;ThreadSanitizer")
dssh_add_output_test(dssh_transport_wire_trace dssh_test_transport
	"1 tests: 1 passed, 0 failed, 0 skipped" --exact transport/wire_trace)
set_tests_properties(dssh_transport_wire_trace PROPERTIES TIMEOUT 120
	ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys)
dssh_add_output_test(dssh_kex_io_arguments dssh_test_transport
	"1 tests: 1 passed, 0 failed, 0 skipped" --exact release/kex_io_arguments)
set_tests_properties(dssh_kex_io_arguments PROPERTIES TIMEOUT 120
	ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys)
foreach(part IN ITEMS expansion context_replacement auth_cleanup sensitive_failure teardown_cleanup queued_rekey scratch_failures replay_cleanup callbacks newkeys_framing mac_before_decode zlib_bounds gather_slots rekey_reuse transform_failures provider_changes setup_failures registration zlib zlib_allocations)
	add_test(NAME dssh_transport_compression_${part}
		COMMAND dssh_test_transport --exact compression/${part})
	set_tests_properties(dssh_transport_compression_${part} PROPERTIES
		ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys)
endforeach()

dssh_add_test(auth test_auth.c)
dssh_add_output_test(dssh_auth_setup_ownership dssh_test_auth
	"1 tests: 1 passed, 0 failed, 0 skipped" --exact release/auth_setup_ownership)
set_tests_properties(dssh_auth_setup_ownership PROPERTIES TIMEOUT 120
	ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys)
dssh_add_output_test(dssh_auth_nested_setup_ownership dssh_test_auth
	"1 tests: 1 passed, 0 failed, 0 skipped" --exact release/auth_nested_setup_ownership)
set_tests_properties(dssh_auth_nested_setup_ownership PROPERTIES TIMEOUT 120
	ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys)
dssh_add_output_test(dssh_auth_fixture_builder dssh_test_auth
	"1 tests: 1 passed, 0 failed, 0 skipped" --exact release/auth_fixture_builder)
dssh_add_output_test(dssh_auth_direct_fixture_status dssh_test_auth
	"1 tests: 1 passed, 0 failed, 0 skipped" --exact release/auth_direct_fixture_status)
set_tests_properties(dssh_auth_direct_fixture_status PROPERTIES
	ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys TIMEOUT 120)
add_test(NAME dssh_auth_request_capacity
	COMMAND dssh_test_auth --exact release/request_capacity)
target_link_libraries(dssh_test_auth PRIVATE dssh_mock_io dssh_mock_comp)
target_sources(dssh_test_auth PRIVATE password_result_provider.c kbi_result_provider.c signature_result_provider.c)
set(AUTH_TESTS
	callbacks/banner_transaction callbacks/output_pairs callbacks/password_lifetime callbacks/password_result callbacks/signature_result callbacks/kbi_client_result callbacks/kbi_server_result
	callbacks/kbi_lifetime callbacks/client_cleanup callbacks/results callbacks/reply_failures
	framing/client_results framing/client_text framing/client_kbi framing/server_requests
	framing/server_config_update
	parse/prefix_valid parse/prefix_empty
	parse/prefix_no_service parse/prefix_trunc_service
	parse/prefix_trunc_username parse/prefix_no_method
	parse/prefix_trunc_method
	auth/password/success auth/password/failure
	auth/password/wrong_user auth/password/partial
	auth/password/empty auth/password/long
	auth/server/none_accept auth/server/none_reject
	auth/server/password_accept auth/server/password_reject
	auth/server/publickey_accept auth/server/publickey_reject
	auth/server/no_callbacks auth/server/username_captured
	auth/roundtrip/password auth/roundtrip/password_reject
	auth/roundtrip/publickey auth/roundtrip/get_methods
	auth/roundtrip/kbi auth/roundtrip/multiple_attempts
	auth/banner_delivered auth/banner_no_lang
	auth/server/password_change auth/server/publickey_probe
	auth/server/unknown_method auth/server/unexpected_message
	auth/kbi/zero_prompts auth/kbi/failure_response
	auth/kbi/callback_abort auth/kbi/empty_response
	auth/kbi/unexpected_message auth/kbi/banner_before_info
	auth/kbi/truncated_name_header auth/kbi/truncated_name_data
	auth/kbi/truncated_instr_header auth/kbi/truncated_instr_data
	auth/kbi/truncated_lang_header auth/kbi/truncated_lang_data
	auth/kbi/truncated_num_prompts
	auth/kbi/truncated_prompt_header auth/kbi/truncated_prompt_data
	auth/banner_truncated
	auth/get_methods_none_accepted
	auth/get_methods_fail_trunc auth/get_methods_fail_len
	auth/get_methods_fail_ctrl auth/get_methods_unexpected
	auth/get_methods_del_char auth/get_methods_small_buf
	auth/get_methods_zero_buf
	auth/server/parse_empty auth/server/parse_long_username
	auth/server/parse_no_method auth/server/parse_no_service
	auth/server/parse_not_svc_req
	auth/server/parse_trunc_method auth/server/parse_trunc_service
	auth/server/parse_trunc_user
	auth/server/parse_pw_no_bool auth/server/parse_pw_no_pass
	auth/server/parse_pw_trunc_pw
	auth/server/parse_pw_chg_no_new auth/server/parse_pw_chg_trunc
	auth/server/parse_pk_no_algo auth/server/parse_pk_no_blob
	auth/server/parse_pk_no_has_sig auth/server/parse_pk_no_sig
	auth/server/short_svc_req auth/server/tiny_svc_req
	auth/server/method_4_not_none
	auth/server/method_8_not_password
	auth/server/method_9_not_publickey
	auth/server/kbi_roundtrip
	auth/server/kbi_failure
	auth/server/kbi_multi_round
	auth/server/banner
	auth/server/set_banner_null
	auth/server/kbi_bad_response
	auth/server/kbi_trunc_response
	auth/server/kbi_trunc_lang
	auth/server/kbi_no_callback
	auth/server/kbi_with_banner
	auth/server/no_password_cb auth/server/no_publickey_cb
	auth/server/pk_probe_rejected auth/server/pk_unknown_algo
	auth/server/pk_verify_bad_sig
	auth/server/pk_sig_truncated
	auth/server/pk_sig_trunc_algo auth/server/pk_sig_trunc_blob
	auth/server/pw_change_no_cb auth/server/pw_change_rejected
	auth/server/changepw_null_prompt
	auth/server/changepw_null_prompt_chg
	auth/server/long_algo_name
	auth/server/null_username_out
	auth/server/small_username_buffer
	auth/server_send_fail/svc_accept
	auth/server_send_fail/none_success auth/server_send_fail/none_failure
	auth/server_send_fail/pw_success auth/server_send_fail/pw_failure
	auth/server_send_fail/pw_no_cb auth/server_send_fail/pw_changereq
	auth/server_send_fail/pk_success auth/server_send_fail/pk_ok
	auth/server_send_fail/pk_no_cb auth/server_send_fail/pk_unknown
	auth/server_send_fail/pk_bad_sig auth/server_send_fail/pk_reject_sig
	auth/server_send_fail/pk_probe_rej
	auth/server_send_fail/unknown_meth
	auth/server_send_fail/kbi_success auth/server_send_fail/kbi_failure
	auth/server_send_fail/kbi_info_req auth/server_send_fail/kbi_no_cb
	auth/server_send_fail/chg_success auth/server_send_fail/chg_failure
	auth/server_send_fail/chg_changereq
	auth/pw_changereq_no_cb auth/pw_changereq_loop
	auth/pw_changereq_no_lang
	auth/pw_changereq_trunc_prompt auth/pw_changereq_trunc_lang
	auth/pw_changereq_trunc_lang_data auth/pw_changereq_trunc_data
	auth/pw_unexpected_msg
	auth/service_accept_unexpected
	auth/client/svc_req_send_fail auth/client/pw_changereq_cb_error
	auth/client/pw_changereq_send_fail
	auth/client/pk_no_key auth/client/pk_pubkey_fail
	auth/client/pk_sign_fail auth/client/pk_send_fail
	auth/client/pk_recv_fail auth/client/pk_banner
	auth/client/get_methods_send_fail
	auth/client/kbi_send_fail auth/client/kbi_recv_fail
	direct/wrong_first_msg direct/short_svc_request
	direct/svc_slen_overflow direct/bad_prefix_in_loop
	direct/long_username direct/null_username_out_len
	direct/pw_no_bool direct/pw_no_pw_len direct/pw_overflow
	direct/pw_change_no_new direct/pw_change_overflow
	direct/pk_no_algo_len direct/pk_algo_overflow
	direct/pk_no_hassig direct/pk_no_pk_len direct/pk_pk_overflow
	direct/pk_sig_no_sig_len direct/pk_sig_overflow
	direct/pk_sig_unknown_algo
	direct/pk_verify_alloc
	dclient/wrong_svc_reply dclient/get_methods_unexpected
	dclient/get_methods_trunc_payload
	dclient/get_methods_ctrl_char dclient/get_methods_del
	dclient/changereq_no_cb dclient/changereq_trunc
	dclient/changereq_no_lang
	dclient/changereq_prompt_overflow
	dclient/changereq_lang_overflow
	dclient/get_methods_multi_banner
	dclient/changereq_cb_error
	dclient/pk_no_sign dclient/pk_alloc_fail
	dclient/kbi_alloc_fail dclient/kbi_calloc_chain
	dclient/kbi_resp_alloc
	auth/server/password_disconnect
	auth/server/none_disconnect
	auth/server/pk_probe_disconnect
	auth/server/pk_verify_disconnect
	auth/server/kbi_disconnect
	auth/server/passwd_change_disconnect
	direct/kbi_wrong_resp_type direct/kbi_resp_parse_error
	dclient/pk_no_key
	dclient/pk_banner_in_response dclient/pk_banner_parse_error
	dclient/kbi_resp_overflow dclient/kbi_resp_size_overflow
	direct/kbi_trunc_lang_hdr direct/kbi_trunc_lang_data
	direct/kbi_trunc_submethods direct/kbi_trunc_submethods_data
	auth/server/kbi_trunc_lang_hdr auth/server/kbi_trunc_submethods
	auth/server/kbi_resp_alloc auth/server/kbi_trunc_resp_body
	auth/server/kbi_excess_responses auth/client/kbi_too_many_prompts
)
dssh_add_individual_tests(dssh_test_auth dssh_auth AUTH_TESTS)

dssh_add_test(conn test_conn.c)
foreach(part IN ITEMS admission resize)
	dssh_add_output_test(dssh_conn_tx_slot_${part} dssh_test_conn
		"1 tests: 1 passed, 0 failed, 0 skipped" --exact release/tx_slot_${part})
	set_tests_properties(dssh_conn_tx_slot_${part} PROPERTIES TIMEOUT 120
		ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys)
endforeach()
foreach(kind IN ITEMS key size)
	dssh_add_output_test(dssh_conn_tx_slot_refusal_${kind} dssh_test_conn
		"1 tests: 1 passed, 0 failed, 0 skipped" --exact release/tx_slot_refusal)
	set_tests_properties(dssh_conn_tx_slot_refusal_${kind} PROPERTIES TIMEOUT 120
		ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys)
endforeach()
set_property(TEST dssh_conn_tx_slot_refusal_size APPEND PROPERTY ENVIRONMENT "DSSH_TEST_COMPRESSION=test-growth")
foreach(part IN ITEMS threshold inflight simultaneous failure)
	dssh_add_output_test(dssh_conn_transmit_rekey_${part} dssh_test_conn
		"1 tests: 1 passed, 0 failed, 0 skipped" --exact release/transmit_rekey_${part})
	set_tests_properties(dssh_conn_transmit_rekey_${part} PROPERTIES TIMEOUT 120
		ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys)
endforeach()
foreach(method IN ITEMS dh-gex group14 group16 sntrup mlkem)
	dssh_add_output_test(dssh_conn_transmit_rekey_threshold_${method} dssh_test_conn
		"1 tests: 1 passed, 0 failed, 0 skipped" --exact release/transmit_rekey_threshold)
	set_tests_properties(dssh_conn_transmit_rekey_threshold_${method} PROPERTIES TIMEOUT 120
		ENVIRONMENT "${DSSH_TEST_KEY_ENV};DSSH_TEST_KEX=${method}" FIXTURES_REQUIRED dssh_cached_keys)
endforeach()
dssh_add_output_test(dssh_conn_transmit_rekey_inflight_growth dssh_test_conn
	"1 tests: 1 passed, 0 failed, 0 skipped" --exact release/transmit_rekey_inflight)
set_tests_properties(dssh_conn_transmit_rekey_inflight_growth PROPERTIES TIMEOUT 120
	ENVIRONMENT "${DSSH_TEST_KEY_ENV};DSSH_TEST_COMPRESSION=test-growth" FIXTURES_REQUIRED dssh_cached_keys)
foreach(part IN ITEMS lifetime late_reply backpressure)
	dssh_add_output_test(dssh_conn_channel_id_${part} dssh_test_conn
		"1 tests: 1 passed, 0 failed, 0 skipped" --exact release/channel_id_${part})
	set_tests_properties(dssh_conn_channel_id_${part} PROPERTIES TIMEOUT 120
		ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys)
endforeach()
foreach(part IN ITEMS queued popped confirmed late_confirmation concurrent_accept ordered_terminal)
	dssh_add_output_test(dssh_conn_peer_id_${part} dssh_test_conn
		"1 tests: 1 passed, 0 failed, 0 skipped" --exact release/peer_id_${part})
	set_tests_properties(dssh_conn_peer_id_${part} PROPERTIES TIMEOUT 120
		ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys)
endforeach()
foreach(part IN ITEMS direct queued buffered)
	dssh_add_output_test(dssh_conn_post_close_${part} dssh_test_conn
		"1 tests: 1 passed, 0 failed, 0 skipped" --exact release/post_close_${part})
	set_tests_properties(dssh_conn_post_close_${part} PROPERTIES TIMEOUT 120
		ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys)
endforeach()
dssh_add_output_test(dssh_conn_post_close_capacity dssh_test_conn
	"1 tests: 1 passed, 0 failed, 0 skipped" --exact release/post_close_direct)
set_tests_properties(dssh_conn_post_close_capacity PROPERTIES TIMEOUT 120
	ENVIRONMENT "${DSSH_TEST_KEY_ENV};DSSH_TEST_COMPRESSION=test-growth" FIXTURES_REQUIRED dssh_cached_keys)
dssh_add_output_test(dssh_conn_channel_worker_ownership dssh_test_conn
	"1 tests: 1 passed, 0 failed, 0 skipped" --exact release/channel_worker_ownership)
set_tests_properties(dssh_conn_channel_worker_ownership PROPERTIES TIMEOUT 120
	ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys)
foreach(part IN ITEMS setup no_start)
	dssh_add_output_test(dssh_conn_${part}_ownership dssh_test_conn
		"1 tests: 1 passed, 0 failed, 0 skipped" --exact release/conn_${part}_ownership)
	set_tests_properties(dssh_conn_${part}_ownership PROPERTIES TIMEOUT 120
		ENVIRONMENT "${DSSH_TEST_KEY_ENV}" FIXTURES_REQUIRED dssh_cached_keys)
endforeach()
target_link_libraries(dssh_test_conn PRIVATE dssh_mock_io dssh_mock_comp)

# Exercise actual auth/channel fixtures with external compression. Exact-test
# output is required so a skipped setup cannot be credited as a passing case.
foreach(provider IN ITEMS test-growth zlib)
	if(provider STREQUAL "zlib" AND NOT ZLIB_FOUND)
		continue()
	endif()
	set(compressed_auth_cases
		callbacks/password_lifetime callbacks/password_result callbacks/signature_result callbacks/kbi_client_result callbacks/kbi_server_result callbacks/kbi_lifetime callbacks/client_cleanup
		callbacks/results callbacks/reply_failures framing/server_requests
		framing/client_kbi auth/roundtrip/password auth/roundtrip/kbi
		auth/server/password_change)
	set(compressed_conn_cases
		queue_retry/packet_size_refusal queue_retry/gather_size_partial
		queue_retry/packet_concurrent_key queue_retry/gather_concurrent_size
		queue_retry/packet_channel_key_partial queue_retry/gather_key_probe_write
		queue_retry/packet_key_rekey queue_retry/gather_size_rekey
		window_credit/reverse_packet_0_stream_full window_credit/reverse_gather_0_stream_full
		window_credit/reverse_packet_1_zc_full window_credit/reverse_gather_1_zc_full
		window_credit/packet_0_stream_full window_credit/gather_0_stream_full
		window_credit/packet_1_zc_full window_credit/gather_1_zc_full
		test_session_write_read test_session_read_write_reverse test_session_large_write
		test_subsys_large_write test_concurrent_write_read test_replenish_queued_accounting
		zc/open_client zc/cancel data/extended_zc_types control/unknown_replies
		lifecycle/receive_callback)
	foreach(layer IN ITEMS auth conn)
		foreach(case IN LISTS compressed_${layer}_cases)
			string(REPLACE "/" "_" case_name "${case}")
			set(test_name "dssh_${layer}_compression_${provider}_${case_name}")
			dssh_add_output_test("${test_name}" dssh_test_${layer} "1 tests: 1 passed, 0 failed, 0 skipped"
				--exact "${case}")
			set_tests_properties("${test_name}" PROPERTIES
				ENVIRONMENT "${DSSH_TEST_KEY_ENV};DSSH_TEST_COMPRESSION=${provider}"
				FIXTURES_REQUIRED dssh_cached_keys)
		endforeach()
	endforeach()
endforeach()
dssh_add_output_test(dssh_conn_compression_test-growth_window_rekey dssh_test_conn "1 tests: 1 passed, 0 failed, 0 skipped"
	--exact compression/window_rekey)
set_tests_properties(dssh_conn_compression_test-growth_window_rekey PROPERTIES
	ENVIRONMENT "${DSSH_TEST_KEY_ENV};DSSH_TEST_COMPRESSION=test-growth"
	FIXTURES_REQUIRED dssh_cached_keys
	TIMEOUT 60)
set(CONN_TESTS
	queue_retry/packet_stream_callback queue_retry/gather_stream_callback
	queue_retry/packet_ordinary queue_retry/packet_key_refusal queue_retry/packet_size_refusal queue_retry/packet_key_partial queue_retry/packet_size_partial queue_retry/packet_phase_pause queue_retry/packet_concurrent_key queue_retry/packet_channel_key_partial queue_retry/packet_window_size queue_retry/packet_concurrent_size queue_retry/packet_key_rekey queue_retry/packet_size_rekey queue_retry/packet_key_probe_send queue_retry/packet_key_probe_write queue_retry/packet_key_probe_slot queue_retry/packet_key_probe_rekey queue_retry/packet_size_probe_send queue_retry/packet_size_probe_write queue_retry/packet_size_probe_slot queue_retry/packet_size_probe_rekey queue_retry/gather_ordinary queue_retry/gather_key_refusal queue_retry/gather_size_refusal queue_retry/gather_key_partial queue_retry/gather_size_partial queue_retry/gather_phase_pause queue_retry/gather_concurrent_key queue_retry/gather_channel_key_partial queue_retry/gather_window_size queue_retry/gather_concurrent_size queue_retry/gather_key_rekey queue_retry/gather_size_rekey queue_retry/gather_key_probe_send queue_retry/gather_key_probe_write queue_retry/gather_key_probe_slot queue_retry/gather_key_probe_rekey queue_retry/gather_size_probe_send queue_retry/gather_size_probe_write queue_retry/gather_size_probe_slot queue_retry/gather_size_probe_rekey
	control_frame/wire_normal_window control_frame/wire_normal_eof control_frame/wire_normal_close control_frame/wire_normal_success control_frame/wire_normal_failure control_frame/wire_setup_window control_frame/wire_setup_eof control_frame/wire_setup_close control_frame/wire_setup_success control_frame/wire_setup_failure control_frame/wire_pending_success control_frame/wire_pending_failure
	control_frame/stream_normal_window control_frame/stream_normal_eof control_frame/stream_normal_close control_frame/stream_normal_success control_frame/stream_normal_failure control_frame/stream_normal_valid control_frame/stream_setup_window control_frame/stream_setup_eof control_frame/stream_setup_close control_frame/stream_setup_success control_frame/stream_setup_failure control_frame/stream_setup_valid control_frame/zc_normal_window control_frame/zc_normal_eof control_frame/zc_normal_close control_frame/zc_normal_success control_frame/zc_normal_failure control_frame/zc_normal_valid control_frame/zc_setup_window control_frame/zc_setup_eof control_frame/zc_setup_close control_frame/zc_setup_success control_frame/zc_setup_failure control_frame/zc_setup_valid control_frame/unknown control_frame/stale
	window_credit/arithmetic window_credit/atomic
	window_credit/packet_0_stream_small window_credit/packet_0_stream_full window_credit/packet_0_zc_small window_credit/packet_0_zc_full window_credit/packet_0_cancel window_credit/packet_0_oversize window_credit/packet_0_key_limit window_credit/packet_0_io_failure window_credit/packet_1_stream_small window_credit/packet_1_stream_full window_credit/packet_1_zc_small window_credit/packet_1_zc_full window_credit/packet_1_cancel window_credit/packet_1_oversize window_credit/packet_1_key_limit window_credit/packet_1_io_failure window_credit/gather_0_stream_small window_credit/gather_0_stream_full window_credit/gather_0_zc_small window_credit/gather_0_zc_full window_credit/gather_0_cancel window_credit/gather_0_oversize window_credit/gather_0_key_limit window_credit/gather_0_io_failure window_credit/gather_1_stream_small window_credit/gather_1_stream_full window_credit/gather_1_zc_small window_credit/gather_1_zc_full window_credit/gather_1_cancel window_credit/gather_1_oversize window_credit/gather_1_key_limit window_credit/gather_1_io_failure window_credit/reverse_packet_0_stream_small window_credit/reverse_packet_0_stream_full window_credit/reverse_packet_0_zc_small window_credit/reverse_packet_0_zc_full window_credit/reverse_packet_0_cancel window_credit/reverse_packet_0_oversize window_credit/reverse_packet_0_key_limit window_credit/reverse_packet_0_io_failure window_credit/reverse_packet_1_stream_small window_credit/reverse_packet_1_stream_full window_credit/reverse_packet_1_zc_small window_credit/reverse_packet_1_zc_full window_credit/reverse_packet_1_cancel window_credit/reverse_packet_1_oversize window_credit/reverse_packet_1_key_limit window_credit/reverse_packet_1_io_failure window_credit/reverse_gather_0_stream_small window_credit/reverse_gather_0_stream_full window_credit/reverse_gather_0_zc_small window_credit/reverse_gather_0_zc_full window_credit/reverse_gather_0_cancel window_credit/reverse_gather_0_oversize window_credit/reverse_gather_0_key_limit window_credit/reverse_gather_0_io_failure window_credit/reverse_gather_1_stream_small window_credit/reverse_gather_1_stream_full window_credit/reverse_gather_1_zc_small window_credit/reverse_gather_1_zc_full window_credit/reverse_gather_1_cancel window_credit/reverse_gather_1_oversize window_credit/reverse_gather_1_key_limit window_credit/reverse_gather_1_io_failure
	accept_callback/publish_before_return accept_callback/terminate_deferred accept_callback/stop_deferred accept_callback/cleanup_deferred
	accept_callback/pty_silent_positive accept_callback/pty_silent_negative accept_callback/pty_reply_positive accept_callback/pty_reply_negative accept_callback/env_silent_positive accept_callback/env_silent_negative accept_callback/env_reply_positive accept_callback/env_reply_negative accept_callback/shell_silent_positive accept_callback/shell_silent_negative accept_callback/shell_reply_positive accept_callback/shell_reply_negative accept_callback/exec_silent_positive accept_callback/exec_silent_negative accept_callback/exec_reply_positive accept_callback/exec_reply_negative accept_callback/subsystem_silent_positive accept_callback/subsystem_silent_negative accept_callback/subsystem_reply_positive accept_callback/subsystem_reply_negative accept_callback/pty_request_only accept_callback/env_request_only
	test_assertion_cleanup
	test_session_start test_session_stop test_session_start_stop
	test_session_stop_open_channel
	lifecycle/join_once lifecycle/demux_callback lifecycle/receive_callback
	lifecycle/recursive_callbacks lifecycle/tx_reservation
	clock/deadline clock/poll_accept clock/pending_waits clock/receive
	data/extended_stream_types data/extended_zc_types data/framing
	data/replenish_sync control/unknown_replies
	test_open_exec test_open_exec_command test_open_exec_rejected
	test_open_shell test_open_subsystem
	open/before_start open/type_and_queue_policy open/response_state
	open/failure_roundtrip open/sync_failures
	io/validation io/request_response_state io/sync_failures io/tx_sync_sweep
	io/registration_failures
	test_session_write_read test_session_read_write_reverse
	test_session_write_ext test_session_read_ext
	test_session_poll_read test_session_poll_timeout
	test_session_large_write test_session_multiple_writes
	test_subsys_write_read test_subsys_multiple_writes
	test_subsys_poll test_subsys_large_write
	test_send_signal test_signal_after_data test_window_change
	test_session_close_exit_code test_channel_close_subsys
	test_eof_detection test_eof_half_close test_read_nomore_vs_eof
	test_graceful_disconnect
	test_two_channels test_accept_reject test_channel_independence
	test_concurrent_write_read test_terminate_during_io
	test_connection_drop_during_read test_connection_drop_during_write
	test_cleanup_after_drop
	test_session_start_twice test_accept_timeout_zero
	test_accept_timeout_short test_session_poll_timeout_zero
	test_auto_reject_x11 test_auto_reject_forwarded_tcpip
	test_auto_reject_direct_tcpip test_auto_reject_session_server
	test_window_adjust_from_peer test_data_after_eof
	test_truncated_channel_data test_ext_data_after_eof
	test_truncated_ext_data test_channel_request_want_reply
	test_data_exceeds_window
	test_session_poll_write test_session_write_after_eof
	test_session_write_ext_after_eof test_subsys_write_after_close
	test_subsys_poll_write test_subsys_poll_timeout_zero
	test_read_event_empty test_signal_interleave_read
	test_signal_interleave_read_ext test_truncated_channel_open
	test_truncated_channel_request test_demux_short_payload
	test_session_poll_read_empty test_session_write_window_zero
	test_session_write_ext_window_zero test_accept_timeout_negative
	test_setup_exec_rejected_by_callback test_truncated_open_confirmation
	test_open_conf_unknown_channel test_channel_success_no_request
	test_double_eof_close test_data_dlen_exceeds_payload
	test_demux_chan_type_zero test_send_eof_already_sent
	test_send_close_already_sent test_replenish_after_eof
	test_replenish_low_window test_replenish_queued_accounting
	test_replenish_reserves_outstanding
	test_zc_consumption_clamped test_window_underflow_to_zero
	test_window_add_overflow
	test_chan_write_not_open test_chan_write_close_recv
	test_subsystem_roundtrip test_accept_zc test_close_during_zc_callback
	test_dispatch_sync_failures test_detach_sync_failures
	test_session_poll_nsec_overflow test_accept_nsec_overflow
	test_demux_data_truncation test_replenish_caps_buf_space
	rx_truncation/default rx_truncation/clips_to_window
	rx_bypass/pre_setup rx_bypass/disengages_post_setup
	early_data/type_lock_subsystem
	poll/terminate_surfaces_data poll/terminate_no_event_bit
	null/chan_read null/chan_write null/chan_poll null/chan_close
	null/chan_send_signal null/chan_send_window_change
	alloc/open_exec_sweep alloc/open_shell_sweep
	alloc/open_subsystem_sweep alloc/server_accept_sweep
	subsys/write_zero
	test_data_after_close test_ext_data_after_close
	test_replenish_after_close test_truncated_window_adjust
	test_poll_deadline_not_reset
	chanreq/parse_valid chanreq/parse_empty_type chanreq/parse_no_data
	chanreq/parse_truncated_type_len chanreq/parse_truncated_type
	chanreq/parse_truncated_want_reply
	zc/open_client zc/cancel null/zc_open
	event/overflow_request_notification event/overflow_eof_notification event/overflow_close_notification event/overflow_request_close_failure event/overflow_eof_close_failure event/overflow_close_close_failure event/overflow_request_normal event/overflow_eof_normal event/overflow_close_normal
	framing/name_byte_and_boolean
	framing/setup_short_length framing/setup_short_name framing/setup_short_reply framing/setup_empty framing/setup_nonascii framing/setup_zero framing/setup_comma framing/setup_long framing/normal_short_length framing/normal_short_name framing/normal_short_reply framing/normal_empty framing/normal_nonascii framing/normal_zero framing/normal_comma framing/normal_long framing/break_short framing/break_trailer framing/shell_reply framing/shell_no_reply framing/setup_unknown framing/normal_unknown framing/event_lengths_stream framing/event_lengths_zc
	params/stream_sync params/zc_sync
	params/stream_validation params/zc_validation
	params/stream_snapshot params/stream_term params/stream_command params/stream_subsystem params/stream_modes params/stream_env_array params/stream_env_name1 params/stream_env_value1 params/stream_env_name2 params/stream_env_value2 params/zc_snapshot params/zc_term params/zc_command params/zc_subsystem params/zc_modes params/zc_env_array params/zc_env_name1 params/zc_env_value1 params/zc_env_name2 params/zc_env_value2
	accept_failure/notify_failure accept_failure/success_send_failure accept_failure/window_send_failure
	accept_failure/close_deadline
	accept_failure/channel_storage accept_failure/event_storage accept_failure/param_storage accept_failure/stream_first accept_failure/stream_second accept_failure/exec_reject accept_failure/exec_no_reply accept_failure/peer_close accept_failure/shell_reject accept_failure/subsystem_reject accept_failure/buf_init accept_failure/cb_init accept_failure/cnd_init accept_failure/slot_first accept_failure/slot_second accept_failure/stream_first_no_reply accept_failure/stream_second_no_reply
	setup/confirmation_cleanup
	setup/mailbox_no_allocation setup/gap_disable setup/gap_detach setup/gap_terminate setup/gap_reacquire
	setup/mailbox_reuse setup/mailbox_growth setup/mailbox_rollback setup/mailbox_bound
	setup/terminal_storage setup/terminal_first_failure setup/terminal_second_failure
	event/text_poll_reuse
	event/text_free_observer event/text_growth_unlocked event/text_poll_race
	event/text_binary_callback event/text_binary_poll event/text_empty_callback event/text_empty_poll event/text_packet_boundary
	event/delivery_atomic_state
	event/delivery_self_disable
	event/delivery_client_defaults event/delivery_lengths event/delivery_positions event/delivery_reacquire
	event/delivery_acquire event/delivery_queue_allocation event/delivery_malformed event/delivery_close_race
	event/delivery_peer_stream event/delivery_peer_zc event/delivery_stress event/delivery_switch event/delivery_replacement event/delivery_lifecycle
	event/session_set_cb event/session_set_cb_toolate event/chan_set_cb
	event/session_set_max event/session_set_max_toolate event/chan_set_max
	pty/get_pty env/roundtrip env/callback_rejection
)
dssh_add_individual_tests(dssh_test_conn dssh_conn CONN_TESTS)
get_property(queue_retry_tests DIRECTORY PROPERTY TESTS)
foreach(case IN LISTS queue_retry_tests)
	if(case MATCHES "^dssh_conn_queue_retry/")
		set_property(TEST "${case}" APPEND PROPERTY ENVIRONMENT "DSSH_TEST_COMPRESSION=test-growth")
	endif()
endforeach()


# Actual SIGABRT checks run in a fresh exec, with no inherited library workers.
if(UNIX)
	add_executable(dssh_test_fatal_driver test_fatal_driver.c)
	set_property(TARGET dssh_test_fatal_driver PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
	set_property(TARGET dssh_test_fatal_driver PROPERTY C_STANDARD_REQUIRED ON)
	target_compile_definitions(dssh_test_fatal_driver PRIVATE _POSIX_C_SOURCE=200809L)
	target_compile_options(dssh_test_fatal_driver PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
	foreach(operation IN ITEMS open exec shell subsystem accept)
		foreach(mode IN ITEMS retained released)
			set(name dssh_channel_worker_fatal_${operation}_${mode})
			dssh_add_output_test(${name} dssh_test_fatal_driver "channel_join_fatal=1"
				$<TARGET_FILE:dssh_test_conn> --channel-fatal ${operation} ${mode})
			set_tests_properties(${name} PROPERTIES FIXTURES_REQUIRED dssh_cached_keys
				ENVIRONMENT "${DSSH_TEST_KEY_ENV}" TIMEOUT 120)
		endforeach()
	endforeach()
	foreach(operation IN ITEMS stop cleanup)
		add_test(NAME dssh_lifecycle_fatal_${operation}
			COMMAND dssh_test_fatal_driver $<TARGET_FILE:dssh_test_conn> ${operation})
		set_tests_properties(dssh_lifecycle_fatal_${operation} PROPERTIES
			FIXTURES_REQUIRED dssh_cached_keys ENVIRONMENT "${DSSH_TEST_KEY_ENV}"
			TIMEOUT 60)
	endforeach()
endif()

# ================================================================
# Tier 1b: Alloc failure tests (need mock allocator + mock I/O)
# ossl_iterate tests are OpenSSL-only (guarded with #ifdef in source)
# The process-wide allocator injection requires the GNU --wrap linker
# option, so these tests are not available with Apple's Mach-O linker.
# ================================================================

if(NOT APPLE)
dssh_add_test(alloc test_alloc.c)
target_link_libraries(dssh_test_alloc PRIVATE dssh_mock_io dssh_mock_alloc)
target_link_options(dssh_test_alloc PRIVATE ${DSSH_WRAP_FLAGS})
add_test(NAME dssh_unit_alloc COMMAND dssh_test_alloc)
set_tests_properties(dssh_unit_alloc PROPERTIES
	ENVIRONMENT "${DSSH_TEST_KEY_ENV}")
add_test(NAME dssh_unit_alloc_dhgex COMMAND dssh_test_alloc)
set_tests_properties(dssh_unit_alloc_dhgex PROPERTIES
	ENVIRONMENT "DSSH_TEST_KEX=dh-gex;${DSSH_TEST_KEY_ENV}")
add_test(NAME dssh_unit_alloc_rsa COMMAND dssh_test_alloc)
set_tests_properties(dssh_unit_alloc_rsa PROPERTIES
	ENVIRONMENT "DSSH_TEST_KEY=rsa;${DSSH_TEST_KEY_ENV}")
add_test(NAME dssh_unit_alloc_dhgex_rsa COMMAND dssh_test_alloc)
set_tests_properties(dssh_unit_alloc_dhgex_rsa PROPERTIES
	ENVIRONMENT "DSSH_TEST_KEX=dh-gex;DSSH_TEST_KEY=rsa;${DSSH_TEST_KEY_ENV}")

add_test(NAME dssh_unit_alloc_sntrup COMMAND dssh_test_alloc)
set_tests_properties(dssh_unit_alloc_sntrup PROPERTIES COST 6
	ENVIRONMENT "DSSH_TEST_KEX=sntrup;${DSSH_TEST_KEY_ENV}")
add_test(NAME dssh_unit_alloc_sntrup_rsa COMMAND dssh_test_alloc)
set_tests_properties(dssh_unit_alloc_sntrup_rsa PROPERTIES COST 7
	ENVIRONMENT "DSSH_TEST_KEX=sntrup;DSSH_TEST_KEY=rsa;${DSSH_TEST_KEY_ENV}")

add_test(NAME dssh_unit_alloc_mlkem COMMAND dssh_test_alloc)
set_tests_properties(dssh_unit_alloc_mlkem PROPERTIES
	ENVIRONMENT "DSSH_TEST_KEX=mlkem;${DSSH_TEST_KEY_ENV}")
add_test(NAME dssh_unit_alloc_mlkem_rsa COMMAND dssh_test_alloc)
set_tests_properties(dssh_unit_alloc_mlkem_rsa PROPERTIES
	ENVIRONMENT "DSSH_TEST_KEX=mlkem;DSSH_TEST_KEY=rsa;${DSSH_TEST_KEY_ENV}")

add_test(NAME dssh_unit_alloc_rsa512 COMMAND dssh_test_alloc)
set_tests_properties(dssh_unit_alloc_rsa512 PROPERTIES
	ENVIRONMENT "DSSH_TEST_KEY=rsa512;${DSSH_TEST_KEY_ENV}")
add_test(NAME dssh_unit_alloc_dhgex_rsa512 COMMAND dssh_test_alloc)
set_tests_properties(dssh_unit_alloc_dhgex_rsa512 PROPERTIES
	ENVIRONMENT "DSSH_TEST_KEX=dh-gex;DSSH_TEST_KEY=rsa512;${DSSH_TEST_KEY_ENV}")

# Targeted coverage tests — run in their own process for clean state
add_test(NAME dssh_targeted_c25519_server_trunc
	COMMAND dssh_test_alloc c25519/server_truncated_init)
set_tests_properties(dssh_targeted_c25519_server_trunc PROPERTIES
	ENVIRONMENT "${DSSH_TEST_KEY_ENV}")
add_test(NAME dssh_targeted_c25519_client_bad_qs
	COMMAND dssh_test_alloc c25519/client_bad_qs_length)
set_tests_properties(dssh_targeted_c25519_client_bad_qs PROPERTIES
	ENVIRONMENT "${DSSH_TEST_KEY_ENV}")
if(DEUCESSH_CRYPTO_BACKEND STREQUAL "OpenSSL")
add_test(NAME dssh_targeted_dhgex_bn_rand_fail
	COMMAND dssh_test_alloc dhgex/server_bn_rand_fail)
set_tests_properties(dssh_targeted_dhgex_bn_rand_fail PROPERTIES
	ENVIRONMENT "DSSH_TEST_KEX=dh-gex;${DSSH_TEST_KEY_ENV}")
endif()
endif()

# ================================================================
# Test algorithm modules (enc/mac with failure injection)
# ================================================================

add_library(dssh_test_algos STATIC test_enc.c test_mac.c)
set_property(TARGET dssh_test_algos PROPERTY C_STANDARD ${DEUCESSH_C_STANDARD})
set_property(TARGET dssh_test_algos PROPERTY C_STANDARD_REQUIRED ON)
target_include_directories(dssh_test_algos PUBLIC
	${PROJECT_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(dssh_test_algos PRIVATE deucessh_test_lib)
target_link_libraries(dssh_test_algo_mac PRIVATE dssh_test_algos)

# ================================================================
# Tier 2b: Transport error tests (need test enc/mac + mock I/O)
# ================================================================

dssh_add_test(transport_errors test_transport_errors.c)
target_link_libraries(dssh_test_transport_errors PRIVATE
	dssh_mock_io dssh_test_algos)
set(TRANSPORT_ERROR_TESTS
	test_modules/roundtrip
	send/encrypt_error send/mac_error send/mac_overflow_rejected
	send/sensitive_success send/sensitive_gather_success
	send/sensitive_encrypt_error send/sensitive_too_long
	send/channel_slot_drain_fatal send/channel_slot_gather_fatal
	recv/decrypt_error_first_block recv/decrypt_error_remaining
	recv/mac_generate_error recv/mac_mismatch recv/mac_too_large
	newkeys/enc_init_failure newkeys/mac_init_failure
)
foreach(t ${TRANSPORT_ERROR_TESTS})
	add_test(NAME dssh_transport_errors_${t}
		COMMAND dssh_test_transport_errors ${t})
	set_tests_properties(dssh_transport_errors_${t} PROPERTIES
		ENVIRONMENT "${DSSH_TEST_KEY_ENV}")
endforeach()
set_tests_properties(
	dssh_transport_errors_send/channel_slot_drain_fatal
	dssh_transport_errors_send/channel_slot_gather_fatal
	PROPERTIES TIMEOUT 15)

# ================================================================
# Tier 2c: Thread error tests (lock/unlock/condvar failure injection)
# ================================================================

dssh_add_test(thread_errors test_thread_errors.c)
target_link_libraries(dssh_test_thread_errors PRIVATE dssh_mock_io)
dssh_add_variant_tests(dssh_thrd dssh_test_thread_errors)
set(WAIT_CONTRACT_TESTS thrd/wait_contract_errors thrd/wait_contract_spurious
	thrd/wait_contract_timeout_errors thrd/wait_contract_timeouts)
dssh_add_individual_tests(dssh_test_thread_errors dssh_wait WAIT_CONTRACT_TESTS)
if(UNIX)
	foreach(path IN ITEMS primitive event limit eof close log-queue log-empty log-data wa-idle wa-zero wa-send)
		foreach(mode IN ITEMS held released)
			add_test(NAME dssh_unlock_fatal_${path}_${mode}
				COMMAND dssh_test_fatal_driver $<TARGET_FILE:dssh_test_thread_errors>
					--unlock-fatal ${path} ${mode})
			set_tests_properties(dssh_unlock_fatal_${path}_${mode} PROPERTIES
				FIXTURES_REQUIRED dssh_cached_keys ENVIRONMENT "${DSSH_TEST_KEY_ENV}"
				TIMEOUT 60)
		endforeach()
	endforeach()
	foreach(path IN ITEMS lock-tx lock-slot lock-accept lock-registry lock-channel
		notify-tx notify-slot notify-accept notify-channel retry-notify)
		foreach(mode IN ITEMS before after)
			add_test(NAME dssh_wake_fatal_${path}_${mode}
				COMMAND dssh_test_fatal_driver $<TARGET_FILE:dssh_test_thread_errors>
					--wake-fatal ${path} ${mode})
			set_tests_properties(dssh_wake_fatal_${path}_${mode} PROPERTIES TIMEOUT 30)
		endforeach()
	endforeach()
endif()

# ================================================================
# Tier 3a: Self-test (integration) — one process per case and variant
# ================================================================

dssh_add_test(selftest test_selftest.c)
target_link_libraries(dssh_test_selftest PRIVATE dssh_mock_comp)
foreach(provider IN ITEMS test-growth zlib)
	if(provider STREQUAL "zlib" AND NOT ZLIB_FOUND)
		continue()
	endif()
	foreach(case IN ITEMS test_self_rekey_during_data test_self_rekey_manual
		test_self_rekey_preserves_channels test_self_rekey_inflight_data
		test_self_window_adjust_race)
		set(test_name "dssh_self_compression_${provider}_${case}")
		dssh_add_output_test("${test_name}" dssh_test_selftest "1 tests: 1 passed, 0 failed, 0 skipped"
			--exact "${case}")
		set_tests_properties("${test_name}" PROPERTIES
			ENVIRONMENT "${DSSH_TEST_KEY_ENV};DSSH_TEST_COMPRESSION=${provider}"
			FIXTURES_REQUIRED dssh_cached_keys)
	endforeach()
endforeach()
set(SELFTEST_TESTS
	test_assertion_cleanup
	test_self_handshake_curve25519
	test_self_auth_password
	test_self_exec_echo
	test_self_window_adjust_race
	test_self_exec_exit_code
	test_self_shell_echo
	test_self_shell_large_data
	test_self_signal
	test_self_window_change
	test_self_multiple_channels
	test_self_graceful_disconnect
	test_self_eof_half_close
	test_self_rekey_during_data
	test_self_rekey_manual
	test_self_rekey_preserves_channels
	test_self_rekey_inflight_data
	test_self_connection_drop
	test_null_session_api
	test_log_api
	test_set_timeout
	test_set_terminate_cb
	test_open_channel_timeout
	test_setup_recv_timeout
	test_rekey_send_timeout
	test_self_chan_exec_echo
	test_self_chan_shell_pty
	test_self_chan_accept_exec
	test_self_chan_accept_shell_pty
	test_self_chan_event_exit_status
	test_self_chan_read_peek
	test_self_chan_shutwr_then_close
	test_self_chan_close_exit_code
	test_self_chan_close_no_exit_code
	test_self_chan_send_break
	test_self_chan_getters_after_accept
	test_self_chan_accept_env_reject
	test_self_io_callback_contract
)
dssh_add_individual_tests(dssh_test_selftest dssh_self SELFTEST_TESTS)
foreach(group IN ITEMS 14 16)
	foreach(case IN LISTS SELFTEST_TESTS)
		add_test(NAME dssh_fixed_group${group}_${case} COMMAND dssh_test_selftest --exact ${case})
		set_tests_properties(dssh_fixed_group${group}_${case} PROPERTIES
			ENVIRONMENT "DSSH_TEST_KEX=group${group};${DSSH_TEST_KEY_ENV}"
			FIXTURES_REQUIRED dssh_cached_keys TIMEOUT 300)
	endforeach()
	add_test(NAME dssh_fixed_group${group}_transport COMMAND dssh_test_transport)
	set_tests_properties(dssh_fixed_group${group}_transport PROPERTIES
		ENVIRONMENT "DSSH_TEST_KEX=group${group};${DSSH_TEST_KEY_ENV}"
		FIXTURES_REQUIRED dssh_cached_keys TIMEOUT 900)
endforeach()


# ================================================================
# Tier 3b: Asymmetric MAC negotiation (fork-based, separate registries)
# ================================================================

dssh_add_test(asymmetric_mac test_asymmetric_mac.c)
dssh_add_output_test(dssh_asymmetric_mac dssh_test_asymmetric_mac
	"4 tests: 4 passed, 0 failed, 0 skipped")
set_tests_properties(dssh_asymmetric_mac PROPERTIES TIMEOUT 60)

# ================================================================
# Tier 3c/3d: Optional interop tests
# ================================================================

if(DEUCESSH_TEST_OPENSSH)
	if(NOT UNIX)
		message(FATAL_ERROR "OpenSSH stdio fixtures currently require POSIX process/I/O support")
	endif()
	find_package(Python3 3.9 REQUIRED COMPONENTS Interpreter)
	find_program(DSSH_OPENSSH_EXECUTABLE NAMES ssh REQUIRED)
	find_program(DSSH_OPENSSH_DAEMON NAMES sshd PATHS /usr/sbin /usr/local/sbin REQUIRED)
	find_program(DSSH_OPENSSH_KEYGEN NAMES ssh-keygen REQUIRED)
	foreach(form IN ITEMS static shared)
		if(TARGET deucessh_${form})
			# Deliberately link the production target, without DSSH_TESTING,
			# private headers, allocator hooks or replacement algorithms.
			add_executable(dssh_openssh_${form} openssh_peer.c)
			target_compile_definitions(dssh_openssh_${form} PRIVATE _POSIX_C_SOURCE=200809L)
			set_property(TARGET dssh_openssh_${form} PROPERTY C_STANDARD 17)
			set_property(TARGET dssh_openssh_${form} PROPERTY C_STANDARD_REQUIRED ON)
			target_compile_options(dssh_openssh_${form} PRIVATE ${DEUCESSH_COMPILE_OPTIONS})
			target_link_libraries(dssh_openssh_${form} PRIVATE deucessh_${form})
			foreach(method IN ITEMS curve25519-sha256 diffie-hellman-group-exchange-sha256
					sntrup761x25519-sha512 mlkem768x25519-sha256
					diffie-hellman-group14-sha256 diffie-hellman-group16-sha512)
				foreach(role IN ITEMS client server)
					set(interop_name dssh_openssh_${form}_${role}_${method})
					add_test(NAME ${interop_name} COMMAND ${Python3_EXECUTABLE}
						${CMAKE_CURRENT_SOURCE_DIR}/openssh_interop.py run
						--peer $<TARGET_FILE:dssh_openssh_${form}> --role ${role} --algorithm ${method}
						--ssh ${DSSH_OPENSSH_EXECUTABLE} --sshd ${DSSH_OPENSSH_DAEMON}
						--keygen ${DSSH_OPENSSH_KEYGEN}
						--evidence ${CMAKE_CURRENT_BINARY_DIR}/openssh-evidence/${interop_name})
					set_tests_properties(${interop_name} PROPERTIES TIMEOUT 210 LABELS openssh)
				endforeach()
			endforeach()
			set(cbc_name dssh_openssh_${form}_client_aes128-cbc)
			foreach(role IN ITEMS client server)
				set(mac_name dssh_openssh_${form}_${role}_hmac-sha2-512)
				add_test(NAME ${mac_name} COMMAND ${Python3_EXECUTABLE}
					${CMAKE_CURRENT_SOURCE_DIR}/openssh_interop.py run
					--peer $<TARGET_FILE:dssh_openssh_${form}> --role ${role} --algorithm curve25519-sha256
					--ssh ${DSSH_OPENSSH_EXECUTABLE} --sshd ${DSSH_OPENSSH_DAEMON}
					--keygen ${DSSH_OPENSSH_KEYGEN}
					--evidence ${CMAKE_CURRENT_BINARY_DIR}/openssh-evidence/${mac_name})
				set_tests_properties(${mac_name} PROPERTIES TIMEOUT 210 LABELS openssh
					ENVIRONMENT "DSSH_TEST_MAC=hmac-sha2-512")
			endforeach()
			foreach(role IN ITEMS client server)
				set(language_name dssh_openssh_${form}_${role}_languages)
				add_test(NAME ${language_name} COMMAND ${Python3_EXECUTABLE}
					${CMAKE_CURRENT_SOURCE_DIR}/openssh_interop.py run
					--peer $<TARGET_FILE:dssh_openssh_${form}> --role ${role} --algorithm curve25519-sha256
					--ssh ${DSSH_OPENSSH_EXECUTABLE} --sshd ${DSSH_OPENSSH_DAEMON}
					--keygen ${DSSH_OPENSSH_KEYGEN}
					--evidence ${CMAKE_CURRENT_BINARY_DIR}/openssh-evidence/${language_name})
				set_tests_properties(${language_name} PROPERTIES TIMEOUT 210 LABELS openssh
					ENVIRONMENT "DSSH_TEST_LANGUAGE_FIELDS=1")
			endforeach()
			add_test(NAME ${cbc_name} COMMAND ${Python3_EXECUTABLE}
				${CMAKE_CURRENT_SOURCE_DIR}/openssh_interop.py run
				--peer $<TARGET_FILE:dssh_openssh_${form}> --role client --algorithm curve25519-sha256
				--ssh ${DSSH_OPENSSH_EXECUTABLE} --sshd ${DSSH_OPENSSH_DAEMON}
				--keygen ${DSSH_OPENSSH_KEYGEN}
				--evidence ${CMAKE_CURRENT_BINARY_DIR}/openssh-evidence/${cbc_name})
			set_tests_properties(${cbc_name} PROPERTIES TIMEOUT 210 LABELS openssh
				ENVIRONMENT "DSSH_TEST_ENC=aes128-cbc")
			set(reject_name dssh_openssh_${form}_reject_host)
			add_test(NAME ${reject_name} COMMAND ${Python3_EXECUTABLE}
				${CMAKE_CURRENT_SOURCE_DIR}/openssh_interop.py run
				--peer $<TARGET_FILE:dssh_openssh_${form}> --role client --algorithm curve25519-sha256
				--ssh ${DSSH_OPENSSH_EXECUTABLE} --sshd ${DSSH_OPENSSH_DAEMON}
				--keygen ${DSSH_OPENSSH_KEYGEN} --negative-host
				--evidence ${CMAKE_CURRENT_BINARY_DIR}/openssh-evidence/${reject_name})
			set_tests_properties(${reject_name} PROPERTIES TIMEOUT 210 LABELS openssh)
		endif()
	endforeach()
endif()

if(DEUCESSH_TEST_SYNCHRONET)
	dssh_add_test(synchronet test_synchronet.c)
	add_test(NAME dssh_integration_synchronet COMMAND dssh_test_synchronet)
endif()

# Include consumers registered by either helper and the standalone unit tests.
get_property(dssh_registered_tests DIRECTORY PROPERTY TESTS)
foreach(test_name IN LISTS dssh_registered_tests)
	get_test_property("${test_name}" ENVIRONMENT test_environment)
	if(NOT test_name STREQUAL "dssh_test_keys"
			AND "${test_environment}" MATCHES "DSSH_TEST_RSA_KEY=")
		set_tests_properties("${test_name}" PROPERTIES
			FIXTURES_REQUIRED dssh_cached_keys)
	endif()
endforeach()
