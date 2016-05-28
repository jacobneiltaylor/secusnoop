
#include <string>
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>


#include <asio.hpp>

#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_internal.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/base64.h>
#include <mbedtls/debug.h>

#ifndef TN_SECUSNOOP
#define TN_SECUSNOOP

int mbed_asio_tcp_send(void*, const unsigned char*, size_t);
int mbed_asio_tcp_recv(void*, unsigned char*, size_t);

#endif