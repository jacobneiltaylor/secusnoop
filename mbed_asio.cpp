#include "secusnoop.h"
#include <cmath>

using asio::ip::tcp;

int mbed_asio_tcp_send(void* socket_ptr, const unsigned char* buf, size_t len)
{
	asio::error_code error;
	size_t length = asio::write(*(tcp::socket*)socket_ptr, asio::buffer(buf, len));;
	
	if (error)
	{
		throw asio::system_error(error);
	}

	return length;
}

int mbed_asio_tcp_recv(void* socket_ptr, unsigned char* buf, size_t len)
{
	asio::error_code error;
	size_t length = asio::read(*(tcp::socket*)socket_ptr, asio::buffer(buf, len));

	if (error)
	{
		throw asio::system_error(error);
	}

	return length;
}