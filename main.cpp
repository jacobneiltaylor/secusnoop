#include "secusnoop.h"

using asio::ip::tcp;
using namespace std::chrono_literals;

#define HOSTNAME "github.com"
#define DEV_PERSONAL_DATA "9xth8rnLkhfpGRyQcsKL32asda2396"

int main()
{
	try
	{
		// Initialise socket connection
		asio::io_service io_service;

		tcp::resolver resolver(io_service);

		tcp::resolver::query query(HOSTNAME, "https");

		tcp::resolver::iterator endpoints = resolver.resolve(query);

		tcp::socket* socket = new tcp::socket(io_service);

		// Initialise TLS context
		mbedtls_entropy_context entropy;
		mbedtls_ctr_drbg_context ctr_drbg;
		mbedtls_ssl_context* ssl = new mbedtls_ssl_context;
		mbedtls_ssl_config conf;
		mbedtls_x509_crt cacert;

		mbedtls_ssl_init(ssl);
		mbedtls_ssl_config_init(&conf);
		mbedtls_x509_crt_init(&cacert);
		mbedtls_ctr_drbg_init(&ctr_drbg);

		// Seeding RNG
		mbedtls_entropy_init(&entropy);
		mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)DEV_PERSONAL_DATA, strlen(DEV_PERSONAL_DATA));

		// Load trust anchors
		mbedtls_x509_crt_parse_file(&cacert, "ca-bundle.crt");
		mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);

		// Configure context and assign BIOs
		mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
		mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

		mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);

		mbedtls_ssl_setup(ssl, &conf);
		mbedtls_ssl_set_hostname(ssl, HOSTNAME);
		mbedtls_ssl_set_bio(ssl, socket, mbed_asio_tcp_send, mbed_asio_tcp_recv, NULL);

		// Connect to remote host
		asio::connect(*socket, endpoints);

		// Perform TLS handshake
		bool done = false;

		while (!done)
		{
			int status = mbedtls_ssl_handshake_step(ssl);

			if (status == 0)
			{
				if (ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER)
				{
					done = true;
				}
			}
			else if (status != MBEDTLS_ERR_SSL_WANT_READ && status != MBEDTLS_ERR_SSL_WANT_WRITE)
			{
				std::string message = "TLS handshake failed - ";

				char errbuf[255];

				mbedtls_strerror(status, errbuf, 255);
				message.append(errbuf);

				throw std::runtime_error(message);
			}
		}

		// Verify server certificate
		size_t verify = mbedtls_ssl_get_verify_result(ssl);
		std::string cipher_suite = mbedtls_ssl_get_ciphersuite_name(ssl->session->ciphersuite);
		std::string trusted = "Yes";

		if (verify != 0)
		{
			trusted = "No";
		}

		// Wait
		/*auto start = std::chrono::high_resolution_clock::now();
		std::this_thread::sleep_for(5s);
		auto end = std::chrono::high_resolution_clock::now();*/

		// Send HEAD request
		std::string request = "HEAD / HTTP/1.1\r\nHost: ";
		request += HOSTNAME;
		request += "\r\nAccept: */* \r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:46.0) Gecko/20100101 Firefox/46.0\r\nConnection: close\r\n\r\n";

		done = false;
		size_t msg_bytes = request.length();
		size_t sent_bytes = 0;

		while (!done)
		{
			int status = mbedtls_ssl_write(ssl, ((const unsigned char*)request.c_str()), request.length());
			
			if (sent_bytes + status >= msg_bytes)
			{
				done = true;
			}
			else if (status < 0 && (status != MBEDTLS_ERR_SSL_WANT_READ || status != MBEDTLS_ERR_SSL_WANT_WRITE))
			{
				std::string message = "Sending data over TLS failed - ";

				char errbuf[255];

				mbedtls_strerror(status, errbuf, 255);
				message.append(errbuf);

				throw std::runtime_error(message);
			}
			else
			{
				sent_bytes += status;
			}
		}

		// Recieve response
		std::string response = "";
		size_t read_bytes = 0;
		unsigned char buf[1024];

		done = false;

		while (!done)
		{
			int status = mbedtls_ssl_read(ssl, buf, 1023);

			if ((status == 0 && read_bytes > 0) || status == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
			{
				done = true;
			}
			else if (status < 0 && (status != MBEDTLS_ERR_SSL_WANT_READ))
			{
				std::string message = "Recieving data over TLS failed - ";

				char errbuf[255];

				mbedtls_strerror(status, errbuf, 255);
				message.append(errbuf);

				throw std::runtime_error(message);
			}
			else
			{
				read_bytes += status;
				buf[status] = '\0';
				response.append((char*)buf);
			}
		}

		if (socket->is_open())
		{
			socket->close();
		}

		mbedtls_x509_crt_free(&cacert);
		mbedtls_ssl_free(ssl);
		mbedtls_ssl_config_free(&conf);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		mbedtls_entropy_free(&entropy);

		std::cout 
			<< "================================" << "\n"
			<< " |                            | " << "\n"
			<< " | Secusnoop Proof of Concept | " << "\n"
			<< " |   HTTPS Auditing Software  | " << "\n"
			<< " |                            | " << "\n"
			<< "================================" << "\n\n"
			<< "> Tested server: " << HOSTNAME << "\n"
			<< "> Negotiated ciphersuite: " << cipher_suite << "\n"
			<< "> Certificate trusted: " << trusted << "\n\n"
			<< "   --- HTTP headers below ---" << "\n\n"
			<< response << "\n";
	}
	catch(const std::runtime_error &e)
	{
		std::cout << e.what() << "\n";
	}

	system("PAUSE");

    return 0;
}

