// TEST COMMIT
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <map>
#include <vector>
#include <algorithm>
#include <iostream>
#include <memory>
#include <cctype>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <openssl/ssl.h>
#include <openssl/err.h>
// === Cache: new headers
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

// Return current local time formatted as "yy-mm-dd hh:mm:ss"
static std::string now_local_yy_mm_dd_hh_mm_ss()
{
    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t t = system_clock::to_time_t(now);
    std::tm local_tm{};
#if defined(_WIN32)
    localtime_s(&local_tm, &t); // thread-safe on Windows
#else
    local_tm = *std::localtime(&t); // use localtime_r if available
    // Alternatively (POSIX): localtime_r(&t, &local_tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&local_tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

struct Url {
    std::string scheme; // "http" or "https"
    std::string host;   // hostname or [IPv6]
    std::string port;   // "80" / "443" / or explicit
    std::string path;   // always starts with '/', at least "/"
};

struct ChunkReadStats {
    size_t socket_bytes = 0;   // total bytes read from socket during chunked phase
    size_t body_bytes = 0;     // total bytes appended to 'acc' (payload only)
    size_t chunks = 0;         // number of chunks successfully appended
    size_t last_chunk_size = 0;
    bool eof_in_size_line = false;
    bool eof_in_chunk_data = false;
    bool missing_crlf_after_chunk = false;
};


static void to_lower_inplace(std::string &s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
}

static bool is_default_port(const Url& u) {
    if (u.scheme == "https") return (u.port == "443");
    if (u.scheme == "http")  return (u.port == "80");
    return false;
}

static bool validate_scheme(const Url& u){
    if (u.scheme == "https") return true;
    if (u.scheme == "http")  return true;
    return false;
}

// Simple URL parser supporting IPv6 literals in brackets, e.g., https://[2001:db8::1]:8443/path
static bool parse_url(const std::string& input, Url& out, std::string& error) {
    auto pos = input.find("://");
    if (pos == std::string::npos) {
        error = "Invalid URL: missing '://'";
        return false;
    }
    out.scheme = input.substr(0, pos);
    to_lower_inplace(out.scheme);

    if (!validate_scheme(out)){
        return false;
    }
    
    size_t host_start = pos + 3;
    size_t path_start = std::string::npos;
    size_t host_end   = std::string::npos;

    // IPv6 literal?
    if (host_start < input.size() && input[host_start] == '[') {
        size_t rb = input.find(']', host_start);
        if (rb == std::string::npos) {
            error = "Invalid URL: missing closing ']' for IPv6 address";
            return false;
        }
        out.host = input.substr(host_start, rb - host_start + 1); // include [ ]
        if (rb + 1 < input.size() && input[rb + 1] == ':') {
            // port after IPv6
            size_t port_begin = rb + 2;
            path_start = input.find('/', port_begin);
            if (path_start == std::string::npos) {
                out.port = input.substr(port_begin);
                out.path = "/";
                goto finalize_defaults;
            } else {
                out.port = input.substr(port_begin, path_start - port_begin);
            }
        } else {
            // no port, next '/' starts path
            path_start = input.find('/', rb + 1);
        }
        host_end = (path_start == std::string::npos) ? input.size() : path_start; // host already set
    } else {
        // IPv4 or name: host[:port][/path]
        path_start = input.find('/', host_start);
        host_end   = (path_start == std::string::npos) ? input.size() : path_start;
        size_t colon = input.find(':', host_start);
        if (colon != std::string::npos && colon < host_end) {
            out.host = input.substr(host_start, colon - host_start);
            out.port = input.substr(colon + 1, host_end - (colon + 1));
        } else {
            out.host = input.substr(host_start, host_end - host_start);
        }
    }

    if (out.host.empty()) {
        error = "Invalid URL: empty host";
        return false;
    }

    if (path_start == std::string::npos) {
        out.path = "/";
    } else {
        out.path = input.substr(path_start);
        if (out.path.empty()) out.path = "/";
    }

finalize_defaults:
    // Default port by scheme
    if (out.port.empty()) {
        if (out.scheme == "https") out.port = "443";
        else if (out.scheme == "http") out.port = "80";
        else {
            error = "Unsupported scheme: " + out.scheme;
            return false;
        }
    }

    // Validate port
    if (!std::all_of(out.port.begin(), out.port.end(), ::isdigit)) {
        error = "Invalid port: " + out.port;
        return false;
    }

    return true;
}

int main(int argc, char* argv[]) {
    bool cache_enabled = false;
    std::string url_str;
    std::string output_file;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--cache") cache_enabled = true;
	else if (a == "-o" || a == "--output") {
            if (i + 1 >= argc) {
	      std::fprintf(stdout, "-o/--output requires a filename (or - for stdout)\n");
	      std::fprintf(stdout, "Usage: %s [--cache] [-o <file|->] url\n", argv[0]);
	      return EXIT_FAILURE;
            }
            output_file = argv[++i];
        }
        else if (!a.empty() && a[0] == '-') {
            std::fprintf(stdout, "Error Unknown option: %s\n", a.c_str());
            std::fprintf(stdout, "Usage: %s [--cache] -o <file>|-> url\n", argv[0]);
            return EXIT_FAILURE;
        } else {
            url_str = a;
        }
    }
    if (url_str.empty()) {
        std::fprintf(stdout, "Usage: %s [--cache] url\n", argv[0]);
        return EXIT_FAILURE;
    }

    Url url;
    std::string error;
    if (!parse_url(url_str, url, error)) {
        std::fprintf(stdout, "ERROR URL parse error: %s\n", error.c_str());
        return EXIT_FAILURE;
    }

    std::printf("Protocol: %s, Host %s, port = %s, path = %s, ",
                url.scheme.c_str(), url.host.c_str(), url.port.c_str(), url.path.c_str());
    std::printf("Output: %s\n", output_file.c_str());

    const int max_redirects = 10;
    int redirects = 0;
    using clock = std::chrono::steady_clock;

    auto t1 = clock::now();
            std::string response;
    /* do stuff */
    while(true){
        struct addrinfo hints, *results = nullptr;
        int sockfd = -1, con = -1;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        int status = getaddrinfo(url.host.c_str(), url.port.c_str(), &hints, &results);
        if(status != 0 || results == NULL){
            std::fprintf(stdout, "ERROR: RESOLVE ISSUE\n");
            fflush(stderr);
            return EXIT_FAILURE;
        }

        for(struct addrinfo *p = results; p != NULL; p = p->ai_next){
            sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if(sockfd == -1){
                continue;
            }

            con = connect(sockfd, p->ai_addr, p->ai_addrlen);
            if(con == -1){
                close(sockfd);
                sockfd = -1;
                continue;
            }
            
            break;
        }
        freeaddrinfo(results);

        if(sockfd == -1){
            std::fprintf(stdout, "error socket failed\n");
            fflush(stderr);
            return EXIT_FAILURE;
        }
        if(con == -1){
            std::fprintf(stdout, "error CANT CONNECT TO %s\n", url.host.c_str());
            fflush(stderr);
            return EXIT_FAILURE;
        }
        printf("Connected to %s:%s successfully!\n", url.host.c_str(), url.port.c_str());


        bool use_https = (url.scheme == "https");
        SSL_CTX* ctx = nullptr;
        SSL* ssl = nullptr;
        
        if(use_https){
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_all_algorithms();

            ctx = SSL_CTX_new(TLS_client_method());
            if(!ctx){
                std::fprintf(stdout, "ERROR: CTX failed\n");
                return EXIT_FAILURE;
            }

            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, sockfd);
            if(SSL_connect(ssl) <= 0){
                std::fprintf(stdout, "ERROR: SSL connect failed\n");
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                close(sockfd);
                return EXIT_FAILURE;
            }
            std::printf("SSL connected\n");
        }

        std::ostringstream request;
        request << "GET " << url.path << " HTTP/1.1\r\n" 
        << "Host: " << url.host << "\r\n" 
        << "Connection: close\r\n" 
        << "\r\n";
        std::string request_str = request.str();

        if(use_https){
            size_t byte_sent = SSL_write(ssl, request_str.c_str(), (int)request_str.size());
            if(byte_sent < 0){
                std::fprintf(stdout, "ERROR: SSL_write failed\n");
                SSL_shutdown(ssl);
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                close(sockfd);
                return EXIT_FAILURE;
            }
            printf("Send: %zd bytes (https)\n", byte_sent);
        }
        else{
            size_t byte_sent = send(sockfd, request_str.c_str(), request_str.size(), 0);
            if(byte_sent < 0){
                perror("send");
                close(sockfd);
                return EXIT_FAILURE;
            }   
            printf("Send: %zd bytes (http)\n", byte_sent);
        }

        response.clear();
        char buf[5000];

        while(true){
            ssize_t byte_recv = 0;
            memset(&buf, 0, sizeof(buf));

            if(use_https){
                byte_recv = SSL_read(ssl, buf, sizeof(buf));
            }
            else{
                byte_recv = recv(sockfd, buf, sizeof(buf), 0);
            }

            if(byte_recv < 0){
                perror("recv");
                close(sockfd);
                return EXIT_FAILURE;
            }
            else if(byte_recv == 0){
                printf("Server Closed...\n");
                break;
            }
            response.append(buf, byte_recv);
            printf("Received %zu bytes from server.\n", response.size());
        }
        close(sockfd);

        if(response.find("HTTP/1.1 3") == 0){

            if(redirects >= max_redirects){
                std::fprintf(stdout, "error maximum amount of redirects reached\n");
                return EXIT_FAILURE;
            }

            size_t location = response.find("Location: ");
            if(location != std::string::npos){
                size_t end = response.find("\r\n", location);
                std::string new_url_str = response.substr(location + 9, end - (location + 9));

                while (!new_url_str.empty() && std::isspace((unsigned char)new_url_str.front()))
                    new_url_str.erase(0, 1);
                while (!new_url_str.empty() && std::isspace((unsigned char)new_url_str.back()))
                    new_url_str.pop_back();

                std::printf("redirecting from %s to %s\n", url_str.c_str(), new_url_str.c_str());

                redirects++;
                Url new_url;
                if (!parse_url(new_url_str, new_url, error)) {
                    std::fprintf(stdout, "ERROR URL parse error: %s\n", error.c_str());
                    return EXIT_FAILURE;
                }

                url = new_url;
                url_str = new_url_str;
                close(sockfd);
                continue;
            }
        }
        close(sockfd);
        break;
    }

    size_t header_end = response.find("\r\n\r\n");
    std::string body;
    if (header_end != std::string::npos)
        body = response.substr(header_end + 4);
    else
        body = response;

    if(output_file == "-" || output_file.empty()){
        std::cout << body;
    }
    else{
        std::ofstream out(output_file, std::ios::binary);
        if(!out){
            std::fprintf(stderr, "error: cannot open output file %s\n", output_file.c_str());
            return EXIT_FAILURE;
        }
        out.write(body.data(), body.size());
        out.close();
    }
    
    int resp_body_size=0xFACCE;
    auto t2 = clock::now();
    std::chrono::duration<double> diff = t2 - t1; // seconds
    std::cout << std::fixed << std::setprecision(6);
    std::cout << now_local_yy_mm_dd_hh_mm_ss() << " " << url_str << " " << resp_body_size << " [bytes] " << diff.count()
              << " [s] " << (8*resp_body_size/diff.count())/1e6 << " [Mbps]\n";

    return EXIT_SUCCESS;
}
