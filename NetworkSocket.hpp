// https://github.com/dualword/demo-nmap
#pragma once
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <cerrno>

class NetworkSocket {
public:
    static std::string probe_port(const std::string& ip, int port, int timeout_ms) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return "";

        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
            close(sock);
            return "";
        }
        int res = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        if (res < 0 && errno != EINPROGRESS) {
            close(sock);
            return "";
        }

        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sock, &write_fds);

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        res = select(sock + 1, nullptr, &write_fds, nullptr, &tv);
        if (res <= 0 || !FD_ISSET(sock, &write_fds)) {
            close(sock);
            return "";
        }

        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error != 0) {
            close(sock);
            return "";
        }
        fcntl(sock, F_SETFL, flags);
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

        char buffer[1024];
        std::memset(buffer, 0, sizeof(buffer));
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            std::string response(buffer, bytes);
            if (response.find("SSH-") == 0 || response.find("SSH/") != std::string::npos) {
                close(sock);
                while (!response.empty() && (response.back() == '\n' || response.back() == '\r')) {
                    response.pop_back();
                }
                return response;
            }
            close(sock);
            return "Open (Passive Banner: " + response.substr(0, 20) + ")";
        }

        std::string probe = "GET / HTTP/1.1\r\nHost: " + ip + "\r\nUser-Agent: github.com/dualword/demo-nmap/1.0\r\nConnection: close\r\n\r\n";
        send(sock, probe.c_str(), probe.length(), 0);
        std::memset(buffer, 0, sizeof(buffer));
        bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        close(sock);
        if (bytes > 0) {
            std::string response(buffer, bytes);
            if (response.find("HTTP/") != std::string::npos) {
                size_t server_pos = response.find("Server: ");
                if (server_pos != std::string::npos) {
                    size_t end_pos = response.find("\r\n", server_pos);
                    if (end_pos != std::string::npos) {
                        return response.substr(server_pos + 8, end_pos - (server_pos + 8));
                    }
                }
                return "HTTP Protocol";
            }
            return "Open (Unknown Service)";
        }
        return "Open (Silent)";
    }
};
