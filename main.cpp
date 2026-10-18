// https://github.com/dualword/demo-nmap
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <chrono>
#include <netdb.h>
#include <arpa/inet.h>
#include <CLI/CLI.hpp>
#include "ScannerEngine.hpp"

std::string resolve_host(const std::string& host) {
    hostent* hostname = gethostbyname(host.c_str());
    if (!hostname) return "";
    return inet_ntoa(*(in_addr*)hostname->h_addr_list[0]);
}

int main(int argc, char** argv) {
    CLI::App app{"Multithreaded Network Port Scanner"};

    std::string target;
    std::string port_range_str = "1-1024";
    int threads = 64;
    int timeout = 750;

    app.add_option("-t,--target", target, "Target Hostname or IP Address")->required();
    app.add_option("-p,--ports", port_range_str, "Port ranges (e.g., 80,443 or 1-1024)")->capture_default_str();
    app.add_option("-j,--threads", threads, "Number of execution threads")->check(CLI::Range(1, 512))->capture_default_str();
    app.add_option("--timeout", timeout, "Socket validation connection timeout in ms")->capture_default_str();

    CLI11_PARSE(app, argc, argv);

    std::string ip = resolve_host(target);
    if (ip.empty()) {
        std::cerr << "[-] Error: Failed to resolve hostname: " << target << "\n";
        return 1;
    }

    std::vector<int> ports;
    size_t dash_pos = port_range_str.find('-');
    if (dash_pos != std::string::npos) {
        int start = std::stoi(port_range_str.substr(0, dash_pos));
        int end = std::stoi(port_range_str.substr(dash_pos + 1));
        for (int p = start; p <= end; ++p) ports.push_back(p);
    } else {
        ports.push_back(std::stoi(port_range_str));
    }

    std::cout << "[*] Target Host: " << target << " (" << ip << ")" << std::endl;
    std::cout << "[*] Total Ports: " << ports.size() << " | Concurrency: " << threads << " Workers\n\n";

    auto start_time = std::chrono::high_resolution_clock::now();
    ScannerEngine engine(ip, ports, threads, timeout);
    auto discovered = engine.run();
    auto end_time = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> elapsed = end_time - start_time;
    std::cout << "\n\n[+] Scan Complete in " << std::fixed << std::setprecision(2) << elapsed.count() << " seconds.\n\n";
    std::cout << std::left << std::setw(12) << "PORT" << std::setw(15) << "STATE" << "SERVICE/BANNER\n";
    std::cout << std::string(50, '-') << "\n";

    if (discovered.empty()) {
        std::cout << "No open HTTP or public interfaces discovered on specified port ranges.\n";
    } else {
        for (const auto& record : discovered) {
            std::cout << std::left << std::setw(12) << (std::to_string(record.port) + "/tcp")
            << std::setw(15) << "open"
            << record.banner << "\n";
        }
    }
    std::cout << std::endl;
    return 0;
}
