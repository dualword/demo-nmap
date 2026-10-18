// https://github.com/dualword/demo-nmap
#pragma once
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include "NetworkSocket.hpp"
#include <iostream>

struct ScanResult {
    int port;
    std::string banner;
};

class ScannerEngine {
private:
    std::string target_ip;
    std::vector<int> ports;
    int th_count;
    int timeout;
    std::vector<ScanResult> open_ports;
    std::mutex mutex1;
    std::atomic<size_t> processed_ports{0};

public:
    ScannerEngine(std::string ip, std::vector<int> port_list, int threads, int timeout)
        : target_ip(std::move(ip)), ports(std::move(port_list)), th_count(threads), timeout(timeout) {}

    std::vector<ScanResult> run() {
        std::vector<std::thread> workers;
        std::atomic<size_t> index{0};
        std::mutex mutex2;

        auto draw_progress_bar = [this, &mutex2](size_t current) {
            std::lock_guard<std::mutex> lock(mutex2);
            float progress = static_cast<float>(current) / ports.size();
            int bar_width = 40;
            int pos = static_cast<int>(bar_width * progress);
            std::cout << "\rScanning Ports [";
            for (int i = 0; i < bar_width; ++i) {
                if (i < pos) std::cout << "=";
                else if (i == pos) std::cout << ">";
                else std::cout << " ";
            }
            std::cout << "] " << int(progress * 100.0) << "%" << std::flush;
        };
        draw_progress_bar(0);

        for (int i = 0; i < th_count; ++i) {
            workers.emplace_back([this, &index, &draw_progress_bar]() {
                while (true) {
                    size_t idx = index.fetch_add(1);
                    if (idx >= ports.size()) break;

                    int port = ports[idx];
                    std::string service = NetworkSocket::probe_port(target_ip, port, timeout);
                    if (!service.empty()) {
                        std::lock_guard<std::mutex> lock(mutex1);
                        open_ports.push_back({port, service});
                    }
                    size_t current = ++processed_ports;
                    if (current % 10 == 0 || current == ports.size()) {
                        draw_progress_bar(current);
                    }
                }
            });
        }

        for (auto& worker : workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        workers.clear();
        std::cout << std::endl;
        return open_ports;
    }
};
