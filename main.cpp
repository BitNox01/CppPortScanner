// TCP Port Scanner in C++ with Banner Grabbing, Color Output, and Logging
// Author: BitNox

#include <iostream>
#include <fstream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <vector>
#include <mutex>
#include <chrono>
#include <atomic>
#include <string>
#include <ctime>

#pragma comment(lib, "ws2_32.lib")

std::mutex cout_mutex;
std::mutex log_mutex;
std::ofstream log_file;

// color codes
#define GREEN "\033[32m"
#define RED "\033[31m"
#define YELLOW "\033[33m"
#define RESET "\033[0m"

// ASCII Art
const std::string BITNOX_ASCII = R"(
  _____           _      _____                                    ______          ____  _ _   _   _         __
 |  __ \         | |    / ____|                                  / /  _ \        |  _ \(_) | | \ | |        \ \
 | |__) |__  _ __| |_  | (___   ___ __ _ _ __  _ __   ___ _ __  | || |_) |_   _  | |_) |_| |_|  \| | _____  _| |
 |  ___/ _ \| '__| __|  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__| | ||  _ <| | | | |  _ <| | __| . ` |/ _ \ \/ / |
 | |  | (_) | |  | |_   ____) | (_| (_| | | | | | | |  __/ |    | || |_) | |_| | | |_) | | |_| |\  | (_) >  <| |
 |_|   \___/|_|   \__| |_____/ \___\__,_|_| |_|_| |_|\___|_|    | ||____/ \__, | |____/|_|\__|_| \_|\___/_/\_\ |
                                                                 \_\       __/ |                            /_/
                                                                          |___/)";

// Funzione helper per timestamp stringa per log
std::string current_timestamp()
{
    std::time_t now = std::time(nullptr);
    char buf[20];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    return std::string(buf);
}

// Log thread-safe with timestamp
void log_result(const std::string &result)
{
    std::lock_guard<std::mutex> lock(log_mutex);
    if (log_file.is_open())
        log_file << "[" << current_timestamp() << "] " << result << std::endl;
}

void grab_banner(SOCKET sock)
{
    char buffer[1024];
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    int sel = select(0, &readfds, nullptr, nullptr, &timeout);
    if (sel > 0 && FD_ISSET(sock, &readfds))
    {
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0)
        {
            buffer[bytes] = '\0';
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "    Banner: " << buffer << std::endl;
            log_result("    Banner: " + std::string(buffer));
        }
    }
}

void scan_port(const std::string &ip, int port, std::atomic<int> &counter, int total)
{
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET)
        return;

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    // Timeout per connect
    timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

    int result = connect(sock, (sockaddr *)&addr, sizeof(addr));
    if (result == 0)
    {
        {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << GREEN << "[+] Port " << port << " is open" << RESET << std::endl;
            log_result("[+] Port " + std::to_string(port) + " is open");
        }
        grab_banner(sock);
    }
    else
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << RED << "[-] Port " << port << " is closed" << RESET << std::endl;
    }
    closesocket(sock);

    int current = ++counter;
    if (current % 5 == 0 || current == total)
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << YELLOW << "[*] Progress: " << current << "/" << total << " ports scanned" << RESET << std::endl;
    }
}

int main()
{
    std::string ip;
    int start_port, end_port;

    std::cout << BITNOX_ASCII << std::endl;
    std::cout << "Enter target IP: ";
    std::cin >> ip;

    // Validate IP address
    sockaddr_in sa;
    if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 1)
    {
        std::cerr << "Invalid IP address format." << std::endl;
        return 1;
    }

    std::cout << "Enter start port: ";
    while (!(std::cin >> start_port) || start_port < 1 || start_port > 65535)
    {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cout << "Invalid start port. Enter a number between 1 and 65535: ";
    }
    std::cout << "Enter end port: ";
    while (!(std::cin >> end_port) || end_port < start_port || end_port > 65535)
    {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cout << "Invalid end port. Enter a number between " << start_port << " and 65535: ";
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    // Open log file
    log_file.open("scan_results.txt", std::ios::out | std::ios::app);
    log_result("=== Scan started for IP: " + ip + " Ports: " + std::to_string(start_port) + "-" + std::to_string(end_port) + " ===");

    const int max_threads = 100;
    std::vector<std::thread> threads;
    std::atomic<int> counter{0};
    int total_ports = end_port - start_port + 1;

    for (int port = start_port; port <= end_port; ++port)
    {
        // Se superiamo max_threads, joinamo i thread finiti
        while ((int)threads.size() >= max_threads)
        {
            for (auto it = threads.begin(); it != threads.end();)
            {
                if (it->joinable())
                {
                    it->join();
                    it = threads.erase(it);
                }
                else
                {
                    ++it;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        threads.emplace_back(scan_port, ip, port, std::ref(counter), total_ports);
    }

    // Join remaining threads
    for (auto &t : threads)
    {
        if (t.joinable())
            t.join();
    }

    log_result("=== Scan finished ===");
    log_file.close();
    WSACleanup();

    return 0;
}
