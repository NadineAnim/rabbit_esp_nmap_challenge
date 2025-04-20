#include <WiFi.h>
#include <BluetoothSerial.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include "mbedtls/sha256.h"
#include <esp_wifi.h>
#include <lwip/err.h>
#include <lwip/ip4_addr.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/tcpip.h>
#include <netif/etharp.h>
#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <deque>
#include <numeric>
#include <cmath>

#define TH_SYN 0x02
#define TH_ACK 0x10
#define TH_FIN 0x01
#define TH_PUSH 0x08
#define TH_URG 0x20

// Network configuration
const char* WIFI_SSID = "TP-Link_D06B";
const char* WIFI_PASSWORD = "123456789";
IPAddress gateway(192, 168, 0, 1);
IPAddress subnet(255, 255, 255, 0);
IPAddress dns(8, 8, 8, 8);
IPAddress newIP(192, 168, 0, 0);

BluetoothSerial SerialBT;
WebServer* server;
IPAddress currentIP;
int currentPort;

// Allowed MAC addresses
std::vector<String> allowedMacs;


// Global variable for packet change threshold
int PACKET_CHANGE_THRESHOLD = 250; // Default value

// Scan detection constants
const int SCAN_WINDOW_MS = 5000;      // Збільшуємо вікно виявлення до 5 секунд
const int RAPID_CONN_THRESHOLD = 3;    // Зменшуємо поріг для швидких підключень
const int PORT_SCAN_THRESHOLD = 2;     // Зменшуємо поріг для сканування портів
const int SYN_FLOOD_THRESHOLD = 5;     // Зменшуємо поріг для SYN-флуду
const int NULL_SCAN_THRESHOLD = 2;     // Зменшуємо поріг для NULL-сканування


// Include necessary libraries
#include <set>

// Declare a new WebServer instance for the info server
WebServer infoServer(80);

// Set to store participant IPs
std::set<String> knownIPs;



// Scan detection structures
struct ScanDetector {
    unsigned long lastScanCheck;
    std::map<String, std::set<int>> ipPorts;
    std::map<String, int> synCounter;
    std::map<String, int> nullScanCounter;
    std::map<String, int> connectionCounter;

    void reset() {
        ipPorts.clear();
        synCounter.clear();
        nullScanCounter.clear();
        connectionCounter.clear();
        lastScanCheck = millis();
    }
} scanDetector;

// Hybrid scan detection structures
struct PacketAnalysis {
    unsigned long lastPacketTime;
    int packetCount;
    std::set<uint16_t> uniquePorts;
    std::set<uint8_t> tcpFlags;
    void reset() {
        packetCount = 0;
        uniquePorts.clear();
        tcpFlags.clear();
    }
};

struct BehaviorAnalysis {
    std::deque<unsigned long> intervalTimes;
    int connectionAttempts;
    unsigned long firstSeen;
    unsigned long lastSeen;
    
    void reset() {
        intervalTimes.clear();
        connectionAttempts = 0;
        firstSeen = 0;
        lastSeen = 0;
    }
};

struct StatisticalAnalysis {
    std::deque<unsigned long> intervals;
    double mean;
    double stdDev;
    
    void reset() {
        intervals.clear();
        mean = 0;
        stdDev = 0;
    }
    
    void update(unsigned long newInterval) {
        if (intervals.size() >= 10) {
            intervals.pop_front();
        }
        intervals.push_back(newInterval);
        
        // Update statistics
        mean = std::accumulate(intervals.begin(), intervals.end(), 0.0) / intervals.size();
        
        double sqSum = 0;
        for(const auto& interval : intervals) {
            sqSum += (interval - mean) * (interval - mean);
        }
        stdDev = sqrt(sqSum / intervals.size());
    }
    
    bool isAnomaly(unsigned long newInterval) {
        if (intervals.size() < 3) return false;
        double zScore = (newInterval - mean) / (stdDev > 0 ? stdDev : 1);
        return abs(zScore) > 2.0;
    }
};

class HybridScanDetector {
private:
    std::map<String, PacketAnalysis> packetStats;
    std::map<String, BehaviorAnalysis> behaviorStats;
    std::map<String, StatisticalAnalysis> statsAnalysis;
    
    const unsigned long DETECTION_WINDOW = 5000; // 5 seconds
    const int PACKET_THRESHOLD = 5;
    const int PORT_THRESHOLD = 3;
    const int FLAGS_THRESHOLD = 2;
    
public:
    bool detectScan(const String& ip, uint16_t port, uint8_t flags, unsigned long now) {
                
        int suspiciousCount = 0;
        
        // Packet Analysis
        auto& pStats = packetStats[ip];
        if (now - pStats.lastPacketTime > DETECTION_WINDOW) {
            pStats.reset();
        }
        pStats.lastPacketTime = now;
        pStats.packetCount++;
        pStats.uniquePorts.insert(port);
        pStats.tcpFlags.insert(flags);
        
        if (pStats.packetCount > PACKET_THRESHOLD ||
            pStats.uniquePorts.size() > PORT_THRESHOLD ||
            pStats.tcpFlags.size() > FLAGS_THRESHOLD) {
            suspiciousCount++;
            Serial.printf("[HYBRID] Packet analysis triggered for IP: %s\n", ip.c_str());
        }
        
        // Behavior Analysis
        auto& bStats = behaviorStats[ip];
        if (bStats.firstSeen == 0) {
            bStats.firstSeen = now;
        }
        bStats.lastSeen = now;
        bStats.connectionAttempts++;
        
        if (bStats.lastSeen - bStats.firstSeen < 5000 && bStats.connectionAttempts > 5) {
            suspiciousCount++;
            Serial.printf("[HYBRID] Behavior analysis triggered for IP: %s\n", ip.c_str());
        }
        
        // Statistical Analysis
        auto& sStats = statsAnalysis[ip];
        if (bStats.intervalTimes.size() > 0) {
            unsigned long interval = now - bStats.lastSeen;
            sStats.update(interval);
            if (sStats.isAnomaly(interval)) {
                suspiciousCount++;
                Serial.printf("[HYBRID] Statistical analysis triggered for IP: %s\n", ip.c_str());
            }
        }
        
        // Combined decision
        if (suspiciousCount >= 2) {
            Serial.printf("[HYBRID-ALERT] Multiple detection methods triggered for IP: %s\n", ip.c_str());
            Serial.printf("[HYBRID-DEBUG] Packets: %d, Ports: %d, Flags: %d\n",
                         pStats.packetCount, pStats.uniquePorts.size(), pStats.tcpFlags.size());
            return true;
        }
        
        return false;
    }
    
    void reset() {
        packetStats.clear();
        behaviorStats.clear();
        statsAnalysis.clear();
    }
};

HybridScanDetector hybridDetector;  // Створюємо глобальний екземпляр детектора


// Global vector to store scan attempts
struct ScanAttempt {
    IPAddress ip;
    uint16_t port;
    unsigned long time;
};
std::vector<ScanAttempt> attempts;


// Function to generate a unique flag based on MAC address
String generateFlag(String macAddress) {
    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    
    // Add "rabbit" modifier to the input string
    String modifiedInput = macAddress + "rabbit";
    mbedtls_sha256_update(&ctx, (const unsigned char*)modifiedInput.c_str(), modifiedInput.length());
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    String flagResult = "FLAG{";
    for (int i = 0; i < 5; i++) {
        char hex[3];
        sprintf(hex, "%02x", hash[i]);
        flagResult += hex;
    }
    flagResult += "}";

    Serial.printf("[FLAG] Generated flag for MAC %s \n", macAddress.c_str());
    return flagResult;
}

// Function to send allowed MACs over Bluetooth
void sendAllowedMacsOverBluetooth() {
    SerialBT.println("START_MAC_LIST");
    for (const auto& mac : allowedMacs) {
        SerialBT.println(mac);
    }
    SerialBT.println("END_MAC_LIST");
}



// Function to get MAC address from IP
String getMacFromIP(String ip) {
    ip4_addr_t addr;
    if (!ip4addr_aton(ip.c_str(), &addr)) {
        return "";
    }

    struct netif* netif = netif_default;
    if (!netif) {
        return "";
    }

    err_t result = etharp_request(netif, &addr);
    if (result != ERR_OK) {
        return "";
    }

    delay(100);

    struct eth_addr* eth_ret = NULL;
    ip4_addr_t* ip_ret = NULL;
    if (etharp_find_addr(netif, &addr, &eth_ret, (const ip4_addr_t**)&ip_ret) == -1 || eth_ret == NULL) {
        return "";
    }

    char macStr[18];
    sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X",
            eth_ret->addr[0], eth_ret->addr[1], eth_ret->addr[2],
            eth_ret->addr[3], eth_ret->addr[4], eth_ret->addr[5]);
    return String(macStr);
}


// Global flag to indicate IP change
bool shouldChangeIP = false;

// HTTP request handler
void handleHttpRequest() {
    String clientIP = server->client().remoteIP().toString();
    String clientMAC = getMacFromIP(clientIP); // Get MAC address
    String uri = server->uri();
    int clientPort = server->client().localPort();

    // Log HTTP request information
    Serial.printf("[HTTP] Request from %s (MAC: %s):%d, URI: %s\n", 
                 clientIP.c_str(), clientMAC.c_str(), clientPort, uri.c_str());

    if (uri == "/rabbit") {
        if (clientMAC.length() > 0) {
            // Generate flag based on MAC
            String flag = generateFlag(clientMAC);
            Serial.printf("[HTTP] Flag generated for MAC: %s\n", clientMAC.c_str());
            server->send(200, "text/plain", flag);

            // Add the MAC to allowed list if not already present
            if (std::find(allowedMacs.begin(), allowedMacs.end(), clientMAC) == allowedMacs.end()) {
                Serial.printf("[MAC] Adding new allowed MAC: %s\n", clientMAC.c_str());
                allowedMacs.push_back(clientMAC);

                // Send the newly allowed MAC to the next ESP device via Bluetooth
                Serial.printf("[BT] Sending allowed MAC to 'Peacock': %s\n", clientMAC.c_str());
                SerialBT.begin("Peacock");
                delay(100); // Small delay to ensure BT is ready
                SerialBT.println(clientMAC);
                
                // Send the complete list of allowed MACs
                sendAllowedMacsOverBluetooth();
            }
        } else {
            // Could not get MAC address
            Serial.printf("[HTTP] Could not get MAC address for IP: %s\n", clientIP.c_str());
            server->send(400, "text/plain", "Could not determine your MAC address");
        }
    } else if (uri == "/") {
        server->send(200, "text/plain", "Nice try, but the rabbit discovered you and ran away...");
        shouldChangeIP = true;
    } else {
        Serial.printf("[HTTP] 404 Not Found for URI: %s\n", uri.c_str());
        server->send(404, "text/plain", "Not Found");
    }
}

// Function to change IP
void changeIP() {
    Serial.printf("[CHANGE-IP] Changing IP from %s\n", currentIP.toString().c_str());

    // Stop the server
    if (server) {
        server->stop();
        delete server;
        server = nullptr;
        Serial.println("[CHANGE-IP] Server stopped and resources released.");
    }

    // Generate a new IP and port
    int newOctet;
    do {
        newOctet = random(10, 244);
    } while (newOctet == currentIP[3]);

    newIP[3] = newOctet;
    currentPort = random(10000, 11000);

    Serial.printf("[CHANGE-IP] Applying new IP: %s and port: %d\n", newIP.toString().c_str(), currentPort);

    // Apply the new configuration
    WiFi.config(newIP, gateway, subnet, dns);

    // Start a new server on the new port
    server = new WebServer(currentPort);
    server->on("/", handleHttpRequest);
    server->onNotFound(handleHttpRequest);
    server->begin();

    currentIP = WiFi.localIP();
    Serial.printf("[CHANGE-IP] New configuration active: IP=%s, Port=%d\n", 
                 currentIP.toString().c_str(), currentPort);
}


// Function to register connection attempts
void registerAttempt(IPAddress ip, uint16_t port) {
    unsigned long now = millis();
    attempts.push_back({ip, port, now});
    Serial.printf("[LOG] Registered attempt from IP: %s on port: %d at time: %lu\n", ip.toString().c_str(), port, now);

}




bool detectNmapScan(const String& clientIP, int port, uint8_t tcpFlags) {
    // Enhanced connection logging
    Serial.printf("[DETECT-DEBUG] Checking connection from %s to port %d with flags 0x%02X\n", 
                 clientIP.c_str(), port, tcpFlags);


    unsigned long currentTime = millis();
    bool scanDetected = false;

    // Enhanced detection window logging
    if (currentTime - scanDetector.lastScanCheck > SCAN_WINDOW_MS) {
        Serial.println("[DETECT-DEBUG] Resetting scan detection window");
        scanDetector.reset();
    }

    // Додаємо порт до списку
    scanDetector.ipPorts[clientIP].insert(port);
    scanDetector.connectionCounter[clientIP]++;

    // Enhanced connection tracking
    Serial.printf("[DEBUG] IP: %s, Unique Ports: %d, Connections: %d, Flags: 0x%02X\n",
                 clientIP.c_str(),
                 scanDetector.ipPorts[clientIP].size(),
                 scanDetector.connectionCounter[clientIP],
                 tcpFlags);

    // Перевірка на швидкі підключення
    if (scanDetector.connectionCounter[clientIP] > RAPID_CONN_THRESHOLD) {
        Serial.printf("[DETECT] Rapid connection scan from %s (%d connections)\n",
                     clientIP.c_str(), scanDetector.connectionCounter[clientIP]);
        scanDetected = true;
    }

    // Перевірка на сканування портів
    if (scanDetector.ipPorts[clientIP].size() > PORT_SCAN_THRESHOLD) {
        Serial.printf("[DETECT] Port scan from %s (%d ports)\n",
                     clientIP.c_str(), scanDetector.ipPorts[clientIP].size());
        scanDetected = true;
    }

    // Перевірка SYN-пакетів
    if (tcpFlags & TH_SYN && !(tcpFlags & TH_ACK)) {
        scanDetector.synCounter[clientIP]++;
        Serial.printf("[DEBUG] SYN count for %s: %d (threshold: %d)\n", 
                     clientIP.c_str(), scanDetector.synCounter[clientIP], SYN_FLOOD_THRESHOLD);
        if (scanDetector.synCounter[clientIP] > SYN_FLOOD_THRESHOLD) {
            Serial.printf("[DETECT] SYN scan from %s\n", clientIP.c_str());
            scanDetected = true;
        }
    }

    // Перевірка NULL-сканування
    if (tcpFlags == 0) {
        scanDetector.nullScanCounter[clientIP]++;
        Serial.printf("[DEBUG] NULL count for %s: %d (threshold: %d)\n", 
                     clientIP.c_str(), scanDetector.nullScanCounter[clientIP], NULL_SCAN_THRESHOLD);
        if (scanDetector.nullScanCounter[clientIP] > NULL_SCAN_THRESHOLD) {
            Serial.printf("[DETECT] NULL scan from %s\n", clientIP.c_str());
            scanDetected = true;
        }
    }

    Serial.printf("[DEBUG] SYN count: %d, NULL count: %d, Unique Ports: %d\n",
                  scanDetector.synCounter[clientIP], 
                  scanDetector.nullScanCounter[clientIP], 
                  scanDetector.ipPorts[clientIP].size());

    if (scanDetected) {
        Serial.printf("[ALERT] Scan detected from %s! Changing IP...\n", clientIP.c_str());
        changeIP();
        return true;
    }

    scanDetector.lastScanCheck = currentTime;
    return false;
}

// Глобальна структура для підрахунку пакетів за IP
std::map<String, int> packetCountByIP;



// Function to handle requests to the info server
void handleInfo() {
    IPAddress clientIP = infoServer.client().remoteIP();
    String clientIPStr = clientIP.toString();

    // Check if the IP is new and log it
    if (knownIPs.find(clientIPStr) == knownIPs.end()) {
        knownIPs.insert(clientIPStr);
        Serial.printf("[INFO] New IP added: %s\n", clientIPStr.c_str());
        Serial.printf("[INFO] Total unique IPs on port 80: %d\n", knownIPs.size());

        // Adjust PACKET_CHANGE_THRESHOLD dynamically
        PACKET_CHANGE_THRESHOLD = 150 + (knownIPs.size() * 50);
        Serial.printf("[INFO] PACKET_CHANGE_THRESHOLD updated to: %d\n", PACKET_CHANGE_THRESHOLD);
    }

    // Message to display project information
    String msg = 
        "🧠 CTF Challenge: 'Rabbit'\n"
        "🔍 Your task is to find the correct port and retrieve the flag.\n"
        "⚠️ Be careful! Scanning too fast might scare the rabbit.\n";

    infoServer.send(200, "text/plain", msg);
}
// Function to initialize the info server
void setupInfoServer() {
    infoServer.on("/", handleInfo);  // Register the handler for the root URI
    infoServer.begin();             // Start the server
    Serial.println("[INFO] Info server started on port 80");
}

// Promiscuous packet handler
void promiscuousPacketHandler(void *buf, wifi_promiscuous_pkt_type_t type) {
    static unsigned long lastDebugTime = 0;
    unsigned long currentTime = millis();
    static unsigned long totalPacketCount = 0;

    totalPacketCount++;

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *payload = pkt->payload;

    // Extract source IP
    char srcIP[16];
    sprintf(srcIP, "%d.%d.%d.%d", payload[26], payload[27], payload[28], payload[29]);

    // Count packets for each IP
    packetCountByIP[String(srcIP)]++;

    // Debug logging every 5 seconds
    if (currentTime - lastDebugTime > 5000) {
        Serial.printf("[DEBUG] Processed %lu packets in promiscuous mode in last 5 seconds\n", totalPacketCount);
        Serial.printf("[DEBUG] Current PACKET_CHANGE_THRESHOLD: %d\n", PACKET_CHANGE_THRESHOLD);

        // If the total packet count exceeds the threshold, change IP and port
        if (totalPacketCount > PACKET_CHANGE_THRESHOLD) {
            Serial.printf("[ALERT] Packet count exceeded threshold (%d packets). Changing IP and port...\n", totalPacketCount);
            changeIP();
        }

        // Clear counters for the next interval
        packetCountByIP.clear();
        totalPacketCount = 0;
        lastDebugTime = currentTime;
    }
}

// Function to detect potential scans
void detectScan() {
    unsigned long now = millis();
    // Видаляємо спроби, старші за 5 секунд
    attempts.erase(std::remove_if(attempts.begin(), attempts.end(),
                                  [now](const ScanAttempt &a) { return (now - a.time > 5000); }),
                   attempts.end());


    // Підрахунок спроб від кожного IP
    std::map<String, int> ipCount;
    for (const auto &a : attempts) {
        ipCount[a.ip.toString()]++;
    }

    // Перевірка на сканування
    for (const auto &entry : ipCount) {
        Serial.printf("[LOG] IP: %s has %d attempts in the last 5 seconds\n", entry.first.c_str(), entry.second);

        if (entry.second >= 5) { // Поріг: 5 спроб за 5 секунд
            Serial.printf("[ALERT] Potential scan detected from IP: %s with %d attempts\n", entry.first.c_str(), entry.second);

            changeIP(); // Зміна IP для уникнення сканування
            Serial.println("[ACTION] IP changed to avoid scan.");
        }
    }
}





// Setup function
void setup() {
    Serial.begin(115200);
    SerialBT.begin("Rabbit");
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }

    currentIP = WiFi.localIP();
    currentPort = random(10000, 11000);
    server = new WebServer(currentPort);

    // Register URI handlers
    server->on("/rabbit", handleHttpRequest);
    server->onNotFound([]() {
        server->send(404, "text/plain", "Not Found");
    });

    server->begin();
    Serial.printf("[LOG] Server started at %s:%d\n", currentIP.toString().c_str(), currentPort);

    // Initialize the info server
    setupInfoServer();

    // Enable promiscuous mode for SYN packet detection
    wifi_promiscuous_filter_t filter = { 
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA 
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(promiscuousPacketHandler);
    
    // Added debug logging
    Serial.println("[LOG] Enhanced scan detection enabled. Waiting for scan attempts...");
    Serial.println("[DEBUG] Current scan thresholds:");
    Serial.printf("[DEBUG] SCAN_WINDOW_MS: %d ms\n", SCAN_WINDOW_MS);
    Serial.printf("[DEBUG] RAPID_CONN_THRESHOLD: %d\n", RAPID_CONN_THRESHOLD);
    Serial.printf("[DEBUG] PORT_SCAN_THRESHOLD: %d\n", PORT_SCAN_THRESHOLD);
    Serial.printf("[DEBUG] SYN_FLOOD_THRESHOLD: %d\n", SYN_FLOOD_THRESHOLD);
    Serial.printf("[DEBUG] NULL_SCAN_THRESHOLD: %d\n", NULL_SCAN_THRESHOLD);
}

// Loop function
void loop() {
    // Handle HTTP requests for the main server
    if (server) {
        server->handleClient();
    }

    // Handle HTTP requests for the info server
    infoServer.handleClient();

    // Change IP if the flag is set
    if (shouldChangeIP) {
        shouldChangeIP = false; // Reset the flag
        changeIP();
    }

    // Periodically check for scans
    detectScan();
}

