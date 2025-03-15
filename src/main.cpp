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

// Налаштування мережі
const char* WIFI_SSID = "TP-Link_D06B";
const char* WIFI_PASSWORD = "123456789"; 
IPAddress gateway(192, 168, 0, 1);
IPAddress subnet(255, 255, 255, 0);
IPAddress dns(8, 8, 8, 8);
IPAddress newIP(192, 168, 0, 0); // Initial value, last octet will be set dynamically

// Bluetooth Serial
BluetoothSerial SerialBT;

// Змінні для роботи з мережею
int currentPort;
WebServer* server;
IPAddress currentIP;

// Список MAC-адрес студентів
std::vector<String> allowedMacs;

// Лічильники активності
unsigned long lastActivityTime = 0;
int connectionCount = 0;
unsigned long lastIPChangeTime = 0;
bool aggressiveScanDetected = false;

// Функція генерації прапора
String generateFlag(String macAddress) {
  uint8_t hash[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, (const unsigned char*)macAddress.c_str(), macAddress.length());
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);
  
  // Перетворення перших 10 байт хешу на hex-рядок
  String flagResult = "FLAG{";
  for (int i = 0; i < 5; i++) {
    char hex[3];
    sprintf(hex, "%02x", hash[i]);
    flagResult += hex;
  }
  flagResult += "}";
  
  return flagResult;
}

// Функція отримання MAC за IP (імітація ARP)
String getMacFromIP(String ip) {
  ip4_addr_t addr;
  if (!ip4addr_aton(ip.c_str(), &addr)) {
      return ""; // Невірний IP
  }

  struct netif* netif = netif_default;
  if (!netif) {
      return "";
  }

  // Спроба відправити ARP-запит
  err_t result = etharp_request(netif, &addr);
  if (result != ERR_OK) {
      return "";
  }

  // Додаємо затримку, щоб дати час на отримання ARP відповіді
  delay(100);

  // Безпечна перевірка - просто повертаємо порожній рядок, якщо MAC не знайдено
  struct eth_addr* eth_ret = NULL;
  ip4_addr_t* ip_ret = NULL;
  if (etharp_find_addr(netif, &addr, &eth_ret, (const ip4_addr_t**)&ip_ret) == -1 || eth_ret == NULL) {
      return ""; // MAC не знайдено
  }

  char macStr[18];
  sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", 
          eth_ret->addr[0], eth_ret->addr[1], eth_ret->addr[2], 
          eth_ret->addr[3], eth_ret->addr[4], eth_ret->addr[5]);
  return String(macStr);
}

void handleHttpRequest() {
  // Збільшуємо лічильник підключень
  connectionCount++;
  
  // Отримуємо деталі запиту
  String uri = server->uri();
  String method = server->method() == HTTP_GET ? "GET" : "POST";
  String userAgent = server->header("User-Agent");
  IPAddress clientIP = server->client().remoteIP();
  
  Serial.print("URI запиту: ");
  Serial.println(uri);
  Serial.print("Метод: ");
  Serial.println(method);
  Serial.print("Клієнт IP: ");
  Serial.println(clientIP.toString());
  Serial.print("User-Agent: ");
  Serial.println(userAgent);
  
  // Перевірка на агресивне сканування
  if (userAgent.indexOf("Nmap") >= 0) {
    // Якщо це агресивне сканування (опція -A або кількість підключень перевищує поріг)
    if (userAgent.indexOf("aggressive") >= 0 || 
        userAgent.indexOf("-A") >= 0 || 
        connectionCount > 20) {  // Встановлюємо поріг вищим за max-rate=10
      
      Serial.println("Виявлено агресивне сканування!");
      aggressiveScanDetected = true;
      server->send(403, "text/plain", "Forbidden");
      
      // Затримка перед зміною IP/порту
      delay(4000);  // 4 секунди затримки
      return;
    }
    
    // Звичайне сканування - відповідаємо нормально, але готуємося до зміни IP
    if (uri == "/") {
      server->send(200, "text/plain", "The rabbit is hiding. Try to find it.");
    } else {
      server->send(404, "text/plain", "Not Found");
    }
    
    // Відкладена зміна IP/порту
    lastActivityTime = millis();  // Оновлюємо час активності
    return;
  }
  
  // Обробка шляху /rabbit для отримання прапору
  if (uri == "/rabbit" && method == "GET") {
    // Отримуємо MAC-адресу клієнта
    String macAddress = getMacFromIP(clientIP.toString());
    
    // Якщо не вдалося отримати MAC, використовуємо IP як резервний варіант
    if (macAddress.length() == 0) {
      Serial.println("Не вдалося отримати MAC, використовуємо IP");
      macAddress = clientIP.toString();
    }
    
    String flag = generateFlag(macAddress);
    
    // Додаємо MAC/IP до списку дозволених
    if (std::find(allowedMacs.begin(), allowedMacs.end(), macAddress) == std::end(allowedMacs)) {
      allowedMacs.push_back(macAddress);
    }
    
    // Передача списку через Bluetooth
    SerialBT.println("Allowed MACs/IPs:");
    Serial.println("Allowed MACs/IPs:");
    for (const auto& mac : allowedMacs) {
      SerialBT.println(mac);
      Serial.println(mac);
    }
    
    // Відправляємо прапор
    server->send(200, "text/plain", "Congratulations! Your flag is: " + flag);
    Serial.println("Прапор надіслано для: " + macAddress);
    return;
  }
  
  // Обробка кореневого шляху - надаємо підказку
  if (uri == "/") {
    server->send(200, "text/plain", "The rabbit is hiding. Try to find it.");
    return;
  }
  
  // Для всіх інших шляхів - нічого корисного
  server->send(404, "text/plain", "Not Found");
  
  Serial.println("HTTP-запит оброблено.");
}

// Функція зміни IP
void changeNetworkSubnet() {
  Serial.println("Зміна IP-адреси...");
  
  // Зупинка сервера
  if (server) {
    server->stop();
    delete server;
    server = nullptr;
  }
  
  // Відключення від Wi-Fi
  WiFi.disconnect(true);
  delay(1000);
  
  // Повторне підключення
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 10) {
    delay(500);
    Serial.print(".");
    attempts++;
  }
  
  if (WiFi.status() == WL_CONNECTED) {
    currentIP = WiFi.localIP();
    Serial.print("Нова IP-адреса: ");
    Serial.println(currentIP.toString());
    
    // Створення нового сервера на випадковому порту
    currentPort = random(10000, 11000);
    server = new WebServer(currentPort);
    
    // Реєстрація обробника
    server->on("/", handleHttpRequest);
    server->onNotFound(handleHttpRequest);  // All other paths
    server->begin();
    
    Serial.print("Сервер запущено на порту: ");
    Serial.println(currentPort);
  } else {
    Serial.println("Не вдалося підключитися до Wi-Fi!");
  }
  
  // Скидання лічильників
  connectionCount = 0;
  aggressiveScanDetected = false;
  lastIPChangeTime = millis();
}

// Функція зміни IP на статичний IP 10.19.87.x
void changeStaticIP() {
  Serial.println("Зміна IP-адреси на статичний IP.");

  // Зупинка сервера
  if (server) {
    server->stop();
    delete server;
    server = nullptr;
  }

  // Відключення від Wi-Fi
  WiFi.disconnect(true);
  delay(1000);

  // Випадкове значення для останнього октету IP
  int lastOctet = random(1, 255);
  newIP[3] = lastOctet;

  // Повторне підключення з новим статичним IP
  WiFi.config(newIP, gateway, subnet, dns);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 10) {
    delay(500);
    Serial.print(".");
    attempts++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    currentIP = WiFi.localIP();
    Serial.print("Нова статична IP-адреса: ");
    Serial.println(currentIP.toString());

    // Створення нового сервера на випадковому порту
    currentPort = random(10000, 11000);
    server = new WebServer(currentPort);

    // Реєстрація обробника
    server->on("/", handleHttpRequest);
    server->onNotFound(handleHttpRequest);  // All other paths
    server->begin();

    Serial.print("Сервер запущено на порту: ");
    Serial.println(currentPort);
  } else {
    Serial.println("Не вдалося підключитися до Wi-Fi!");
  }

  // Скидання лічильників
  connectionCount = 0;
  aggressiveScanDetected = false;
  lastIPChangeTime = millis();
}

void setup() {
  Serial.begin(115200);
  Serial.println("Ініціалізація...");
  
  // Ініціалізація Bluetooth
  SerialBT.begin("Заєць");
  Serial.println("Bluetooth розпочато з ім'ям: Заєць");
  
  // Налаштування випадкового генератора
  randomSeed(analogRead(0));
  
  // Підключення до Wi-Fi
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("Підключення до Wi-Fi");
  
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 20) {
    delay(500);
    Serial.print(".");
    attempts++;
  }
  
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("");
    Serial.print("Підключено до Wi-Fi! IP-адреса: ");
    currentIP = WiFi.localIP();
    Serial.println(currentIP.toString());
    
    // Встановлення випадкового порту і створення сервера
    currentPort = random(10000, 11000);
    server = new WebServer(currentPort);
    
    // Реєстрація обробника HTTP-запиту
    server->on("/", handleHttpRequest);
    server->onNotFound(handleHttpRequest);  // All other paths
    server->begin();
    
    Serial.print("Веб-сервер запущено на порту: ");
    Serial.println(currentPort);
    
    lastIPChangeTime = millis();
  } else {
    Serial.println("Не вдалося підключитися до Wi-Fi!");
  }
  Serial.println("Ініціалізація завершена.");
}

void loop() {
  // Обробка запитів, якщо сервер активний
  if (server) {
    server->handleClient();
  }
  
  // Реакція на агресивне сканування - негайна зміна
  if (aggressiveScanDetected) {
    Serial.println("Виявлено агресивне сканування! Негайна зміна IP...");
    changeStaticIP();
  }
  
  // Реакція на звичайне сканування - затримка 4 секунди
  if (millis() - lastActivityTime > 4000 && connectionCount >= 5) {
    Serial.println("Виявлено звичайне сканування! Зміна IP після затримки...");
    changeStaticIP();
  }
  
  // Автоматична зміна IP кожні 2 хвилини
  if (millis() - lastIPChangeTime > 120000) {
    Serial.println("Автоматична зміна IP...");
    changeStaticIP();
  }
  
  // Скидання лічильника підключень кожну секунду
  if (millis() - lastActivityTime > 1000) {
    lastActivityTime = millis();
    connectionCount = 0;
  }
  
  // Невелика затримка для економії ресурсів
  delay(10);
}