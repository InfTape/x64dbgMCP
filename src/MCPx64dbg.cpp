#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

// Include Windows headers before socket headers
#include <Windows.h>
// Include x64dbg SDK
#include "pluginsdk/_plugins.h"
#include "pluginsdk/_scriptapi_argument.h"
#include "pluginsdk/_scriptapi_assembler.h"
#include "pluginsdk/_scriptapi_bookmark.h"
#include "pluginsdk/_scriptapi_comment.h"
#include "pluginsdk/_scriptapi_debug.h"
#include "pluginsdk/_scriptapi_flag.h"
#include "pluginsdk/_scriptapi_function.h"
#include "pluginsdk/_scriptapi_gui.h"
#include "pluginsdk/_scriptapi_label.h"
#include "pluginsdk/_scriptapi_memory.h"
#include "pluginsdk/_scriptapi_misc.h"
#include "pluginsdk/_scriptapi_module.h"
#include "pluginsdk/_scriptapi_pattern.h"
#include "pluginsdk/_scriptapi_register.h"
#include "pluginsdk/_scriptapi_stack.h"
#include "pluginsdk/_scriptapi_symbol.h"
#include "pluginsdk/TitanEngine.h"
#include "pluginsdk/bridgemain.h"
#include <iomanip> // For std::setw and std::setfill


// Socket includes - after Windows.h
#include <winsock2.h>
#include <ws2tcpip.h>

// Standard library includes
#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

// Link with ws2_32.lib
#pragma comment(lib, "ws2_32.lib")

// Link against correct x64dbg library depending on architecture
#ifdef _WIN64
#pragma comment(lib, "x64dbg.lib")
#else
#pragma comment(lib, "x32dbg.lib")
#endif

// Architecture-aware formatting and register macros
#ifdef _WIN64
#define FMT_DUINT_HEX "0x%llx"
#define FMT_DUINT_DEC "%llu"
#define DUINT_CAST_PRINTF(v) (unsigned long long)(v)
#define DUSIZE_CAST_PRINTF(v) (unsigned long long)(v)
#define REG_IP Script::Register::RIP
#else
#define FMT_DUINT_HEX "0x%08X"
#define FMT_DUINT_DEC "%u"
#define DUINT_CAST_PRINTF(v) (unsigned int)(v)
#define DUSIZE_CAST_PRINTF(v) (unsigned int)(v)
#define REG_IP Script::Register::EIP
#endif

// Plugin information
#define PLUGIN_NAME "x64dbg HTTP Server"
#define PLUGIN_VERSION 1

// Default settings
#define DEFAULT_PORT 8888
#define MAX_REQUEST_SIZE 8192

// Global variables
int g_pluginHandle;
HANDLE g_httpServerThread = NULL;
bool g_httpServerRunning = false;
int g_httpPort = DEFAULT_PORT;
std::mutex g_httpMutex;
SOCKET g_serverSocket = INVALID_SOCKET;

struct GuiContextReadRequest {
  DWORD titanIndex;
  ULONG_PTR value;
  bool success;
  HANDLE doneEvent;
};

// Forward declarations
bool startHttpServer();
void stopHttpServer();
DWORD WINAPI HttpServerThread(LPVOID lpParam);
std::string readHttpRequest(SOCKET clientSocket);
void sendHttpResponse(SOCKET clientSocket, int statusCode,
                      const std::string &contentType,
                      const std::string &responseBody);
bool sendAll(SOCKET clientSocket, const char *data, size_t length);
void parseHttpRequest(const std::string &request, std::string &method,
                      std::string &path, std::string &query, std::string &body);
std::unordered_map<std::string, std::string>
parseQueryParams(const std::string &query);
std::string urlDecode(const std::string &str);
std::string escapeJsonString(const char *str);

// Command callback declarations
bool cbEnableHttpServer(int argc, char *argv[]);
bool cbSetHttpPort(int argc, char *argv[]);
void registerCommands();

//=============================================================================
// Plugin Interface Implementation
//============================================================================

// Initialize the plugin
bool pluginInit(PLUG_INITSTRUCT *initStruct) {
  initStruct->pluginVersion = PLUGIN_VERSION;
  initStruct->sdkVersion = PLUG_SDKVERSION;
  strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
  g_pluginHandle = initStruct->pluginHandle;

  _plugin_logputs("x64dbg HTTP Server plugin loading...");

  // Register commands
  registerCommands();

  // Start the HTTP server
  if (startHttpServer()) {
    _plugin_logprintf("x64dbg HTTP Server started on port %d\n", g_httpPort);
  } else {
    _plugin_logputs("Failed to start HTTP server!");
  }

  _plugin_logputs("x64dbg HTTP Server plugin loaded!");
  return true;
}

// Stop the plugin
void pluginStop() {
  _plugin_logputs("Stopping x64dbg HTTP Server...");
  stopHttpServer();
  _plugin_logputs("x64dbg HTTP Server stopped.");
}

// Plugin setup
bool pluginSetup() { return true; }

// Plugin exports
extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT *initStruct) {
  return pluginInit(initStruct);
}

extern "C" __declspec(dllexport) void plugstop() { pluginStop(); }

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT *setupStruct) {
  pluginSetup();
}

//=============================================================================
// HTTP Server Implementation
//=============================================================================

// Start the HTTP server
bool startHttpServer() {
  std::lock_guard<std::mutex> lock(g_httpMutex);

  // Stop existing server if running
  if (g_httpServerRunning) {
    stopHttpServer();
  }

  // Create and start the server thread
  g_httpServerThread = CreateThread(NULL, 0, HttpServerThread, NULL, 0, NULL);
  if (g_httpServerThread == NULL) {
    _plugin_logputs("Failed to create HTTP server thread");
    return false;
  }

  g_httpServerRunning = true;
  return true;
}

// Stop the HTTP server
void stopHttpServer() {
  std::lock_guard<std::mutex> lock(g_httpMutex);

  if (g_httpServerRunning) {
    g_httpServerRunning = false;

    // Close the server socket to unblock any accept calls
    if (g_serverSocket != INVALID_SOCKET) {
      closesocket(g_serverSocket);
      g_serverSocket = INVALID_SOCKET;
    }

    // Wait for the thread to exit
    if (g_httpServerThread != NULL) {
      WaitForSingleObject(g_httpServerThread, 1000);
      CloseHandle(g_httpServerThread);
      g_httpServerThread = NULL;
    }
  }
}

// URL decode function
std::string urlDecode(const std::string &str) {
  std::string decoded;
  for (size_t i = 0; i < str.length(); ++i) {
    if (str[i] == '%' && i + 2 < str.length()) {
      int value;
      std::istringstream is(str.substr(i + 1, 2));
      if (is >> std::hex >> value) {
        decoded += static_cast<char>(value);
        i += 2;
      } else {
        decoded += str[i];
      }
    } else if (str[i] == '+') {
      decoded += ' ';
    } else {
      decoded += str[i];
    }
  }
  return decoded;
}

static bool hasHexPrefix(const std::string &value) {
  return value.length() > 2 && value[0] == '0' &&
         (value[1] == 'x' || value[1] == 'X');
}

static bool tryParseDuint(const std::string &value, duint &parsedValue,
                          int defaultBase = 16) {
  if (value.empty()) {
    return false;
  }

  try {
    const bool prefixedHex = hasHexPrefix(value);
    const std::string digits = prefixedHex ? value.substr(2) : value;
    if (digits.empty()) {
      return false;
    }

    size_t consumed = 0;
    unsigned long long parsed =
        std::stoull(digits, &consumed, prefixedHex ? 16 : defaultBase);
    if (consumed != digits.length()) {
      return false;
    }

    parsedValue = static_cast<duint>(parsed);
    return true;
  } catch (const std::exception &) {
    return false;
  }
}

static std::string
getRequestParam(const std::unordered_map<std::string, std::string> &queryParams,
                const std::unordered_map<std::string, std::string> &bodyParams,
                const std::string &key) {
  auto queryIt = queryParams.find(key);
  if (queryIt != queryParams.end() && !queryIt->second.empty()) {
    return queryIt->second;
  }

  auto bodyIt = bodyParams.find(key);
  if (bodyIt != bodyParams.end() && !bodyIt->second.empty()) {
    return bodyIt->second;
  }

  return "";
}

static void readContextOnGuiThread(void *userdata) {
  auto *request = static_cast<GuiContextReadRequest *>(userdata);
  request->success = false;
  request->value = 0;

  HANDLE threadHandle = DbgGetThreadHandle();
  if (threadHandle != nullptr) {
    if (request->titanIndex == UE_CFLAGS) {
      TITAN_ENGINE_CONTEXT_t context = {};
      if (GetFullContextDataEx(threadHandle, &context)) {
        request->value = context.eflags;
        request->success = true;
      }
    } else {
      request->value = GetContextDataEx(threadHandle, request->titanIndex);
      request->success = true;
    }
  }

  SetEvent(request->doneEvent);
}

static bool readContextDataOnGuiThread(DWORD titanIndex, ULONG_PTR &value) {
  GuiContextReadRequest request = {};
  request.titanIndex = titanIndex;
  request.doneEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
  if (request.doneEvent == nullptr) {
    return false;
  }

  GuiExecuteOnGuiThreadEx(readContextOnGuiThread, &request);
  WaitForSingleObject(request.doneEvent, INFINITE);
  CloseHandle(request.doneEvent);

  if (!request.success) {
    return false;
  }

  value = request.value;
  return true;
}

static bool tryParseFlagBitIndex(const std::string &rawFlagName, int &bitIndex) {
  std::string flagName = rawFlagName;
  std::transform(
      flagName.begin(), flagName.end(), flagName.begin(),
      [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });

  if (flagName == "cf")
    bitIndex = 0;
  else if (flagName == "pf")
    bitIndex = 2;
  else if (flagName == "af")
    bitIndex = 4;
  else if (flagName == "zf")
    bitIndex = 6;
  else if (flagName == "sf")
    bitIndex = 7;
  else if (flagName == "tf")
    bitIndex = 8;
  else if (flagName == "if")
    bitIndex = 9;
  else if (flagName == "df")
    bitIndex = 10;
  else if (flagName == "of")
    bitIndex = 11;
  else
    return false;

  return true;
}

static bool normalizePageRights(const std::string &rawRights,
                                std::string &normalizedRights) {
  normalizedRights.clear();

  std::string decoded = urlDecode(rawRights);
  std::string compactRights;
  compactRights.reserve(decoded.size());

  for (char ch : decoded) {
    unsigned char uch = static_cast<unsigned char>(ch);
    if (std::isspace(uch) || ch == '-') {
      continue;
    }

    char upper = static_cast<char>(std::toupper(uch));
    switch (upper) {
    case 'E':
    case 'R':
    case 'W':
    case 'X':
    case 'C':
    case 'G':
      compactRights += upper;
      break;
    default:
      return false;
    }
  }

  const bool hasExecute = compactRights.find('E') != std::string::npos ||
                          compactRights.find('X') != std::string::npos;
  const bool hasRead = compactRights.find('R') != std::string::npos;
  const bool hasWrite = compactRights.find('W') != std::string::npos;
  const bool hasCopy = compactRights.find('C') != std::string::npos;
  const bool hasGuard = compactRights.find('G') != std::string::npos;

  std::string baseRights;
  if (hasExecute) {
    if (hasCopy) {
      baseRights = "ExecuteWriteCopy";
    } else if (hasRead && hasWrite) {
      baseRights = "ExecuteReadWrite";
    } else if (hasRead) {
      baseRights = "ExecuteRead";
    } else if (!hasWrite) {
      baseRights = "Execute";
    } else {
      return false;
    }
  } else {
    if (hasCopy) {
      baseRights = "WriteCopy";
    } else if (hasRead && hasWrite) {
      baseRights = "ReadWrite";
    } else if (hasRead) {
      baseRights = "ReadOnly";
    } else if (!hasWrite) {
      baseRights = "NoAccess";
    } else {
      return false;
    }
  }

  normalizedRights = hasGuard ? "G" + baseRights : baseRights;
  return true;
}

static bool tryParseRegisterName(const std::string &rawName,
                                 Script::Register::RegisterEnum &reg) {
  std::string regName = rawName;
  std::transform(
      regName.begin(), regName.end(), regName.begin(),
      [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });

  if (regName == "cax")
    reg = Script::Register::CAX;
  else if (regName == "cbx")
    reg = Script::Register::CBX;
  else if (regName == "ccx")
    reg = Script::Register::CCX;
  else if (regName == "cdx")
    reg = Script::Register::CDX;
  else if (regName == "csi")
    reg = Script::Register::CSI;
  else if (regName == "cdi")
    reg = Script::Register::CDI;
  else if (regName == "cbp")
    reg = Script::Register::CBP;
  else if (regName == "csp")
    reg = Script::Register::CSP;
  else if (regName == "cip")
    reg = Script::Register::CIP;
  else if (regName == "cflags" || regName == "eflags" || regName == "rflags")
    reg = Script::Register::CFLAGS;
  else if (regName == "eax")
    reg = Script::Register::EAX;
  else if (regName == "ebx")
    reg = Script::Register::EBX;
  else if (regName == "ecx")
    reg = Script::Register::ECX;
  else if (regName == "edx")
    reg = Script::Register::EDX;
  else if (regName == "esi")
    reg = Script::Register::ESI;
  else if (regName == "edi")
    reg = Script::Register::EDI;
  else if (regName == "ebp")
    reg = Script::Register::EBP;
  else if (regName == "esp")
    reg = Script::Register::ESP;
  else if (regName == "eip")
    reg = Script::Register::EIP;
#ifdef _WIN64
  else if (regName == "rax")
    reg = Script::Register::RAX;
  else if (regName == "rbx")
    reg = Script::Register::RBX;
  else if (regName == "rcx")
    reg = Script::Register::RCX;
  else if (regName == "rdx")
    reg = Script::Register::RDX;
  else if (regName == "rsi")
    reg = Script::Register::RSI;
  else if (regName == "rdi")
    reg = Script::Register::RDI;
  else if (regName == "rbp")
    reg = Script::Register::RBP;
  else if (regName == "rsp")
    reg = Script::Register::RSP;
  else if (regName == "rip")
    reg = Script::Register::RIP;
  else if (regName == "r8")
    reg = Script::Register::R8;
  else if (regName == "r9")
    reg = Script::Register::R9;
  else if (regName == "r10")
    reg = Script::Register::R10;
  else if (regName == "r11")
    reg = Script::Register::R11;
  else if (regName == "r12")
    reg = Script::Register::R12;
  else if (regName == "r13")
    reg = Script::Register::R13;
  else if (regName == "r14")
    reg = Script::Register::R14;
  else if (regName == "r15")
    reg = Script::Register::R15;
#endif
  else
    return false;

  return true;
}

static void sendJsonErrorResponse(SOCKET clientSocket, int statusCode,
                                  const std::string &message) {
  std::stringstream ss;
  ss << "{\"success\":false,\"error\":\"" << escapeJsonString(message.c_str())
     << "\"}";
  sendHttpResponse(clientSocket, statusCode, "application/json", ss.str());
}

static void sendJsonMessageResponse(SOCKET clientSocket, int statusCode,
                                    bool success, const std::string &message) {
  std::stringstream ss;
  ss << "{\"success\":" << (success ? "true" : "false") << ",\"message\":\""
     << escapeJsonString(message.c_str()) << "\"}";
  sendHttpResponse(clientSocket, statusCode, "application/json", ss.str());
}

// Escape a string for safe inclusion in a JSON string value
std::string escapeJsonString(const char *str) {
  std::string result;
  if (!str)
    return result;
  while (*str) {
    switch (*str) {
    case '\\':
      result += "\\\\";
      break;
    case '"':
      result += "\\\"";
      break;
    case '\b':
      result += "\\b";
      break;
    case '\f':
      result += "\\f";
      break;
    case '\n':
      result += "\\n";
      break;
    case '\r':
      result += "\\r";
      break;
    case '\t':
      result += "\\t";
      break;
    default:
      if (static_cast<unsigned char>(*str) < 0x20) {
        char buf[8];
        snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(*str));
        result += buf;
      } else {
        result += *str;
      }
      break;
    }
    str++;
  }
  return result;
}

static bool tryDisasmInstruction(duint addr, DISASM_INSTR &instr) {
  memset(&instr, 0, sizeof(instr));
  DbgDisasmAt(addr, &instr);
  return instr.instr_size > 0;
}

static void appendDisasmInstructionJson(std::stringstream &ss, duint addr,
                                        const DISASM_INSTR &instr, bool found) {
  ss << "{";
  ss << "\"address\":\"0x" << std::hex << addr << "\",";
  ss << "\"instruction\":\"" << escapeJsonString(instr.instruction) << "\",";
  ss << "\"size\":" << std::dec << instr.instr_size << ",";
  ss << "\"found\":" << (found ? "true" : "false");
  ss << "}";
}

// HTTP server thread function using standard Winsock
DWORD WINAPI HttpServerThread(LPVOID lpParam) {
  WSADATA wsaData;
  int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (result != 0) {
    _plugin_logprintf("WSAStartup failed with error: %d\n", result);
    return 1;
  }

  // Create a socket for the server
  g_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (g_serverSocket == INVALID_SOCKET) {
    _plugin_logprintf("Failed to create socket, error: %d\n",
                      WSAGetLastError());
    WSACleanup();
    return 1;
  }

  // Setup the server address structure
  sockaddr_in serverAddr;
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // localhost only
  serverAddr.sin_port = htons((u_short)g_httpPort);

  // Bind the socket
  if (bind(g_serverSocket, (sockaddr *)&serverAddr, sizeof(serverAddr)) ==
      SOCKET_ERROR) {
    _plugin_logprintf("Bind failed with error: %d\n", WSAGetLastError());
    closesocket(g_serverSocket);
    WSACleanup();
    return 1;
  }

  // Listen for incoming connections
  if (listen(g_serverSocket, SOMAXCONN) == SOCKET_ERROR) {
    _plugin_logprintf("Listen failed with error: %d\n", WSAGetLastError());
    closesocket(g_serverSocket);
    WSACleanup();
    return 1;
  }

  _plugin_logprintf("HTTP server started at http://localhost:%d/\n",
                    g_httpPort);

  // Set socket to non-blocking mode
  u_long mode = 1;
  ioctlsocket(g_serverSocket, FIONBIO, &mode);

  // Main server loop
  while (g_httpServerRunning) {
    // Accept a client connection
    sockaddr_in clientAddr;
    int clientAddrSize = sizeof(clientAddr);
    SOCKET clientSocket =
        accept(g_serverSocket, (sockaddr *)&clientAddr, &clientAddrSize);

    if (clientSocket == INVALID_SOCKET) {
      // Check if we need to exit
      if (!g_httpServerRunning) {
        break;
      }

      // Non-blocking socket may return WOULD_BLOCK when no connections are
      // pending
      if (WSAGetLastError() != WSAEWOULDBLOCK) {
        _plugin_logprintf("Accept failed with error: %d\n", WSAGetLastError());
      }

      Sleep(100); // Avoid tight loop
      continue;
    }

    // Read the HTTP request
    std::string requestData = readHttpRequest(clientSocket);

    if (!requestData.empty()) {
      // Parse the HTTP request
      std::string method, path, query, body;
      parseHttpRequest(requestData, method, path, query, body);
      _plugin_logprintf("HTTP Request: %s %s\n", method.c_str(), path.c_str());

      // Parse query parameters
      std::unordered_map<std::string, std::string> queryParams =
          parseQueryParams(query);
      std::unordered_map<std::string, std::string> bodyParams =
          parseQueryParams(body);

      // Handle different endpoints
      try {
        // Unified command execution endpoint
        if (path == "/cmd") {
          std::string cmd = getRequestParam(queryParams, bodyParams, "command");
          if (!cmd.empty()) {
            cmd = urlDecode(cmd);
          }

          if (cmd.empty()) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Missing command parameter");
            continue;
          }

          // Snapshot the references tab row count before the command
          int refRowCountBefore = GuiReferenceGetRowCount();

          // Execute the command synchronously
          bool success = DbgCmdExecDirect(cmd.c_str());

          // Check if the references tab changed (command populated it fresh)
          int refRowCountAfter = GuiReferenceGetRowCount();
          bool refChanged = (refRowCountAfter != refRowCountBefore);

          // If row counts match, do a quick content check on the first row
          // to detect cases where a new search returned the same number of rows
          if (!refChanged && refRowCountAfter > 0) {
            // We can't perfectly detect this without storing old content,
            // but a count change covers the vast majority of cases.
            // As a heuristic: if the command starts with a known ref-producing
            // keyword, assume it changed.
            std::string cmdLower = cmd;
            std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(),
                           ::tolower);
            if (cmdLower.find("refstr") == 0 || cmdLower.find("reffind") == 0 ||
                cmdLower.find("reffindrange") == 0 ||
                cmdLower.find("findall") == 0 ||
                cmdLower.find("findallmem") == 0 ||
                cmdLower.find("findasm") == 0 ||
                cmdLower.find("modcallfind") == 0 ||
                cmdLower.find("guidfind") == 0 ||
                cmdLower.find("strref") == 0) {
              refChanged = true;
            }
          }

          // Pagination parameters for reference view results
          int refOffset = 0;
          int refLimit = 100; // default page size
          if (!queryParams["offset"].empty()) {
            try {
              refOffset = std::stoi(queryParams["offset"]);
            } catch (...) {
            }
            if (refOffset < 0)
              refOffset = 0;
          }
          if (!queryParams["limit"].empty()) {
            try {
              refLimit = std::stoi(queryParams["limit"]);
            } catch (...) {
            }
            if (refLimit < 1)
              refLimit = 1;
            if (refLimit > 5000)
              refLimit = 5000;
          }

          // If the command failed, return a simple error without refView data
          if (!success) {
            std::stringstream ss;
            ss << "{\"success\":false,\"refView\":{\"rowCount\":0,\"rows\":[]}"
                  "}";
            sendHttpResponse(clientSocket, 200, "application/json", ss.str());
          } else {
            int totalRows = refChanged ? refRowCountAfter : 0;

            std::stringstream ss;
            ss << "{";
            ss << "\"success\":true,";
            ss << "\"refView\":{";
            ss << "\"rowCount\":" << totalRows << ",";
            ss << "\"rows\":[";

            if (totalRows > 0) {
              // Clamp offset/limit to actual data range
              if (refOffset >= totalRows)
                refOffset = totalRows;
              int endRow = refOffset + refLimit;
              if (endRow > totalRows)
                endRow = totalRows;

              // Determine column count by probing the first row (up to 10
              // columns)
              int numCols = 0;
              for (int c = 0; c < 10; c++) {
                char *cell = GuiReferenceGetCellContent(0, c);
                if (cell) {
                  if (cell[0] != '\0') {
                    numCols = c + 1;
                  }
                  BridgeFree(cell);
                }
              }
              if (numCols < 2)
                numCols = 2;

              bool firstRow = true;
              for (int row = refOffset; row < endRow; row++) {
                if (!firstRow)
                  ss << ",";
                firstRow = false;
                ss << "[";
                for (int col = 0; col < numCols; col++) {
                  if (col > 0)
                    ss << ",";
                  char *cell = GuiReferenceGetCellContent(row, col);
                  if (cell) {
                    ss << "\"" << escapeJsonString(cell) << "\"";
                    BridgeFree(cell);
                  } else {
                    ss << "\"\"";
                  }
                }
                ss << "]";
              }
            }

            ss << "]}}";
            sendHttpResponse(clientSocket, 200, "application/json", ss.str());
          }
        } else if (path == "/status") {
          const bool isDebugging = DbgIsDebugging();
          const bool isRunning = DbgIsRunning();
          std::stringstream ss;
          ss << "{";
          ss << "\"arch\":\"" <<
#ifdef _WIN64
              "x64"
#else
              "x86"
#endif
             << "\",";
          ss << "\"debugging\":" << (isDebugging ? "true" : "false") << ",";
          ss << "\"running\":" << (isRunning ? "true" : "false") << ",";
          ss << "\"version\":\"" << PLUGIN_VERSION << "\"";
          if (isDebugging) {
            ss << ",\"currentIp\":\"0x" << std::hex
               << Script::Register::Get(REG_IP) << "\"";
          }
          ss << "}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        }
        // =============================================================================
        // REGISTER API ENDPOINTS
        // =============================================================================
        else if (path == "/register/get") {
          std::string regName = queryParams["name"];
          if (regName.empty()) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Missing register parameter");
            continue;
          }

          Script::Register::RegisterEnum reg;
          if (!tryParseRegisterName(regName, reg)) {
            sendJsonErrorResponse(clientSocket, 400, "Unknown register");
            continue;
          }

          duint value = Script::Register::Get(reg);
          std::stringstream ss;
          ss << "{\"name\":\"" << escapeJsonString(regName.c_str())
             << "\",\"value\":\"0x" << std::hex << value << "\"}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        } else if (path == "/register/set") {
          std::string regName = queryParams["name"];
          std::string valueStr = queryParams["value"];
          if (regName.empty() || valueStr.empty()) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Missing register or value parameter");
            continue;
          }

          Script::Register::RegisterEnum reg;
          if (!tryParseRegisterName(regName, reg)) {
            sendJsonErrorResponse(clientSocket, 400, "Unknown register");
            continue;
          }

          duint value = 0;
          try {
            if (valueStr.substr(0, 2) == "0x") {
              value = std::stoull(valueStr.substr(2), nullptr, 16);
            } else {
              value = std::stoull(valueStr, nullptr, 16);
            }
          } catch (const std::exception &e) {
            sendJsonErrorResponse(clientSocket, 400, "Invalid value format");
            continue;
          }

          bool success = Script::Register::Set(reg, value);
          std::stringstream ss;
          ss << "{\"success\":" << (success ? "true" : "false")
             << ",\"name\":\"" << escapeJsonString(regName.c_str())
             << "\",\"value\":\"0x" << std::hex << value << "\""
             << ",\"message\":\""
             << (success ? "Register set successfully"
                         : "Failed to set register")
             << "\"}";
          sendHttpResponse(clientSocket, success ? 200 : 500,
                           "application/json", ss.str());
        } else if (path == "/memory/read") {
          std::string addrStr =
              getRequestParam(queryParams, bodyParams, "addr");
          std::string sizeStr =
              getRequestParam(queryParams, bodyParams, "size");

          if (addrStr.empty() || sizeStr.empty()) {
            sendJsonErrorResponse(clientSocket, 400, "Missing address or size");
            continue;
          }

          duint addr = 0;
          duint size = 0;
          if (!tryParseDuint(addrStr, addr, 16) ||
              !tryParseDuint(sizeStr, size, 10)) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Invalid address or size format");
            continue;
          }

          if (size > 1024 * 1024) {
            sendJsonErrorResponse(clientSocket, 400, "Size too large");
            continue;
          }

          std::vector<unsigned char> buffer(size);
          duint sizeRead = 0;

          if (!Script::Memory::Read(addr, buffer.data(), size, &sizeRead)) {
            sendJsonErrorResponse(clientSocket, 500, "Failed to read memory");
            continue;
          }

          std::stringstream hexStream;
          for (duint i = 0; i < sizeRead; i++) {
            hexStream << std::setw(2) << std::setfill('0') << std::hex
                      << (int)buffer[i];
          }

          std::stringstream ss;
          ss << "{\"address\":\"0x" << std::hex << addr << "\","
             << "\"requestedSize\":\"0x" << std::hex << size << "\","
             << "\"bytesRead\":\"0x" << std::hex << sizeRead << "\","
             << "\"hex\":\"" << hexStream.str() << "\"}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        } else if (path == "/memory/write") {
          std::string addrStr =
              getRequestParam(queryParams, bodyParams, "addr");
          std::string dataStr =
              getRequestParam(queryParams, bodyParams, "data");
          if (dataStr.empty() && !body.empty() && bodyParams.empty()) {
            dataStr = body;
          }

          if (addrStr.empty() || dataStr.empty()) {
            sendJsonErrorResponse(clientSocket, 400, "Missing address or data");
            continue;
          }

          duint addr = 0;
          if (!tryParseDuint(addrStr, addr, 16)) {
            sendJsonErrorResponse(clientSocket, 400, "Invalid address format");
            continue;
          }

          std::string normalizedData;
          normalizedData.reserve(dataStr.size());
          for (char ch : dataStr) {
            if (!std::isspace(static_cast<unsigned char>(ch))) {
              normalizedData += ch;
            }
          }

          if (normalizedData.empty() || (normalizedData.length() % 2) != 0) {
            sendJsonErrorResponse(clientSocket, 400, "Invalid data format");
            continue;
          }

          std::vector<unsigned char> buffer;
          bool invalidData = false;
          for (size_t i = 0; i < normalizedData.length(); i += 2) {
            std::string byteString = normalizedData.substr(i, 2);
            try {
              unsigned char byte =
                  (unsigned char)std::stoi(byteString, nullptr, 16);
              buffer.push_back(byte);
            } catch (const std::exception &) {
              invalidData = true;
              break;
            }
          }

          if (invalidData) {
            sendJsonErrorResponse(clientSocket, 400, "Invalid data format");
            continue;
          }

          duint sizeWritten = 0;
          bool success = Script::Memory::Write(addr, buffer.data(),
                                               buffer.size(), &sizeWritten);
          std::stringstream ss;
          ss << "{\"success\":" << (success ? "true" : "false")
             << ",\"address\":\"0x" << std::hex << addr << "\""
             << ",\"bytesWritten\":\"0x" << std::hex << sizeWritten << "\""
             << ",\"message\":\""
             << (success ? "Memory written successfully"
                         : "Failed to write memory")
             << "\"}";
          sendHttpResponse(clientSocket, success ? 200 : 500,
                           "application/json", ss.str());
        } else if (path == "/memory/is-valid") {
          std::string addrStr = queryParams["addr"];
          if (addrStr.empty()) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Missing address parameter");
            continue;
          }

          duint addr = 0;
          try {
            if (addrStr.substr(0, 2) == "0x") {
              addr = std::stoull(addrStr.substr(2), nullptr, 16);
            } else {
              addr = std::stoull(addrStr, nullptr, 16);
            }
          } catch (const std::exception &e) {
            sendJsonErrorResponse(clientSocket, 400, "Invalid address format");
            continue;
          }

          bool isValid = Script::Memory::IsValidPtr(addr);
          std::stringstream ss;
          ss << "{\"address\":\"0x" << std::hex << addr
             << "\",\"valid\":" << (isValid ? "true" : "false") << "}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        } else if (path == "/memory/protect") {
          std::string addrStr = queryParams["addr"];
          if (addrStr.empty()) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Missing address parameter");
            continue;
          }

          duint addr = 0;
          try {
            if (addrStr.substr(0, 2) == "0x") {
              addr = std::stoull(addrStr.substr(2), nullptr, 16);
            } else {
              addr = std::stoull(addrStr, nullptr, 16);
            }
          } catch (const std::exception &e) {
            sendJsonErrorResponse(clientSocket, 400, "Invalid address format");
            continue;
          }

          unsigned int protect = Script::Memory::GetProtect(addr);
          std::stringstream ss;
          ss << "{\"address\":\"0x" << std::hex << addr << "\",\"protect\":\"0x"
             << std::hex << protect << "\"}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        } else if (path == "/memory/protect/set") {
          std::string addrStr =
              getRequestParam(queryParams, bodyParams, "addr");
          std::string rightsStr =
              getRequestParam(queryParams, bodyParams, "rights");

          if (addrStr.empty() || rightsStr.empty()) {
            sendHttpResponse(clientSocket, 400, "application/json",
                             "{\"error\":\"Missing required 'addr' or 'rights' "
                             "parameter\"}");
            continue;
          }

          duint addr = 0;
          if (!tryParseDuint(addrStr, addr, 16)) {
            sendHttpResponse(clientSocket, 400, "application/json",
                             "{\"error\":\"Invalid address format\"}");
            continue;
          }

          std::string normalizedRights;
          if (!normalizePageRights(rightsStr, normalizedRights)) {
            sendHttpResponse(
                clientSocket, 400, "application/json",
                "{\"error\":\"Invalid rights format. Use values like rwx, rx, "
                "rw, ERW, ER, RW, ReadOnly or ExecuteReadWrite\"}");
            continue;
          }

          const DBGFUNCTIONS *dbgFunc = DbgFunctions();
          if (!dbgFunc || !dbgFunc->SetPageRights) {
            sendHttpResponse(clientSocket, 500, "application/json",
                             "{\"error\":\"SetPageRights not available\"}");
            continue;
          }

          bool success = dbgFunc->SetPageRights(addr, normalizedRights.c_str());
          std::stringstream ss;
          ss << "{\"success\":" << (success ? "true" : "false") << ","
             << "\"address\":\"0x" << std::hex << addr << "\","
             << "\"rights\":\"" << normalizedRights << "\"}";

          sendHttpResponse(clientSocket, success ? 200 : 500,
                           "application/json", ss.str());
        }

        // =============================================================================
        // DEBUG API ENDPOINTS
        // =============================================================================
        else if (path == "/debug/run") {
          if (!DbgIsDebugging()) {
            sendJsonMessageResponse(clientSocket, 200, false,
                                    "No active debug session");
            continue;
          }

          if (DbgIsRunning()) {
            sendJsonMessageResponse(clientSocket, 200, false,
                                    "Debugger already running");
            continue;
          }

          bool queued = DbgCmdExec("run");
          sendJsonMessageResponse(clientSocket, queued ? 200 : 500, queued,
                                  queued ? "Debug run queued"
                                         : "Failed to queue debug run");
        } else if (path == "/debug/pause") {
          Script::Debug::Pause();
          sendJsonMessageResponse(clientSocket, 200, true,
                                  "Debug pause executed");
        } else if (path == "/debug/stop") {
          Script::Debug::Stop();
          sendJsonMessageResponse(clientSocket, 200, true,
                                  "Debug stop executed");
        } else if (path == "/debug/step-in") {
          Script::Debug::StepIn();
          sendJsonMessageResponse(clientSocket, 200, true, "Step in executed");
        } else if (path == "/debug/step-over") {
          Script::Debug::StepOver();
          sendJsonMessageResponse(clientSocket, 200, true,
                                  "Step over executed");
        } else if (path == "/debug/step-out") {
          Script::Debug::StepOut();
          sendJsonMessageResponse(clientSocket, 200, true, "Step out executed");
        } else if (path == "/breakpoint/set") {
          std::string addrStr =
              getRequestParam(queryParams, bodyParams, "addr");
          if (addrStr.empty()) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Missing address parameter");
            continue;
          }

          duint addr = 0;
          if (!tryParseDuint(addrStr, addr, 16)) {
            sendJsonErrorResponse(clientSocket, 400, "Invalid address format");
            continue;
          }

          bool success = Script::Debug::SetBreakpoint(addr);
          std::stringstream ss;
          ss << "{\"success\":" << (success ? "true" : "false")
             << ",\"address\":\"0x" << std::hex << addr << "\""
             << ",\"message\":\""
             << (success ? "Breakpoint set successfully"
                         : "Failed to set breakpoint")
             << "\"}";
          sendHttpResponse(clientSocket, success ? 200 : 500,
                           "application/json", ss.str());
        } else if (path == "/breakpoint/delete") {
          std::string addrStr =
              getRequestParam(queryParams, bodyParams, "addr");
          if (addrStr.empty()) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Missing address parameter");
            continue;
          }

          duint addr = 0;
          if (!tryParseDuint(addrStr, addr, 16)) {
            sendJsonErrorResponse(clientSocket, 400, "Invalid address format");
            continue;
          }

          bool success = Script::Debug::DeleteBreakpoint(addr);
          std::stringstream ss;
          ss << "{\"success\":" << (success ? "true" : "false")
             << ",\"address\":\"0x" << std::hex << addr << "\""
             << ",\"message\":\""
             << (success ? "Breakpoint deleted successfully"
                         : "Failed to delete breakpoint")
             << "\"}";
          sendHttpResponse(clientSocket, success ? 200 : 500,
                           "application/json", ss.str());
        }

        else if (path == "/assembler/assemble") {
          std::string addrStr = queryParams["addr"];
          std::string instruction = queryParams["instruction"];
          if (instruction.empty() && !body.empty()) {
            instruction = body;
          }

          if (addrStr.empty() || instruction.empty()) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Missing address or instruction parameter");
            continue;
          }

          duint addr = 0;
          try {
            if (addrStr.substr(0, 2) == "0x") {
              addr = std::stoull(addrStr.substr(2), nullptr, 16);
            } else {
              addr = std::stoull(addrStr, nullptr, 16);
            }
          } catch (const std::exception &e) {
            sendJsonErrorResponse(clientSocket, 400, "Invalid address format");
            continue;
          }

          unsigned char dest[16];
          int size = 16;
          bool success = Script::Assembler::Assemble(addr, dest, &size,
                                                     instruction.c_str());

          if (success) {
            std::stringstream ss;
            ss << "{\"success\":true,\"size\":" << size << ",\"bytes\":\"";
            for (int i = 0; i < size; i++) {
              ss << std::setw(2) << std::setfill('0') << std::hex
                 << (int)dest[i];
            }
            ss << "\"}";
            sendHttpResponse(clientSocket, 200, "application/json", ss.str());
          } else {
            sendJsonErrorResponse(clientSocket, 500,
                                  "Failed to assemble instruction");
          }
        } else if (path == "/assembler/write") {
          std::string addrStr = queryParams["addr"];
          std::string instruction = queryParams["instruction"];
          if (instruction.empty() && !body.empty()) {
            instruction = body;
          }

          if (addrStr.empty() || instruction.empty()) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Missing address or instruction parameter");
            continue;
          }

          duint addr = 0;
          try {
            if (addrStr.substr(0, 2) == "0x") {
              addr = std::stoull(addrStr.substr(2), nullptr, 16);
            } else {
              addr = std::stoull(addrStr, nullptr, 16);
            }
          } catch (const std::exception &e) {
            sendJsonErrorResponse(clientSocket, 400, "Invalid address format");
            continue;
          }

          bool success =
              Script::Assembler::AssembleMem(addr, instruction.c_str());
          std::stringstream ss;
          ss << "{\"success\":" << (success ? "true" : "false")
             << ",\"address\":\"0x" << std::hex << addr << "\""
             << ",\"message\":\""
             << (success ? "Instruction assembled in memory successfully"
                         : "Failed to assemble instruction in memory")
             << "\"}";
          sendHttpResponse(clientSocket, success ? 200 : 500,
                           "application/json", ss.str());
        } else if (path == "/stack/pop") {
          duint value = Script::Stack::Pop();
          std::stringstream ss;
          ss << "{\"value\":\"0x" << std::hex << value << "\"}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        } else if (path == "/stack/push") {
          std::string valueStr = queryParams["value"];
          if (valueStr.empty()) {
            sendJsonErrorResponse(clientSocket, 400, "Missing value parameter");
            continue;
          }

          duint value = 0;
          try {
            if (valueStr.substr(0, 2) == "0x") {
              value = std::stoull(valueStr.substr(2), nullptr, 16);
            } else {
              value = std::stoull(valueStr, nullptr, 16);
            }
          } catch (const std::exception &e) {
            sendJsonErrorResponse(clientSocket, 400, "Invalid value format");
            continue;
          }

          duint prevTop = Script::Stack::Push(value);
          std::stringstream ss;
          ss << "{\"previousTop\":\"0x" << std::hex << prevTop << "\"}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        } else if (path == "/stack/peek") {
          std::string offsetStr = queryParams["offset"];
          int offset = 0;
          if (!offsetStr.empty()) {
            try {
              offset = std::stoi(offsetStr);
            } catch (const std::exception &e) {
              sendJsonErrorResponse(clientSocket, 400, "Invalid offset format");
              continue;
            }
          }

          duint value = Script::Stack::Peek(offset);
          std::stringstream ss;
          ss << "{\"offset\":" << std::dec << offset << ",\"value\":\"0x"
             << std::hex << value << "\"}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        } else if (path == "/disasm/instruction") {
          std::string addrStr = queryParams["addr"];
          if (addrStr.empty()) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Missing address parameter");
            continue;
          }

          duint addr = 0;
          try {
            if (addrStr.substr(0, 2) == "0x") {
              addr = std::stoull(addrStr.substr(2), nullptr, 16);
            } else {
              addr = std::stoull(addrStr, nullptr, 16);
            }
          } catch (const std::exception &e) {
            sendJsonErrorResponse(clientSocket, 400, "Invalid address format");
            continue;
          }

          DISASM_INSTR instr;
          bool found = tryDisasmInstruction(addr, instr);

          std::stringstream ss;
          appendDisasmInstructionJson(ss, addr, instr, found);

          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        } else if (path == "/disasm/range") {
          std::string addrStr = queryParams["addr"];
          std::string countStr = queryParams["count"];

          if (addrStr.empty()) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Missing address parameter");
            continue;
          }

          duint addr = 0;
          int count = 1;

          try {
            if (addrStr.substr(0, 2) == "0x") {
              addr = std::stoull(addrStr.substr(2), nullptr, 16);
            } else {
              addr = std::stoull(addrStr, nullptr, 16);
            }

            if (!countStr.empty()) {
              count = std::stoi(countStr);
            }
          } catch (const std::exception &e) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Invalid address or count format");
            continue;
          }

          if (count <= 0 || count > 100) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Count must be between 1 and 100");
            continue;
          }

          // Get multiple instructions
          std::stringstream ss;
          ss << "[";

          duint currentAddr = addr;
          bool appended = false;
          for (int i = 0; i < count; i++) {
            DISASM_INSTR instr;
            bool found = tryDisasmInstruction(currentAddr, instr);

            if (found) {
              if (appended)
                ss << ",";
              appendDisasmInstructionJson(ss, currentAddr, instr, true);
              appended = true;
              currentAddr += instr.instr_size;
            } else {
              break;
            }
          }

          ss << "]";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        } else if (path == "/disasm/step-into") {
          // Step in first
          Script::Debug::StepIn();

          // Then get current instruction
          duint rip = Script::Register::Get(REG_IP);

          DISASM_INSTR instr;
          bool found = tryDisasmInstruction(rip, instr);

          // Create JSON response
          std::stringstream ss;
          ss << "{";
          ss << "\"step_result\":\"Step in executed\",";
          ss << "\"rip\":\"0x" << std::hex << rip << "\",";
          ss << "\"instruction\":\"" << escapeJsonString(instr.instruction)
             << "\",";
          ss << "\"size\":" << std::dec << instr.instr_size << ",";
          ss << "\"found\":" << (found ? "true" : "false");
          ss << "}";

          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        }
        // =============================================================================
        // FLAG API ENDPOINTS
        // =============================================================================
        else if (path == "/flag/get") {
          std::string flagName = getRequestParam(queryParams, bodyParams, "flag");
          if (flagName.empty()) {
            sendJsonErrorResponse(clientSocket, 400, "Missing flag parameter");
            continue;
          }

          int bitIndex = -1;
          if (!tryParseFlagBitIndex(flagName, bitIndex)) {
            sendJsonErrorResponse(clientSocket, 400, "Unknown flag");
            continue;
          }

          ULONG_PTR cflags = 0;
          if (!readContextDataOnGuiThread(UE_CFLAGS, cflags)) {
            sendJsonErrorResponse(clientSocket, 500, "Failed to read flags");
            continue;
          }

          bool value = ((cflags >> bitIndex) & 1) != 0;
          std::stringstream ss;
          ss << "{\"flag\":\"" << flagName
             << "\",\"value\":" << (value ? "true" : "false") << "}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        } else if (path == "/flag/set") {
          std::string flagName = getRequestParam(queryParams, bodyParams, "flag");
          std::string valueStr = getRequestParam(queryParams, bodyParams, "value");
          if (flagName.empty() || valueStr.empty()) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Missing flag or value parameter");
            continue;
          }

          std::string normalizedValue = valueStr;
          std::transform(normalizedValue.begin(), normalizedValue.end(),
                         normalizedValue.begin(),
                         [](unsigned char ch) {
                           return static_cast<char>(std::tolower(ch));
                         });

          bool value = (normalizedValue == "true" || normalizedValue == "1");
          int bitIndex = -1;
          if (!tryParseFlagBitIndex(flagName, bitIndex)) {
            sendJsonErrorResponse(clientSocket, 400, "Unknown flag");
            continue;
          }

          bool success = false;
          HANDLE threadHandle = DbgGetThreadHandle();
          if (threadHandle != nullptr) {
            ULONG_PTR cflags = GetContextDataEx(threadHandle, UE_CFLAGS);
            if (value)
              cflags |= static_cast<ULONG_PTR>(1) << bitIndex;
            else
              cflags &= ~(static_cast<ULONG_PTR>(1) << bitIndex);

            success = SetContextDataEx(threadHandle, UE_CFLAGS, cflags);
            if (success) {
              GuiUpdateRegisterView();
            }
          }

          std::stringstream ss;
          ss << "{\"success\":" << (success ? "true" : "false")
             << ",\"flag\":\"" << flagName << "\""
             << ",\"value\":" << (value ? "true" : "false") << ",\"message\":\""
             << (success ? "Flag set successfully" : "Failed to set flag")
             << "\"}";
          sendHttpResponse(clientSocket, success ? 200 : 500,
                           "application/json", ss.str());
        }

        // =============================================================================
        // PATTERN API ENDPOINTS
        // =============================================================================
        else if (path == "/pattern/find") {
          std::string startStr = queryParams["start"];
          std::string sizeStr = queryParams["size"];
          std::string pattern = queryParams["pattern"];
          std::string Pattern = urlDecode(pattern);
          if (startStr.empty() || sizeStr.empty() || pattern.empty()) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Missing start, size, or pattern parameter");
            continue;
          }

          duint start = 0, size = 0;

          Pattern.erase(
              std::remove_if(pattern.begin(), pattern.end(),
                             [](unsigned char c) { return std::isspace(c); }),
              Pattern.end());

          try {
            if (startStr.substr(0, 2) == "0x") {
              start = std::stoull(startStr.substr(2), nullptr, 16);
            } else {
              start = std::stoull(startStr, nullptr, 16);
            }
            if (sizeStr.substr(0, 2) == "0x") {
              size = std::stoull(sizeStr.substr(2), nullptr, 16);
            } else {
              size = std::stoull(sizeStr, nullptr, 16);
            }
          } catch (const std::exception &e) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Invalid start or size format");
            continue;
          }

          duint result = Script::Pattern::FindMem(start, size, Pattern.c_str());
          if (result != 0) {
            std::stringstream ss;
            ss << "{\"found\":true,\"address\":\"0x" << std::hex << result
               << "\"}";
            sendHttpResponse(clientSocket, 200, "application/json", ss.str());
          } else {
            sendJsonErrorResponse(clientSocket, 404, "Pattern not found");
          }
        }

        else if (path == "/expression/parse") {
          std::string expression = queryParams["expression"];
          if (expression.empty() && !body.empty()) {
            expression = body;
          }

          if (expression.empty()) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Missing expression parameter");
            continue;
          }

          duint value = 0;
          bool success =
              Script::Misc::ParseExpression(expression.c_str(), &value);

          if (success) {
            std::stringstream ss;
            ss << "{\"expression\":\"" << escapeJsonString(expression.c_str())
               << "\",\"value\":\"0x" << std::hex << value << "\"}";
            sendHttpResponse(clientSocket, 200, "application/json", ss.str());
          } else {
            sendJsonErrorResponse(clientSocket, 500,
                                  "Failed to parse expression");
          }
        } else if (path == "/module/proc-address") {
          std::string module = queryParams["module"];
          std::string api = queryParams["api"];

          if (module.empty() || api.empty()) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Missing module or api parameter");
            continue;
          }

          duint addr =
              Script::Misc::RemoteGetProcAddress(module.c_str(), api.c_str());
          if (addr != 0) {
            std::stringstream ss;
            ss << "{\"module\":\"" << escapeJsonString(module.c_str()) << "\","
               << "\"api\":\"" << escapeJsonString(api.c_str()) << "\","
               << "\"address\":\"0x" << std::hex << addr << "\"}";
            sendHttpResponse(clientSocket, 200, "application/json", ss.str());
          } else {
            sendJsonErrorResponse(clientSocket, 404, "Function not found");
          }
        } else if (path == "/module/by-address") {
          std::string addrStr = queryParams["addr"];
          if (addrStr.empty() && !body.empty()) {
            addrStr = body;
          }
          _plugin_logprintf("MemoryBase endpoint called with addr: %s\n",
                            addrStr.c_str());
          // Convert string address to duint
          duint addr = 0;
          try {
            addr = std::stoull(addrStr, nullptr, 16); // Parse as hex
          } catch (const std::exception &e) {
            sendJsonErrorResponse(clientSocket, 400, "Invalid address format");
            continue;
          }
          _plugin_logprintf("Converted address: " FMT_DUINT_HEX "\n",
                            DUINT_CAST_PRINTF(addr));

          // Get the base address and size
          duint size = 0;
          duint baseAddr = DbgMemFindBaseAddr(addr, &size);
          _plugin_logprintf("Base address found: " FMT_DUINT_HEX
                            ", size: " FMT_DUINT_DEC "\n",
                            DUINT_CAST_PRINTF(baseAddr),
                            DUSIZE_CAST_PRINTF(size));
          if (baseAddr == 0) {
            sendJsonErrorResponse(clientSocket, 404,
                                  "No module found for this address");
          } else {
            // Format the response as JSON
            std::stringstream ss;
            ss << "{\"base_address\":\"0x" << std::hex << baseAddr
               << "\",\"size\":\"0x" << std::hex << size << "\"}";
            sendHttpResponse(clientSocket, 200, "application/json", ss.str());
          }
        } else if (path == "/modules") {
          // Create a list to store the module information
          ListInfo moduleList;

          // Get the list of modules
          bool success = Script::Module::GetList(&moduleList);

          if (!success) {
            sendJsonErrorResponse(clientSocket, 500,
                                  "Failed to get module list");
          } else {
            // Create a JSON array to hold the module information
            std::stringstream jsonResponse;
            jsonResponse << "[";

            // Iterate through each module in the list
            size_t count = moduleList.count;
            Script::Module::ModuleInfo *modules =
                (Script::Module::ModuleInfo *)moduleList.data;

            for (size_t i = 0; i < count; i++) {
              if (i > 0)
                jsonResponse << ",";

              // Add module info as JSON object
              jsonResponse << "{";
              jsonResponse << "\"name\":\"" << escapeJsonString(modules[i].name)
                           << "\",";
              jsonResponse << "\"base\":\"0x" << std::hex << modules[i].base
                           << "\",";
              jsonResponse << "\"size\":\"0x" << std::hex << modules[i].size
                           << "\",";
              jsonResponse << "\"entry\":\"0x" << std::hex << modules[i].entry
                           << "\",";
              jsonResponse << "\"sectionCount\":" << std::dec
                           << modules[i].sectionCount << ",";
              jsonResponse << "\"path\":\"" << escapeJsonString(modules[i].path)
                           << "\"";
              jsonResponse << "}";
            }

            jsonResponse << "]";

            // Free the list
            BridgeFree(moduleList.data);

            // Send the response
            sendHttpResponse(clientSocket, 200, "application/json",
                             jsonResponse.str());
          }
        }
        // =============================================================================
        // SYMBOL ENUMERATION ENDPOINT
        // =============================================================================
        else if (path == "/symbols") {
          // Module name is required to keep response sizes manageable
          std::string moduleFilter = queryParams["module"];
          if (moduleFilter.empty()) {
            sendHttpResponse(
                clientSocket, 400, "application/json",
                "{\"error\":\"Missing required 'module' parameter. Use "
                "GetModuleList to discover module names.\"}");
            continue;
          }

          // Parse pagination parameters
          std::string offsetStr = queryParams["offset"];
          std::string limitStr = queryParams["limit"];

          int offset = 0;
          int limit = 5000;

          if (!offsetStr.empty()) {
            try {
              offset = std::stoi(offsetStr);
            } catch (...) {
              offset = 0;
            }
          }
          if (!limitStr.empty()) {
            try {
              limit = std::stoi(limitStr);
            } catch (...) {
              limit = 5000;
            }
          }

          // Clamp values
          if (offset < 0)
            offset = 0;
          if (limit <= 0)
            limit = 5000;
          if (limit > 50000)
            limit = 50000;

          std::string moduleFilterDecoded = urlDecode(moduleFilter);

          // Get all symbols using Script::Symbol::GetList
          ListInfo symbolList;
          bool success = Script::Symbol::GetList(&symbolList);

          if (!success || symbolList.data == nullptr) {
            sendHttpResponse(clientSocket, 500, "application/json",
                             "{\"error\":\"Failed to enumerate "
                             "symbols\",\"symbols\":[],\"total\":0}");
            continue;
          }

          size_t totalCount = symbolList.count;
          Script::Symbol::SymbolInfo *symbols =
              (Script::Symbol::SymbolInfo *)symbolList.data;

          _plugin_logprintf("SymbolEnum: module='%s', total symbols from "
                            "GetList = %llu, offset=%d, limit=%d\n",
                            moduleFilterDecoded.c_str(),
                            (unsigned long long)totalCount, offset, limit);

          // Build JSON response - filter to requested module only
          std::stringstream jsonResponse;

          int matchIndex = 0;    // Index among matching symbols
          int emitted = 0;       // Number of symbols emitted in this page
          int filteredTotal = 0; // Total matching symbols for this module

          // First pass: count total matching symbols for this module
          for (size_t i = 0; i < totalCount; i++) {
            if (_stricmp(symbols[i].mod, moduleFilterDecoded.c_str()) == 0) {
              filteredTotal++;
            }
          }

          // Write header
          jsonResponse << "{\"total\":" << filteredTotal << ",\"module\":\""
                       << escapeJsonString(moduleFilterDecoded.c_str()) << "\""
                       << ",\"offset\":" << offset << ",\"limit\":" << limit
                       << ",\"symbols\":[";

          // Second pass: emit symbols with pagination
          for (size_t i = 0; i < totalCount && emitted < limit; i++) {
            // Filter to requested module
            if (_stricmp(symbols[i].mod, moduleFilterDecoded.c_str()) != 0) {
              continue;
            }

            // Apply offset (skip first N matching symbols)
            if (matchIndex < offset) {
              matchIndex++;
              continue;
            }
            matchIndex++;

            // Determine type string
            const char *typeStr = "unknown";
            switch (symbols[i].type) {
            case Script::Symbol::Function:
              typeStr = "function";
              break;
            case Script::Symbol::Import:
              typeStr = "import";
              break;
            case Script::Symbol::Export:
              typeStr = "export";
              break;
            }

            if (emitted > 0)
              jsonResponse << ",";

            jsonResponse << "{"
                         << "\"rva\":\"0x" << std::hex << symbols[i].rva
                         << "\","
                         << "\"name\":\"" << escapeJsonString(symbols[i].name)
                         << "\","
                         << "\"manual\":"
                         << (symbols[i].manual ? "true" : "false") << ","
                         << "\"type\":\"" << typeStr << "\""
                         << "}";

            emitted++;
          }

          jsonResponse << "]}";

          // Free the list
          BridgeFree(symbolList.data);

          _plugin_logprintf(
              "SymbolEnum: returned %d symbols for '%s' (module total: %d)\n",
              emitted, moduleFilterDecoded.c_str(), filteredTotal);

          sendHttpResponse(clientSocket, 200, "application/json",
                           jsonResponse.str());
        }
        // =============================================================================
        // THREAD API ENDPOINTS
        // =============================================================================
        else if (path == "/threads") {
          THREADLIST threadList;
          memset(&threadList, 0, sizeof(threadList));
          DbgGetThreadList(&threadList);

          if (threadList.count == 0 || threadList.list == nullptr) {
            sendHttpResponse(
                clientSocket, 200, "application/json",
                "{\"count\":0,\"currentThread\":-1,\"threads\":[]}");
            continue;
          }

          std::stringstream jsonResponse;
          jsonResponse << "{\"count\":" << threadList.count
                       << ",\"currentThread\":" << threadList.CurrentThread
                       << ",\"threads\":[";

          for (int i = 0; i < threadList.count; i++) {
            THREADALLINFO &t = threadList.list[i];

            if (i > 0)
              jsonResponse << ",";

            // Map priority enum to readable string
            const char *priorityStr = "Unknown";
            switch (t.Priority) {
            case _PriorityIdle:
              priorityStr = "Idle";
              break;
            case _PriorityAboveNormal:
              priorityStr = "AboveNormal";
              break;
            case _PriorityBelowNormal:
              priorityStr = "BelowNormal";
              break;
            case _PriorityHighest:
              priorityStr = "Highest";
              break;
            case _PriorityLowest:
              priorityStr = "Lowest";
              break;
            case _PriorityNormal:
              priorityStr = "Normal";
              break;
            case _PriorityTimeCritical:
              priorityStr = "TimeCritical";
              break;
            default:
              break;
            }

            // Map wait reason enum to readable string
            const char *waitStr = "Unknown";
            switch (t.WaitReason) {
            case _Executive:
              waitStr = "Executive";
              break;
            case _FreePage:
              waitStr = "FreePage";
              break;
            case _PageIn:
              waitStr = "PageIn";
              break;
            case _PoolAllocation:
              waitStr = "PoolAllocation";
              break;
            case _DelayExecution:
              waitStr = "DelayExecution";
              break;
            case _Suspended:
              waitStr = "Suspended";
              break;
            case _UserRequest:
              waitStr = "UserRequest";
              break;
            case _WrExecutive:
              waitStr = "WrExecutive";
              break;
            case _WrFreePage:
              waitStr = "WrFreePage";
              break;
            case _WrPageIn:
              waitStr = "WrPageIn";
              break;
            case _WrPoolAllocation:
              waitStr = "WrPoolAllocation";
              break;
            case _WrDelayExecution:
              waitStr = "WrDelayExecution";
              break;
            case _WrSuspended:
              waitStr = "WrSuspended";
              break;
            case _WrUserRequest:
              waitStr = "WrUserRequest";
              break;
            case _WrQueue:
              waitStr = "WrQueue";
              break;
            case _WrLpcReceive:
              waitStr = "WrLpcReceive";
              break;
            case _WrLpcReply:
              waitStr = "WrLpcReply";
              break;
            case _WrVirtualMemory:
              waitStr = "WrVirtualMemory";
              break;
            case _WrPageOut:
              waitStr = "WrPageOut";
              break;
            case _WrRendezvous:
              waitStr = "WrRendezvous";
              break;
            default:
              break;
            }

            jsonResponse << "{"
                         << "\"threadNumber\":" << t.BasicInfo.ThreadNumber
                         << ","
                         << "\"threadId\":" << std::dec << t.BasicInfo.ThreadId
                         << ","
                         << "\"threadName\":\""
                         << escapeJsonString(t.BasicInfo.threadName) << "\","
                         << "\"startAddress\":\"0x" << std::hex
                         << t.BasicInfo.ThreadStartAddress << "\","
                         << "\"localBase\":\"0x" << std::hex
                         << t.BasicInfo.ThreadLocalBase << "\","
                         << "\"cip\":\"0x" << std::hex << t.ThreadCip << "\","
                         << "\"suspendCount\":" << std::dec << t.SuspendCount
                         << ","
                         << "\"priority\":\"" << priorityStr << "\","
                         << "\"waitReason\":\"" << waitStr << "\","
                         << "\"lastError\":" << std::dec << t.LastError << ","
                         << "\"cycles\":" << std::dec << t.Cycles << "}";
          }

          jsonResponse << "]}";

          // Free the thread list
          BridgeFree(threadList.list);

          sendHttpResponse(clientSocket, 200, "application/json",
                           jsonResponse.str());
        } else if (path == "/thread/teb") {
          std::string tidStr = queryParams["tid"];
          if (tidStr.empty()) {
            sendJsonErrorResponse(clientSocket, 400,
                                  "Missing 'tid' parameter (thread ID)");
            continue;
          }

          DWORD tid = 0;
          try {
            tid = (DWORD)std::stoul(tidStr, nullptr, 0);
          } catch (const std::exception &e) {
            sendJsonErrorResponse(clientSocket, 400, "Invalid tid format");
            continue;
          }

          duint tebAddr = DbgGetTebAddress(tid);
          if (tebAddr == 0) {
            sendHttpResponse(
                clientSocket, 404, "application/json",
                "{\"error\":\"TEB not found for given thread ID\"}");
            continue;
          }

          std::stringstream ss;
          ss << "{\"tid\":" << std::dec << tid << ",\"tebAddress\":\"0x"
             << std::hex << tebAddr << "\"}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        }
        // =============================================================================
        // STRING API ENDPOINTS
        // =============================================================================
        else if (path == "/string/at") {
          std::string addrStr = queryParams["addr"];
          if (addrStr.empty()) {
            sendHttpResponse(
                clientSocket, 400, "application/json",
                "{\"error\":\"Missing required 'addr' parameter\"}");
            continue;
          }

          duint addr = 0;
          try {
            addr = std::stoull(addrStr, nullptr, 16);
          } catch (const std::exception &e) {
            sendHttpResponse(clientSocket, 400, "application/json",
                             "{\"error\":\"Invalid address format\"}");
            continue;
          }

          char text[MAX_STRING_SIZE] = {0};
          bool found = DbgGetStringAt(addr, text);

          std::stringstream ss;
          ss << "{\"address\":\"0x" << std::hex << addr << "\","
             << "\"found\":" << (found ? "true" : "false") << ","
             << "\"string\":\"" << escapeJsonString(text) << "\"}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        }
        // =============================================================================
        // XREF API ENDPOINTS
        // =============================================================================
        else if (path == "/xref/list") {
          std::string addrStr = queryParams["addr"];
          if (addrStr.empty()) {
            sendHttpResponse(
                clientSocket, 400, "application/json",
                "{\"error\":\"Missing required 'addr' parameter\"}");
            continue;
          }

          duint addr = 0;
          try {
            addr = std::stoull(addrStr, nullptr, 16);
          } catch (const std::exception &e) {
            sendHttpResponse(clientSocket, 400, "application/json",
                             "{\"error\":\"Invalid address format\"}");
            continue;
          }

          XREF_INFO xrefInfo = {0};
          bool success = DbgXrefGet(addr, &xrefInfo);

          std::stringstream ss;
          ss << "{\"address\":\"0x" << std::hex << addr << "\","
             << "\"refcount\":" << std::dec << (success ? xrefInfo.refcount : 0)
             << ","
             << "\"references\":[";

          if (success && xrefInfo.references != nullptr) {
            for (duint i = 0; i < xrefInfo.refcount; i++) {
              if (i > 0)
                ss << ",";

              const char *typeStr = "none";
              switch (xrefInfo.references[i].type) {
              case XREF_DATA:
                typeStr = "data";
                break;
              case XREF_JMP:
                typeStr = "jmp";
                break;
              case XREF_CALL:
                typeStr = "call";
                break;
              default:
                typeStr = "none";
                break;
              }

              // Also try to get the string at the target address for context
              char refString[MAX_STRING_SIZE] = {0};
              DbgGetStringAt(xrefInfo.references[i].addr, refString);

              ss << "{\"addr\":\"0x" << std::hex << xrefInfo.references[i].addr
                 << "\","
                 << "\"type\":\"" << typeStr << "\"";

              if (refString[0] != '\0') {
                ss << ",\"string\":\"" << escapeJsonString(refString) << "\"";
              }

              ss << "}";
            }

            // Free the references array
            BridgeFree(xrefInfo.references);
          }

          ss << "]}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        } else if (path == "/xref/count") {
          std::string addrStr = queryParams["addr"];
          if (addrStr.empty()) {
            sendHttpResponse(
                clientSocket, 400, "application/json",
                "{\"error\":\"Missing required 'addr' parameter\"}");
            continue;
          }

          duint addr = 0;
          try {
            addr = std::stoull(addrStr, nullptr, 16);
          } catch (const std::exception &e) {
            sendHttpResponse(clientSocket, 400, "application/json",
                             "{\"error\":\"Invalid address format\"}");
            continue;
          }

          size_t count = DbgGetXrefCountAt(addr);

          std::stringstream ss;
          ss << "{\"address\":\"0x" << std::hex << addr << "\","
             << "\"count\":" << std::dec << count << "}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        }
        // =============================================================================
        // MEMORY MAP ENDPOINT
        // =============================================================================
        else if (path == "/memory/map") {
          MEMMAP memmap;
          memset(&memmap, 0, sizeof(memmap));
          bool success = DbgMemMap(&memmap);

          if (!success || memmap.page == nullptr || memmap.count == 0) {
            sendHttpResponse(
                clientSocket, 500, "application/json",
                "{\"error\":\"Failed to get memory map\",\"pages\":[]}");
            continue;
          }

          std::stringstream ss;
          ss << "{\"count\":" << memmap.count << ",\"pages\":[";

          for (int i = 0; i < memmap.count; i++) {
            if (i > 0)
              ss << ",";
            MEMPAGE &p = memmap.page[i];

            // Decode protection to string
            const char *protectStr = "---";
            DWORD prot = p.mbi.Protect & 0xFF;
            if (prot == PAGE_EXECUTE_READWRITE)
              protectStr = "ERW";
            else if (prot == PAGE_EXECUTE_READ)
              protectStr = "ER-";
            else if (prot == PAGE_EXECUTE_WRITECOPY)
              protectStr = "ERW";
            else if (prot == PAGE_READWRITE)
              protectStr = "-RW";
            else if (prot == PAGE_READONLY)
              protectStr = "-R-";
            else if (prot == PAGE_WRITECOPY)
              protectStr = "-RW";
            else if (prot == PAGE_EXECUTE)
              protectStr = "E--";
            else if (prot == PAGE_NOACCESS)
              protectStr = "---";

            // Decode type
            const char *typeStr = "Unknown";
            if (p.mbi.Type == MEM_IMAGE)
              typeStr = "IMG";
            else if (p.mbi.Type == MEM_MAPPED)
              typeStr = "MAP";
            else if (p.mbi.Type == MEM_PRIVATE)
              typeStr = "PRV";

            ss << "{\"base\":\"0x" << std::hex << (duint)p.mbi.BaseAddress
               << "\","
               << "\"size\":\"0x" << std::hex << p.mbi.RegionSize << "\","
               << "\"protect\":\"" << protectStr << "\","
               << "\"type\":\"" << typeStr << "\","
               << "\"info\":\"" << escapeJsonString(p.info) << "\"}";
          }

          ss << "]}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        }
        // =============================================================================
        // REMOTE MEMORY ALLOC/FREE ENDPOINTS
        // =============================================================================
        else if (path == "/memory/alloc") {
          std::string addrStr = queryParams["addr"];
          std::string sizeStr = queryParams["size"];

          if (sizeStr.empty()) {
            sendHttpResponse(
                clientSocket, 400, "application/json",
                "{\"error\":\"Missing required 'size' parameter\"}");
            continue;
          }

          duint addr = 0;
          duint size = 0;
          try {
            if (!addrStr.empty())
              addr = std::stoull(addrStr, nullptr, 16);
            size = std::stoull(sizeStr, nullptr, 16);
          } catch (const std::exception &e) {
            sendHttpResponse(clientSocket, 400, "application/json",
                             "{\"error\":\"Invalid parameter format\"}");
            continue;
          }

          duint result = Script::Memory::RemoteAlloc(addr, size);

          if (result == 0) {
            sendHttpResponse(clientSocket, 500, "application/json",
                             "{\"error\":\"RemoteAlloc failed\"}");
          } else {
            std::stringstream ss;
            ss << "{\"address\":\"0x" << std::hex << result << "\","
               << "\"size\":\"0x" << std::hex << size << "\"}";
            sendHttpResponse(clientSocket, 200, "application/json", ss.str());
          }
        } else if (path == "/memory/free") {
          std::string addrStr = queryParams["addr"];
          if (addrStr.empty()) {
            sendHttpResponse(
                clientSocket, 400, "application/json",
                "{\"error\":\"Missing required 'addr' parameter\"}");
            continue;
          }

          duint addr = 0;
          try {
            addr = std::stoull(addrStr, nullptr, 16);
          } catch (const std::exception &e) {
            sendHttpResponse(clientSocket, 400, "application/json",
                             "{\"error\":\"Invalid address format\"}");
            continue;
          }

          bool success = Script::Memory::RemoteFree(addr);
          std::stringstream ss;
          ss << "{\"success\":" << (success ? "true" : "false") << "}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        }
        // =============================================================================
        // BRANCH DESTINATION ENDPOINT
        // =============================================================================
        else if (path == "/branch/destination") {
          std::string addrStr = queryParams["addr"];
          if (addrStr.empty()) {
            sendHttpResponse(
                clientSocket, 400, "application/json",
                "{\"error\":\"Missing required 'addr' parameter\"}");
            continue;
          }

          duint addr = 0;
          try {
            addr = std::stoull(addrStr, nullptr, 16);
          } catch (const std::exception &e) {
            sendHttpResponse(clientSocket, 400, "application/json",
                             "{\"error\":\"Invalid address format\"}");
            continue;
          }

          duint dest = DbgGetBranchDestination(addr);

          std::stringstream ss;
          ss << "{\"address\":\"0x" << std::hex << addr << "\","
             << "\"destination\":\"0x" << std::hex << dest << "\","
             << "\"resolved\":" << (dest != 0 ? "true" : "false") << "}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        }
        // =============================================================================
        // CALL STACK ENDPOINT
        // =============================================================================
        else if (path == "/callstack") {
          const DBGFUNCTIONS *dbgFunc = DbgFunctions();
          if (!dbgFunc || !dbgFunc->GetCallStackEx) {
            sendHttpResponse(clientSocket, 500, "application/json",
                             "{\"error\":\"GetCallStackEx not available\"}");
            continue;
          }

          DBGCALLSTACK callstack;
          memset(&callstack, 0, sizeof(callstack));
          dbgFunc->GetCallStackEx(&callstack, true);

          std::stringstream ss;
          ss << "{\"total\":" << callstack.total << ",\"entries\":[";

          if (callstack.entries != nullptr) {
            for (int i = 0; i < callstack.total; i++) {
              if (i > 0)
                ss << ",";
              DBGCALLSTACKENTRY &e = callstack.entries[i];
              ss << "{\"addr\":\"0x" << std::hex << e.addr << "\","
                 << "\"from\":\"0x" << std::hex << e.from << "\","
                 << "\"to\":\"0x" << std::hex << e.to << "\","
                 << "\"comment\":\"" << escapeJsonString(e.comment) << "\"}";
            }
            BridgeFree(callstack.entries);
          }

          ss << "]}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        }
        // =============================================================================
        // BREAKPOINT LIST ENDPOINT
        // =============================================================================
        else if (path == "/breakpoint/list") {
          std::string typeStr = queryParams["type"];

          // Default to listing all breakpoint types
          BPXTYPE bpType = bp_normal;
          if (typeStr == "hardware")
            bpType = bp_hardware;
          else if (typeStr == "memory")
            bpType = bp_memory;
          else if (typeStr == "dll")
            bpType = bp_dll;
          else if (typeStr == "exception")
            bpType = bp_exception;
          else if (typeStr == "normal" || typeStr.empty())
            bpType = bp_normal;

          // If type is "all", we gather all types
          bool getAllTypes = (typeStr == "all" || typeStr.empty());

          std::stringstream ss;
          ss << "{\"breakpoints\":[";

          int totalEmitted = 0;

          // Types to iterate
          BPXTYPE types[] = {bp_normal, bp_hardware, bp_memory, bp_dll,
                             bp_exception};
          int numTypes = getAllTypes ? 5 : 1;
          BPXTYPE *typeList = getAllTypes ? types : &bpType;

          for (int t = 0; t < numTypes; t++) {
            BPMAP bpmap;
            memset(&bpmap, 0, sizeof(bpmap));
            int count = DbgGetBpList(typeList[t], &bpmap);

            if (count > 0 && bpmap.bp != nullptr) {
              for (int i = 0; i < bpmap.count; i++) {
                if (totalEmitted > 0)
                  ss << ",";
                BRIDGEBP &bp = bpmap.bp[i];

                const char *bpTypeStr = "unknown";
                switch (bp.type) {
                case bp_normal:
                  bpTypeStr = "normal";
                  break;
                case bp_hardware:
                  bpTypeStr = "hardware";
                  break;
                case bp_memory:
                  bpTypeStr = "memory";
                  break;
                case bp_dll:
                  bpTypeStr = "dll";
                  break;
                case bp_exception:
                  bpTypeStr = "exception";
                  break;
                default:
                  break;
                }

                ss << "{\"type\":\"" << bpTypeStr << "\","
                   << "\"addr\":\"0x" << std::hex << bp.addr << "\","
                   << "\"enabled\":" << (bp.enabled ? "true" : "false") << ","
                   << "\"singleshoot\":" << (bp.singleshoot ? "true" : "false")
                   << ","
                   << "\"active\":" << (bp.active ? "true" : "false") << ","
                   << "\"name\":\"" << escapeJsonString(bp.name) << "\","
                   << "\"module\":\"" << escapeJsonString(bp.mod) << "\","
                   << "\"hitCount\":" << std::dec << bp.hitCount << ","
                   << "\"fastResume\":" << (bp.fastResume ? "true" : "false")
                   << ","
                   << "\"silent\":" << (bp.silent ? "true" : "false") << ","
                   << "\"breakCondition\":\""
                   << escapeJsonString(bp.breakCondition) << "\","
                   << "\"logText\":\"" << escapeJsonString(bp.logText) << "\","
                   << "\"commandText\":\"" << escapeJsonString(bp.commandText)
                   << "\""
                   << "}";
                totalEmitted++;
              }
              BridgeFree(bpmap.bp);
            }
          }

          ss << "],\"count\":" << std::dec << totalEmitted << "}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        }
        // =============================================================================
        // LABEL GET/SET ENDPOINTS
        // =============================================================================
        else if (path == "/label/set") {
          std::string addrStr = queryParams["addr"];
          std::string text = queryParams["text"];
          if (!body.empty() && text.empty())
            text = body;
          text = urlDecode(text);

          if (addrStr.empty() || text.empty()) {
            sendHttpResponse(clientSocket, 400, "application/json",
                             "{\"error\":\"Missing required 'addr' and 'text' "
                             "parameters\"}");
            continue;
          }

          duint addr = 0;
          try {
            addr = std::stoull(addrStr, nullptr, 16);
          } catch (const std::exception &e) {
            sendHttpResponse(clientSocket, 400, "application/json",
                             "{\"error\":\"Invalid address format\"}");
            continue;
          }

          bool success = DbgSetLabelAt(addr, text.c_str());
          std::stringstream ss;
          ss << "{\"success\":" << (success ? "true" : "false") << ","
             << "\"address\":\"0x" << std::hex << addr << "\","
             << "\"label\":\"" << escapeJsonString(text.c_str()) << "\"}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        } else if (path == "/label/get") {
          std::string addrStr = queryParams["addr"];
          if (addrStr.empty()) {
            sendHttpResponse(
                clientSocket, 400, "application/json",
                "{\"error\":\"Missing required 'addr' parameter\"}");
            continue;
          }

          duint addr = 0;
          try {
            addr = std::stoull(addrStr, nullptr, 16);
          } catch (const std::exception &e) {
            sendHttpResponse(clientSocket, 400, "application/json",
                             "{\"error\":\"Invalid address format\"}");
            continue;
          }

          char text[MAX_LABEL_SIZE] = {0};
          bool found = DbgGetLabelAt(addr, SEG_DEFAULT, text);

          std::stringstream ss;
          ss << "{\"address\":\"0x" << std::hex << addr << "\","
             << "\"found\":" << (found ? "true" : "false") << ","
             << "\"label\":\"" << escapeJsonString(text) << "\"}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        } else if (path == "/label/list") {
          ListInfo labelList;
          bool success = Script::Label::GetList(&labelList);

          if (!success || labelList.data == nullptr) {
            sendHttpResponse(clientSocket, 200, "application/json",
                             "{\"count\":0,\"labels\":[]}");
            continue;
          }

          Script::Label::LabelInfo *labels =
              (Script::Label::LabelInfo *)labelList.data;
          size_t count = labelList.count;

          std::stringstream ss;
          ss << "{\"count\":" << std::dec << count << ",\"labels\":[";

          for (size_t i = 0; i < count; i++) {
            if (i > 0)
              ss << ",";
            ss << "{\"module\":\"" << escapeJsonString(labels[i].mod) << "\","
               << "\"rva\":\"0x" << std::hex << labels[i].rva << "\","
               << "\"text\":\"" << escapeJsonString(labels[i].text) << "\","
               << "\"manual\":" << (labels[i].manual ? "true" : "false") << "}";
          }

          ss << "]}";
          BridgeFree(labelList.data);
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        }
        // =============================================================================
        // COMMENT GET/SET ENDPOINTS
        // =============================================================================
        else if (path == "/comment/set") {
          std::string addrStr = queryParams["addr"];
          std::string text = queryParams["text"];
          if (!body.empty() && text.empty())
            text = body;
          text = urlDecode(text);

          if (addrStr.empty() || text.empty()) {
            sendHttpResponse(clientSocket, 400, "application/json",
                             "{\"error\":\"Missing required 'addr' and 'text' "
                             "parameters\"}");
            continue;
          }

          duint addr = 0;
          try {
            addr = std::stoull(addrStr, nullptr, 16);
          } catch (const std::exception &e) {
            sendHttpResponse(clientSocket, 400, "application/json",
                             "{\"error\":\"Invalid address format\"}");
            continue;
          }

          bool success = DbgSetCommentAt(addr, text.c_str());
          std::stringstream ss;
          ss << "{\"success\":" << (success ? "true" : "false") << ","
             << "\"address\":\"0x" << std::hex << addr << "\"}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        } else if (path == "/comment/get") {
          std::string addrStr = queryParams["addr"];
          if (addrStr.empty()) {
            sendHttpResponse(
                clientSocket, 400, "application/json",
                "{\"error\":\"Missing required 'addr' parameter\"}");
            continue;
          }

          duint addr = 0;
          try {
            addr = std::stoull(addrStr, nullptr, 16);
          } catch (const std::exception &e) {
            sendHttpResponse(clientSocket, 400, "application/json",
                             "{\"error\":\"Invalid address format\"}");
            continue;
          }

          char text[MAX_COMMENT_SIZE] = {0};
          bool found = DbgGetCommentAt(addr, text);

          std::stringstream ss;
          ss << "{\"address\":\"0x" << std::hex << addr << "\","
             << "\"found\":" << (found ? "true" : "false") << ","
             << "\"comment\":\"" << escapeJsonString(text) << "\"}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        }
        // =============================================================================
        // REGISTER DUMP ENDPOINT
        // =============================================================================
        else if (path == "/registers") {
          REGDUMP regdump;
          memset(&regdump, 0, sizeof(regdump));
          bool success = DbgGetRegDumpEx(&regdump, sizeof(regdump));

          if (!success) {
            sendHttpResponse(clientSocket, 500, "application/json",
                             "{\"error\":\"Failed to get register dump\"}");
            continue;
          }

          std::stringstream ss;
          ss << "{";

          // General purpose registers
          ss << "\"cax\":\"0x" << std::hex << regdump.regcontext.cax << "\","
             << "\"ccx\":\"0x" << std::hex << regdump.regcontext.ccx << "\","
             << "\"cdx\":\"0x" << std::hex << regdump.regcontext.cdx << "\","
             << "\"cbx\":\"0x" << std::hex << regdump.regcontext.cbx << "\","
             << "\"csp\":\"0x" << std::hex << regdump.regcontext.csp << "\","
             << "\"cbp\":\"0x" << std::hex << regdump.regcontext.cbp << "\","
             << "\"csi\":\"0x" << std::hex << regdump.regcontext.csi << "\","
             << "\"cdi\":\"0x" << std::hex << regdump.regcontext.cdi << "\","
#ifdef _WIN64
             << "\"r8\":\"0x" << std::hex << regdump.regcontext.r8 << "\","
             << "\"r9\":\"0x" << std::hex << regdump.regcontext.r9 << "\","
             << "\"r10\":\"0x" << std::hex << regdump.regcontext.r10 << "\","
             << "\"r11\":\"0x" << std::hex << regdump.regcontext.r11 << "\","
             << "\"r12\":\"0x" << std::hex << regdump.regcontext.r12 << "\","
             << "\"r13\":\"0x" << std::hex << regdump.regcontext.r13 << "\","
             << "\"r14\":\"0x" << std::hex << regdump.regcontext.r14 << "\","
             << "\"r15\":\"0x" << std::hex << regdump.regcontext.r15 << "\","
#endif
             << "\"cip\":\"0x" << std::hex << regdump.regcontext.cip << "\","
             << "\"eflags\":\"0x" << std::hex << regdump.regcontext.eflags
             << "\","

             // Segment registers
             << "\"gs\":\"0x" << std::hex << regdump.regcontext.gs << "\","
             << "\"fs\":\"0x" << std::hex << regdump.regcontext.fs << "\","
             << "\"es\":\"0x" << std::hex << regdump.regcontext.es << "\","
             << "\"ds\":\"0x" << std::hex << regdump.regcontext.ds << "\","
             << "\"cs\":\"0x" << std::hex << regdump.regcontext.cs << "\","
             << "\"ss\":\"0x" << std::hex << regdump.regcontext.ss
             << "\","

             // Debug registers
             << "\"dr0\":\"0x" << std::hex << regdump.regcontext.dr0 << "\","
             << "\"dr1\":\"0x" << std::hex << regdump.regcontext.dr1 << "\","
             << "\"dr2\":\"0x" << std::hex << regdump.regcontext.dr2 << "\","
             << "\"dr3\":\"0x" << std::hex << regdump.regcontext.dr3 << "\","
             << "\"dr6\":\"0x" << std::hex << regdump.regcontext.dr6 << "\","
             << "\"dr7\":\"0x" << std::hex << regdump.regcontext.dr7
             << "\","

             // Flags
             << "\"flags\":{"
             << "\"ZF\":" << (regdump.flags.z ? "true" : "false") << ","
             << "\"OF\":" << (regdump.flags.o ? "true" : "false") << ","
             << "\"CF\":" << (regdump.flags.c ? "true" : "false") << ","
             << "\"PF\":" << (regdump.flags.p ? "true" : "false") << ","
             << "\"SF\":" << (regdump.flags.s ? "true" : "false") << ","
             << "\"TF\":" << (regdump.flags.t ? "true" : "false") << ","
             << "\"AF\":" << (regdump.flags.a ? "true" : "false") << ","
             << "\"DF\":" << (regdump.flags.d ? "true" : "false") << ","
             << "\"IF\":" << (regdump.flags.i ? "true" : "false")
             << "},"

             // Last error/status
             << "\"lastError\":{\"code\":" << std::dec << regdump.lastError.code
             << ","
             << "\"name\":\"" << escapeJsonString(regdump.lastError.name)
             << "\"},"
             << "\"lastStatus\":{\"code\":" << std::dec
             << regdump.lastStatus.code << ","
             << "\"name\":\"" << escapeJsonString(regdump.lastStatus.name)
             << "\"}"
             << "}";

          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        }
        // =============================================================================
        // HARDWARE BREAKPOINT ENDPOINTS
        // =============================================================================
        else if (path == "/breakpoint/hardware/set") {
          std::string addrStr = queryParams["addr"];
          std::string typeStr = queryParams["type"]; // access, write, execute

          if (addrStr.empty()) {
            sendHttpResponse(
                clientSocket, 400, "application/json",
                "{\"error\":\"Missing required 'addr' parameter\"}");
            continue;
          }

          duint addr = 0;
          try {
            addr = std::stoull(addrStr, nullptr, 16);
          } catch (const std::exception &e) {
            sendHttpResponse(clientSocket, 400, "application/json",
                             "{\"error\":\"Invalid address format\"}");
            continue;
          }

          Script::Debug::HardwareType hwType = Script::Debug::HardwareExecute;
          if (typeStr == "access")
            hwType = Script::Debug::HardwareAccess;
          else if (typeStr == "write")
            hwType = Script::Debug::HardwareWrite;
          else if (typeStr == "execute")
            hwType = Script::Debug::HardwareExecute;

          bool success = Script::Debug::SetHardwareBreakpoint(addr, hwType);
          std::stringstream ss;
          ss << "{\"success\":" << (success ? "true" : "false") << ","
             << "\"address\":\"0x" << std::hex << addr << "\"}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        } else if (path == "/breakpoint/hardware/delete") {
          std::string addrStr = queryParams["addr"];
          if (addrStr.empty()) {
            sendHttpResponse(
                clientSocket, 400, "application/json",
                "{\"error\":\"Missing required 'addr' parameter\"}");
            continue;
          }

          duint addr = 0;
          try {
            addr = std::stoull(addrStr, nullptr, 16);
          } catch (const std::exception &e) {
            sendHttpResponse(clientSocket, 400, "application/json",
                             "{\"error\":\"Invalid address format\"}");
            continue;
          }

          bool success = Script::Debug::DeleteHardwareBreakpoint(addr);
          std::stringstream ss;
          ss << "{\"success\":" << (success ? "true" : "false") << ","
             << "\"address\":\"0x" << std::hex << addr << "\"}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        }
        // =============================================================================
        // ENUM TCP CONNECTIONS ENDPOINT
        // =============================================================================
        else if (path == "/network/tcp") {
          const DBGFUNCTIONS *dbgFunc = DbgFunctions();
          if (!dbgFunc || !dbgFunc->EnumTcpConnections) {
            sendHttpResponse(
                clientSocket, 500, "application/json",
                "{\"error\":\"EnumTcpConnections not available\"}");
            continue;
          }

          ListInfo tcpList;
          bool success = dbgFunc->EnumTcpConnections(&tcpList);

          if (!success || tcpList.data == nullptr) {
            sendHttpResponse(clientSocket, 200, "application/json",
                             "{\"count\":0,\"connections\":[]}");
            continue;
          }

          TCPCONNECTIONINFO *connections = (TCPCONNECTIONINFO *)tcpList.data;
          size_t count = tcpList.count;

          std::stringstream ss;
          ss << "{\"count\":" << std::dec << count << ",\"connections\":[";

          for (size_t i = 0; i < count; i++) {
            if (i > 0)
              ss << ",";
            ss << "{\"remoteAddress\":\""
               << escapeJsonString(connections[i].RemoteAddress) << "\","
               << "\"remotePort\":" << std::dec << connections[i].RemotePort
               << ","
               << "\"localAddress\":\""
               << escapeJsonString(connections[i].LocalAddress) << "\","
               << "\"localPort\":" << std::dec << connections[i].LocalPort
               << ","
               << "\"state\":\"" << escapeJsonString(connections[i].StateText)
               << "\"}";
          }

          ss << "]}";
          BridgeFree(tcpList.data);
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        }
        // =============================================================================
        // PATCH ENUM/GET ENDPOINTS
        // =============================================================================
        else if (path == "/patch/list") {
          const DBGFUNCTIONS *dbgFunc = DbgFunctions();
          if (!dbgFunc || !dbgFunc->PatchEnum) {
            sendHttpResponse(clientSocket, 500, "application/json",
                             "{\"error\":\"PatchEnum not available\"}");
            continue;
          }

          // First call to get size needed
          size_t cbsize = 0;
          dbgFunc->PatchEnum(nullptr, &cbsize);

          if (cbsize == 0) {
            sendHttpResponse(clientSocket, 200, "application/json",
                             "{\"count\":0,\"patches\":[]}");
            continue;
          }

          size_t count = cbsize / sizeof(DBGPATCHINFO);
          std::vector<DBGPATCHINFO> patches(count);

          if (!dbgFunc->PatchEnum(patches.data(), &cbsize)) {
            sendHttpResponse(clientSocket, 500, "application/json",
                             "{\"error\":\"PatchEnum failed\"}");
            continue;
          }

          std::stringstream ss;
          ss << "{\"count\":" << std::dec << count << ",\"patches\":[";

          for (size_t i = 0; i < count; i++) {
            if (i > 0)
              ss << ",";
            ss << "{\"module\":\"" << escapeJsonString(patches[i].mod) << "\","
               << "\"address\":\"0x" << std::hex << patches[i].addr << "\","
               << "\"oldByte\":\"0x" << std::hex << (int)patches[i].oldbyte
               << "\","
               << "\"newByte\":\"0x" << std::hex << (int)patches[i].newbyte
               << "\"}";
          }

          ss << "]}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        } else if (path == "/patch/get") {
          std::string addrStr = queryParams["addr"];
          if (addrStr.empty()) {
            sendHttpResponse(
                clientSocket, 400, "application/json",
                "{\"error\":\"Missing required 'addr' parameter\"}");
            continue;
          }

          duint addr = 0;
          try {
            addr = std::stoull(addrStr, nullptr, 16);
          } catch (const std::exception &e) {
            sendHttpResponse(clientSocket, 400, "application/json",
                             "{\"error\":\"Invalid address format\"}");
            continue;
          }

          const DBGFUNCTIONS *dbgFunc = DbgFunctions();
          if (!dbgFunc) {
            sendHttpResponse(clientSocket, 500, "application/json",
                             "{\"error\":\"DbgFunctions not available\"}");
            continue;
          }

          DBGPATCHINFO patchInfo;
          memset(&patchInfo, 0, sizeof(patchInfo));
          bool found = false;

          if (dbgFunc->PatchGetEx) {
            found = dbgFunc->PatchGetEx(addr, &patchInfo);
          } else if (dbgFunc->PatchGet) {
            found = dbgFunc->PatchGet(addr);
          }

          std::stringstream ss;
          ss << "{\"address\":\"0x" << std::hex << addr << "\","
             << "\"patched\":" << (found ? "true" : "false");

          if (found && dbgFunc->PatchGetEx) {
            ss << ",\"module\":\"" << escapeJsonString(patchInfo.mod) << "\","
               << "\"oldByte\":\"0x" << std::hex << (int)patchInfo.oldbyte
               << "\","
               << "\"newByte\":\"0x" << std::hex << (int)patchInfo.newbyte
               << "\"";
          }

          ss << "}";
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        }
        // =============================================================================
        // ENUM HANDLES ENDPOINT
        // =============================================================================
        else if (path == "/handles") {
          const DBGFUNCTIONS *dbgFunc = DbgFunctions();
          if (!dbgFunc || !dbgFunc->EnumHandles) {
            sendHttpResponse(clientSocket, 500, "application/json",
                             "{\"error\":\"EnumHandles not available\"}");
            continue;
          }

          ListInfo handleList;
          bool success = dbgFunc->EnumHandles(&handleList);

          if (!success || handleList.data == nullptr) {
            sendHttpResponse(clientSocket, 200, "application/json",
                             "{\"count\":0,\"handles\":[]}");
            continue;
          }

          HANDLEINFO *handles = (HANDLEINFO *)handleList.data;
          size_t count = handleList.count;

          std::stringstream ss;
          ss << "{\"count\":" << std::dec << count << ",\"handles\":[";

          for (size_t i = 0; i < count; i++) {
            if (i > 0)
              ss << ",";

            // Try to get the handle name and type
            char handleName[256] = {0};
            char typeName[256] = {0};
            if (dbgFunc->GetHandleName) {
              dbgFunc->GetHandleName(handles[i].Handle, handleName,
                                     sizeof(handleName), typeName,
                                     sizeof(typeName));
            }

            ss << "{\"handle\":\"0x" << std::hex << handles[i].Handle << "\","
               << "\"typeNumber\":" << std::dec << (int)handles[i].TypeNumber
               << ","
               << "\"grantedAccess\":\"0x" << std::hex
               << handles[i].GrantedAccess << "\","
               << "\"name\":\"" << escapeJsonString(handleName) << "\","
               << "\"typeName\":\"" << escapeJsonString(typeName) << "\"}";
          }

          ss << "]}";
          BridgeFree(handleList.data);
          sendHttpResponse(clientSocket, 200, "application/json", ss.str());
        }

      } catch (const std::exception &e) {
        // Exception in handling request
        sendJsonErrorResponse(clientSocket, 500,
                              std::string("Internal Server Error: ") +
                                  e.what());
      }
    }

    // Close the client socket
    closesocket(clientSocket);
  }

  // Clean up
  if (g_serverSocket != INVALID_SOCKET) {
    closesocket(g_serverSocket);
    g_serverSocket = INVALID_SOCKET;
  }

  WSACleanup();
  return 0;
}

// Function to read the HTTP request
std::string readHttpRequest(SOCKET clientSocket) {
  std::string request;
  char buffer[MAX_REQUEST_SIZE];
  int bytesReceived;

  // Set socket to blocking mode to receive full request
  u_long mode = 0;
  ioctlsocket(clientSocket, FIONBIO, &mode);

  // Receive data
  bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

  if (bytesReceived > 0) {
    buffer[bytesReceived] = '\0';
    request = buffer;
  }

  return request;
}

// Function to parse an HTTP request
void parseHttpRequest(const std::string &request, std::string &method,
                      std::string &path, std::string &query,
                      std::string &body) {
  // Parse the request line
  size_t firstLineEnd = request.find("\r\n");
  if (firstLineEnd == std::string::npos) {
    return;
  }

  std::string requestLine = request.substr(0, firstLineEnd);

  // Extract method and URL
  size_t methodEnd = requestLine.find(' ');
  if (methodEnd == std::string::npos) {
    return;
  }

  method = requestLine.substr(0, methodEnd);

  size_t urlEnd = requestLine.find(' ', methodEnd + 1);
  if (urlEnd == std::string::npos) {
    return;
  }

  std::string url = requestLine.substr(methodEnd + 1, urlEnd - methodEnd - 1);

  // Split URL into path and query
  size_t queryStart = url.find('?');
  if (queryStart != std::string::npos) {
    path = url.substr(0, queryStart);
    query = url.substr(queryStart + 1);
  } else {
    path = url;
    query = "";
  }

  // Find the end of headers and start of body
  size_t headersEnd = request.find("\r\n\r\n");
  if (headersEnd == std::string::npos) {
    return;
  }

  // Extract body
  body = request.substr(headersEnd + 4);
}

// Function to send HTTP response
bool sendAll(SOCKET clientSocket, const char *data, size_t length) {
  size_t totalSent = 0;

  while (totalSent < length) {
    const size_t remaining = length - totalSent;
    const int chunkSize = remaining > static_cast<size_t>(INT_MAX)
                              ? INT_MAX
                              : static_cast<int>(remaining);

    const int sent = send(clientSocket, data + totalSent, chunkSize, 0);
    if (sent == SOCKET_ERROR || sent == 0) {
      return false;
    }

    totalSent += static_cast<size_t>(sent);
  }

  return true;
}

void sendHttpResponse(SOCKET clientSocket, int statusCode,
                      const std::string &contentType,
                      const std::string &responseBody) {
  // Prepare status line
  std::string statusText;
  switch (statusCode) {
  case 200:
    statusText = "OK";
    break;
  case 404:
    statusText = "Not Found";
    break;
  case 500:
    statusText = "Internal Server Error";
    break;
  default:
    statusText = "Unknown";
  }

  // Build the response
  std::stringstream response;
  response << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
  response << "Content-Type: " << contentType << "\r\n";
  response << "Content-Length: " << responseBody.length() << "\r\n";
  response << "Connection: close\r\n";
  response << "\r\n";
  response << responseBody;

  // Send the response
  std::string responseStr = response.str();
  if (!sendAll(clientSocket, responseStr.c_str(), responseStr.length())) {
    _plugin_logprintf(
        "sendAll failed with WSA error %d while sending %zu bytes\n",
        WSAGetLastError(), responseStr.length());
  }
}

// Parse query or form-urlencoded parameters and URL-decode key/value pairs.
std::unordered_map<std::string, std::string>
parseQueryParams(const std::string &query) {
  std::unordered_map<std::string, std::string> params;

  size_t pos = 0;
  size_t nextPos;

  while (pos < query.length()) {
    nextPos = query.find('&', pos);
    if (nextPos == std::string::npos) {
      nextPos = query.length();
    }

    std::string pair = query.substr(pos, nextPos - pos);
    size_t equalPos = pair.find('=');

    if (equalPos != std::string::npos) {
      std::string key = urlDecode(pair.substr(0, equalPos));
      std::string value = urlDecode(pair.substr(equalPos + 1));
      params[key] = value;
    }

    pos = nextPos + 1;
  }

  return params;
}

// Command callback for toggling HTTP server
bool cbEnableHttpServer(int argc, char *argv[]) {
  if (g_httpServerRunning) {
    _plugin_logputs("Stopping HTTP server...");
    stopHttpServer();
    _plugin_logputs("HTTP server stopped");
  } else {
    _plugin_logputs("Starting HTTP server...");
    if (startHttpServer()) {
      _plugin_logprintf("HTTP server started on port %d\n", g_httpPort);
    } else {
      _plugin_logputs("Failed to start HTTP server");
    }
  }
  return true;
}

// Command callback for changing HTTP server port
bool cbSetHttpPort(int argc, char *argv[]) {
  if (argc < 2) {
    _plugin_logputs("Usage: httpport [port_number]");
    return false;
  }

  int port;
  try {
    port = std::stoi(argv[1]);
  } catch (const std::exception &) {
    _plugin_logputs("Invalid port number");
    return false;
  }

  if (port <= 0 || port > 65535) {
    _plugin_logputs("Port number must be between 1 and 65535");
    return false;
  }

  g_httpPort = port;

  if (g_httpServerRunning) {
    _plugin_logputs("Restarting HTTP server with new port...");
    stopHttpServer();
    if (startHttpServer()) {
      _plugin_logprintf("HTTP server restarted on port %d\n", g_httpPort);
    } else {
      _plugin_logputs("Failed to restart HTTP server");
    }
  } else {
    _plugin_logprintf("HTTP port set to %d\n", g_httpPort);
  }

  return true;
}

// Register plugin commands
void registerCommands() {
  _plugin_registercommand(g_pluginHandle, "httpserver", cbEnableHttpServer,
                          "Toggle HTTP server on/off");
  _plugin_registercommand(g_pluginHandle, "httpport", cbSetHttpPort,
                          "Set HTTP server port");
}
