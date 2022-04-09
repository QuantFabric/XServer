#ifndef SERVERENGINE_H
#define SERVERENGINE_H

#include <list>
#include <vector>
#include <mutex>
#include <stdlib.h>
#include <unordered_map>
#include "HPPackServer.h"
#include "YMLConfig.hpp"

class ServerEngine
{
public:
    explicit ServerEngine();
    void LoadConfig(const char* yml);
    void RegisterServer(const char *ip, unsigned int port);
    void Run();
private:
    void HandlePackMessage(const Message::PackMessage &msg);

    bool IsTrading()const;
    void CheckTrading();
private:
    HPPackServer* m_HPPackServer;
    Message::PackMessage m_PackMessage;
    Utils::XServerConfig m_XServerConfig;
    bool m_Trading;
    unsigned long m_CurrentTimeStamp;
    int m_OpenTime;
    int m_CloseTime;
    int m_AppCheckTime;
};

#endif // SERVERENGINE_H