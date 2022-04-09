#ifndef SERVERENGINE_H
#define SERVERENGINE_H

#include <list>
#include <vector>
#include <mutex>
#include <stdlib.h>
#include <unordered_map>
#include "HPPackServer.h"
#include "YMLConfig.hpp"
#include "UserDBManager.hpp"

class ServerEngine
{
public:
    explicit ServerEngine();
    void LoadConfig(const char* yml);
    void RegisterServer(const char *ip, unsigned int port);
    void Run();
protected:
    void HandlePackMessage(const Message::PackMessage &msg);
    void HandleLoginRequest(const Message::PackMessage &msg);
    void HandleCommand(const Message::PackMessage &msg);

    void UpdateUserPermissionTable(const Message::PackMessage &msg);
    bool ParseUpdateUserPermissionCommand(const std::string& cmd, std::string& sql, std::string& op, Message::TLoginResponse& rsp);
    static int sqlite3_callback_UserPermission(void *data, int argc, char **argv, char **azColName);
    bool QueryUserPermission();

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
    static std::unordered_map<std::string, Message::TLoginResponse> m_UserPermissionMap;
    UserDBManager* m_UserDBManager;
};

#endif // SERVERENGINE_H