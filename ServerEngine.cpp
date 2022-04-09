#include "ServerEngine.h"

extern Utils::Logger *gLogger;

std::unordered_map<std::string, Message::TLoginResponse> ServerEngine::m_UserPermissionMap;

ServerEngine::ServerEngine()
{
    m_HPPackServer = NULL;
    m_UserDBManager = Utils::Singleton<UserDBManager>::GetInstance();
}

void ServerEngine::LoadConfig(const char* yml)
{
    Utils::gLogger->Log->info("ServerEngine::LoadConfig {} start", yml);
    std::string errorBuffer;
    if(Utils::LoadXServerConfig(yml, m_XServerConfig, errorBuffer))
    {
        Utils::gLogger->Log->info("ServerEngine::LoadXServerConfig {} successed", yml);
        m_OpenTime = Utils::getTimeStampMs(m_XServerConfig.OpenTime.c_str());
        m_CloseTime = Utils::getTimeStampMs(m_XServerConfig.CloseTime.c_str());
        m_AppCheckTime = Utils::getTimeStampMs(m_XServerConfig.AppCheckTime.c_str());

        bool ret = m_UserDBManager->LoadDataBase(m_XServerConfig.UserDBPath, errorBuffer);
        if(!ret)
        {
            Utils::gLogger->Log->error("ServerEngine::LoadDataBase {} failed, {}", m_XServerConfig.UserDBPath.c_str(), errorBuffer.c_str());
        }
        else
        {
            // Load Permission
            m_UserDBManager->QueryUserPermission(&ServerEngine::sqlite3_callback_UserPermission, errorBuffer);
        }
    }
    else
    {
        Utils::gLogger->Log->error("ServerEngine::LoadXServerConfig {} failed, {}", yml, errorBuffer.c_str());
    }
}

void ServerEngine::RegisterServer(const char *ip, unsigned int port)
{
    m_HPPackServer = new HPPackServer(ip, port);
    m_HPPackServer->Start();
}

void ServerEngine::Run()
{
    RegisterServer(m_XServerConfig.ServerIP.c_str(), m_XServerConfig.Port);

    Utils::gLogger->Log->info("ServerEngine::Run start to handle message");
    while (true)
    {
        CheckTrading();
        memset(&m_PackMessage, 0, sizeof(m_PackMessage));
        while(m_HPPackServer->m_PackMessageQueue.pop(m_PackMessage))
        {
            HandlePackMessage(m_PackMessage);
        }
    }
}

void ServerEngine::HandlePackMessage(const Message::PackMessage &msg)
{
    unsigned int type = msg.MessageType;
    switch (type)
    {
    case Message::ELoginRequest:
        HandleLoginRequest(msg);
        break;
    case Message::ECommand:
        HandleCommand(msg);
        break;
    case Message::EEventLog:
    case Message::EAccountFund:
    case Message::EAccountPosition:
    case Message::EOrderStatus:
    case Message::EOrderRequest:
    case Message::EActionRequest:
    case Message::ERiskReport:
    case Message::EColoStatus:
    case Message::EAppStatus:
    case Message::EFutureMarketData:
    case Message::EStockMarketData:
    default:
        char buffer[128] = {0};
        sprintf(buffer, "UnKown Message type:0X%X", msg.MessageType);
        Utils::gLogger->Log->warn("ServerEngine::HandlePackMessage {}", buffer);
        break;
    }
}

void ServerEngine::HandleLoginRequest(const Message::PackMessage &msg)
{
    if(Message::EClientType::EXMONITOR != msg.LoginRequest.ClientType)
        return;
    std::string Account = msg.LoginRequest.Account;
    auto it = m_UserPermissionMap.find(Account);
    if(m_UserPermissionMap.end() != it)
    {
        std::string Plugins = it->second.Plugins;
        std::string errorString;
        for (auto it1 = m_HPPackServer->m_sConnections.begin(); it1 != m_HPPackServer->m_sConnections.end(); ++it1)
        {
            if (Utils::equalWith(Account, it1->second.Account))
            {
                if (Utils::equalWith(msg.LoginRequest.PassWord, it->second.PassWord))
                {
                    it->second.ErrorID = 0;
                    strncpy(it->second.ErrorMsg, "Login Successed.", sizeof(it->second.ErrorMsg));
                }
                else
                {
                    {
                        // send LoginResponse
                        Message::PackMessage message;
                        memset(&message, 0, sizeof(message));
                        message.MessageType = Message::EMessageType::ELoginResponse;
                        it->second.ErrorID = 0X1000;
                        sprintf(it->second.ErrorMsg, "Login Failed, Invalid PassWord:%s", msg.LoginRequest.PassWord);
                        memcpy(&message.LoginResponse, &it->second, sizeof(message.LoginResponse));
                        m_HPPackServer->SendData(it1->second.dwConnID, (const unsigned char*)&message, sizeof(message));
                    }
                    {
                        char errorString[256] = {0};
                        sprintf(errorString, "%s Login Failed, PassWord Invalid:%s", Account.c_str(), msg.LoginRequest.PassWord);
                        Message::PackMessage message;
                        memset(&message, 0, sizeof(message));
                        message.MessageType = Message::EMessageType::EEventLog;
                        message.EventLog.Level = Message::EEventLogLevel::EERROR;
                        strncpy(message.EventLog.App, "XServer", sizeof(message.EventLog.App));
                        strncpy(message.EventLog.Event, errorString, sizeof(message.EventLog.Event));
                        strncpy(message.EventLog.UpdateTime, Utils::getCurrentTimeUs(), sizeof(message.EventLog.UpdateTime));
                        m_HPPackServer->SendData(it1->second.dwConnID, (const unsigned char*)&message, sizeof(message));
                        Utils::gLogger->Log->warn(errorString);
                    }
                    return;
                }
                if(Utils::equalWith(it1->second.Account, "root") || Utils::equalWith(it1->second.Account, "admin"))
                {
                    if(Plugins.find(PLUGIN_PERMISSION) == std::string::npos)
                    {
                        if(Plugins.length() > 0)
                        {
                            Plugins += "|";
                        }
                        Plugins += PLUGIN_PERMISSION;
                    }
                }
                strncpy(it->second.Plugins, Plugins.c_str(), sizeof(it->second.Plugins));
                strncpy(it1->second.Plugins, Plugins.c_str(), sizeof(it1->second.Plugins));
                strncpy(it1->second.Messages, it->second.Messages, sizeof(it1->second.Messages));
                // add new connection
                m_HPPackServer->m_newConnections.insert(std::pair<HP_CONNID, Connection>(it1->second.dwConnID, it1->second));
                {
                    // send LoginResponse
                    Message::PackMessage message;
                    memset(&message, 0, sizeof(message));
                    message.MessageType = Message::EMessageType::ELoginResponse;
                    memcpy(&message.LoginResponse, &it->second, sizeof(message.LoginResponse));
                    m_HPPackServer->SendData(it1->second.dwConnID, (const unsigned char*)&message, sizeof(message));
                }
                if(Utils::equalWith(it1->second.Account, "root") || Utils::equalWith(it1->second.Account, "admin"))
                {
                    for (auto it3 = m_UserPermissionMap.begin(); it3 != m_UserPermissionMap.end(); it3++)
                    {
                        Message::PackMessage message;
                        memset(&message, 0, sizeof(message));
                        message.MessageType = Message::EMessageType::ELoginResponse;
                        memcpy(&message.LoginResponse, &it3->second, sizeof(message.LoginResponse));
                        m_HPPackServer->SendData(it1->second.dwConnID, (const unsigned char*)&message, sizeof(message));
                        Utils::gLogger->Log->info("ServerEngine::HandleLoginRequest UserName:{} Role:{} Plugins:{}",
                                                  it3->second.Account, it3->second.Role, it3->second.Plugins);
                    }
                }
                break;
            }
            else
            {
                errorString = "Account or UUID not matched.";
            }
        }
        Utils::gLogger->Log->info("ServerEngine::HandleLoginRequest new Connection, Account:{} UUID:{} newConnections:{} errorMsg:{}",
                                  msg.LoginRequest.Account, msg.LoginRequest.UUID,
                                  m_HPPackServer->m_newConnections.size(), errorString.c_str());
    }
    else
    {
        Utils::gLogger->Log->warn("ServerEngine::HandleLoginRequest UserName:{} not Found ,mapSize:{}",
                                  Account.c_str(), m_UserPermissionMap.size());
    }
}

void ServerEngine::HandleCommand(const Message::PackMessage &msg)
{
    // Handle UserPermission
    if(Message::ECommandType::EUPDATE_USERPERMISSION == msg.Command.CmdType)
    {
         // Update UserPermission Table
        UpdateUserPermissionTable(msg);
        char errorString[512] = {0};
        sprintf(errorString, "ServerEngine::HandleCommand Update UserPermission Table:%s", msg.Command.Command);
        Utils::gLogger->Log->debug(errorString);
    }
}


void ServerEngine::UpdateUserPermissionTable(const Message::PackMessage &msg)
{
    std::string sql, op;
    Message::TLoginResponse rsp;
    Utils::gLogger->Log->info("XRiskEngine::ParseUpdateUserPermissionCommand start size:{}", m_UserPermissionMap.size());
    if(ParseUpdateUserPermissionCommand(msg.Command.Command, sql, op, rsp))
    {
        std::string errorString;
        bool ok = m_UserDBManager->UpdateUserPermissionTable(sql, op, &ServerEngine::sqlite3_callback_UserPermission, errorString);
        if(ok)
        {
            if(Utils::equalWith(op, "INSERT"))
            {
                rsp.Operation = Message::EPermissionOperation::EUSER_ADD;
            }
            else if(Utils::equalWith(op, "UPDATE"))
            {
                rsp.Operation = Message::EPermissionOperation::EUSER_UPDATE;
            }
            else if(Utils::equalWith(op, "DELETE"))
            {
                rsp.Operation = Message::EPermissionOperation::EUSER_DELETE;
            }
            auto it = m_UserPermissionMap.find(rsp.Account);
            if(m_UserPermissionMap.end() == it)
            {
                m_UserPermissionMap.insert(std::pair<std::string, Message::TLoginResponse>(rsp.Account, rsp));
            }
            else
            {
                it->second.Operation = rsp.Operation;
            }
            QueryUserPermission();
            if(Message::EPermissionOperation::EUSER_DELETE == rsp.Operation)
            {
                m_UserPermissionMap.erase(rsp.Account);
            }
        }
        else
        {
            Utils::gLogger->Log->warn("XRiskEngine::ParseUpdateUserPermissionCommand failed:{}", errorString.c_str());
        }
        Utils::gLogger->Log->info("XRiskEngine::ParseUpdateUserPermissionCommand end size:{}", m_UserPermissionMap.size());
    }
}

bool ServerEngine::ParseUpdateUserPermissionCommand(const std::string& cmd, std::string& sql, std::string& op, Message::TLoginResponse& rsp)
{
    bool ret = true;
    sql.clear();
    std::vector<std::string> items;
    Utils::Split(cmd, ",", items);
    if(6 == items.size())
    {
        std::vector<std::string> keyValue;
        Utils::Split(items[0], ":", keyValue);
        std::string UserName = keyValue[1];
        strncpy(rsp.Account, UserName.c_str(), sizeof(rsp.Account));

        keyValue.clear();
        Utils::Split(items[1], ":", keyValue);
        std::string PassWord = keyValue[1];
        strncpy(rsp.PassWord, PassWord.c_str(), sizeof(rsp.PassWord));

        keyValue.clear();
        Utils::Split(items[2], ":", keyValue);
        std::string Operation = keyValue[1];

        keyValue.clear();
        Utils::Split(items[3], ":", keyValue);
        std::string Role = keyValue[1];
        strncpy(rsp.Role, Role.c_str(), sizeof(rsp.Role));

        keyValue.clear();
        Utils::Split(items[4], ":", keyValue);
        std::string Plugins = keyValue[1];
        strncpy(rsp.Plugins, Plugins.c_str(), sizeof(rsp.Plugins));

        keyValue.clear();
        Utils::Split(items[5], ":", keyValue);
        std::string Messages = keyValue[1];
        strncpy(rsp.Messages, Messages.c_str(), sizeof(rsp.Messages));

        std::string CurrentTime = Utils::getCurrentTimeUs();
        strncpy(rsp.UpdateTime, CurrentTime.c_str(), sizeof(rsp.UpdateTime));
        char buffer[1024] = {0};
        auto it = m_UserPermissionMap.find(UserName);
        if(m_UserPermissionMap.end() == it)
        {

            sprintf(buffer, "INSERT INTO UserPermissionTable(UserName,PassWord,Role,Plugins,Messages,UpdateTime) VALUES ('%s', '%s', '%s', '%s', '%s', '%s');",
                    UserName.c_str(), PassWord.c_str(), Role.c_str(), Plugins.c_str(), Messages.c_str(), CurrentTime.c_str());
            op = "INSERT";
        }
        else
        {
            // Update
            if(Utils::equalWith(Operation, "Add") || Utils::equalWith(Operation, "Update"))
            {
                sprintf(buffer, "UPDATE UserPermissionTable SET PassWord='%s',Role='%s',Plugins='%s',Messages='%s',UpdateTime='%s' WHERE UserName='%s';",
                        PassWord.c_str(), Role.c_str(), Plugins.c_str(), Messages.c_str(), CurrentTime.c_str(), UserName.c_str());
                op = "UPDATE";
            }
            else if(Utils::equalWith(Operation, "Delete"))
            {
                sprintf(buffer, "DELETE FROM UserPermissionTable WHERE UserName='%s';", UserName.c_str());
                op = "DELETE";
            }
        }
        sql = buffer;
        Utils::gLogger->Log->info("ServerEngine::ParseUpdateUserPermissionCommand successed, UserName:{} Role:{} Plugins:{} Messages:{} MapSize:{}",
                                  UserName.c_str(), Role.c_str(), Plugins.c_str(), Messages.c_str(), m_UserPermissionMap.size());
    }
    else
    {
        ret = false;
        sprintf(rsp.ErrorMsg, "invalid command: %s", cmd.c_str());
        Utils::gLogger->Log->warn("ServerEngine::ParseUpdateUserPermissionCommand invalid command, {}", cmd.c_str());
    }

    return ret;
}

int ServerEngine::sqlite3_callback_UserPermission(void *data, int argc, char **argv, char **azColName)
{
    for(int i = 0; i < argc; i++)
    {
        Utils::gLogger->Log->info("ServerEngine::sqlite3_callback_UserPermission, {} {} = {}", (char*)data, azColName[i], argv[i]);
        std::string colName = azColName[i];
        std::string value = argv[i];
        static std::string UserName;
        static std::string PassWord;
        static std::string Role;
        static std::string Plugins;
        static std::string Messages;
        static std::string UpdateTime;

        if(Utils::equalWith(colName, "UserName"))
        {
            UserName = value;
        }
        if(Utils::equalWith(colName, "PassWord"))
        {
            PassWord = value.c_str();
        }
        if(Utils::equalWith(colName, "Role"))
        {
            Role = value.c_str();
        }
        if(Utils::equalWith(colName, "Plugins"))
        {
            Plugins = value.c_str();
        }
        if(Utils::equalWith(colName, "Messages"))
        {
            Messages = value.c_str();
        }
        if(Utils::equalWith(colName, "UpdateTime"))
        {
            std::string UpdateTime = value;
            std::mutex mtx;
            mtx.lock();
            Message::TLoginResponse& rsp = m_UserPermissionMap[UserName];
            strncpy(rsp.Account, UserName.c_str(), sizeof(rsp.Account));
            strncpy(rsp.PassWord, PassWord.c_str(), sizeof(rsp.PassWord));
            strncpy(rsp.Role, Role.c_str(), sizeof(rsp.Role));
            strncpy(rsp.Plugins, Plugins.c_str(), sizeof(rsp.Plugins));
            strncpy(rsp.Messages, Messages.c_str(), sizeof(rsp.Messages));
            rsp.Operation = Message::EPermissionOperation::EUSER_UPDATE;
            strncpy(rsp.UpdateTime, UpdateTime.c_str(), sizeof(rsp.UpdateTime));
            mtx.unlock();
        }
    }
    return 0;
}

bool ServerEngine::QueryUserPermission()
{
    std::string errorString;
    bool ret = m_UserDBManager->QueryUserPermission(&ServerEngine::sqlite3_callback_UserPermission, errorString);
    if(!ret)
    {
        Utils::gLogger->Log->warn("ServerEngine::QueryUserPermission failed, {}", errorString.c_str());
    }
    else
    {
        for (auto it1 = m_HPPackServer->m_sConnections.begin(); it1 != m_HPPackServer->m_sConnections.end(); ++it1)
        {
            if (Message::EClientType::EXMONITOR == it1->second.ClientType &&
                    (Utils::equalWith(it1->second.Account, "root") || Utils::equalWith(it1->second.Account, "admin")))
            {
                for (auto it2 = m_UserPermissionMap.begin(); it2 != m_UserPermissionMap.end(); it2++)
                {
                    Message::PackMessage message;
                    memset(&message, 0, sizeof(message));
                    message.MessageType = Message::EMessageType::ELoginResponse;
                    memcpy(&message.LoginResponse, &it2->second, sizeof(message.LoginResponse));
                    m_HPPackServer->SendData(it1->second.dwConnID,
                                         (const unsigned char *)&message, sizeof(message));
                }
            }
        }
    }
    return ret;
}

bool ServerEngine::IsTrading()const
{
    return m_Trading;
}

void ServerEngine::CheckTrading()
{
    std::string buffer = Utils::getCurrentTimeMs() + 11;
    m_CurrentTimeStamp = Utils::getTimeStampMs(buffer.c_str());
    m_Trading  = (m_CurrentTimeStamp >= m_OpenTime && m_CurrentTimeStamp <= m_CloseTime);
}
