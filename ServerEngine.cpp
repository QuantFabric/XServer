#include "ServerEngine.h"

extern Utils::Logger *gLogger;

ServerEngine::ServerEngine()
{
    m_HPPackServer = NULL;
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
    case Message::ECommand:
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
