#include "HPPackServer.h"


HPPackServer::ConnectionMapT HPPackServer::m_sConnections;
HPPackServer::ConnectionMapT HPPackServer::m_newConnections;
Utils::LockFreeQueue<Message::PackMessage> HPPackServer::m_PackMessageQueue(1 << 15);

HPPackServer::HPPackServer(const char *ip, unsigned int port)
{
    m_ServerIP = ip;
    m_ServerPort = port;
    // 创建监听器对象
    m_pListener = ::Create_HP_TcpPackServerListener();
    // 创建 Socket 对象
    m_pServer = ::Create_HP_TcpPackServer(m_pListener);

    // 设置 Socket 监听器回调函数
    ::HP_Set_FN_Server_OnAccept(m_pListener, OnAccept);
    ::HP_Set_FN_Server_OnSend(m_pListener, OnSend);
    ::HP_Set_FN_Server_OnReceive(m_pListener, OnReceive);
    ::HP_Set_FN_Server_OnClose(m_pListener, OnClose);
    ::HP_Set_FN_Server_OnShutdown(m_pListener, OnShutdown);

    // 设置包头标识与最大包长限制
    ::HP_TcpPackServer_SetMaxPackSize(m_pServer, 0xFFFF);
    ::HP_TcpPackServer_SetPackHeaderFlag(m_pServer, 0x169);
    ::HP_TcpServer_SetKeepAliveTime(m_pServer, 30 * 1000);
}

HPPackServer::~HPPackServer()
{
    // 销毁 Socket 对象
    ::Destroy_HP_TcpPackServer(m_pServer);
    // 销毁监听器对象
    ::Destroy_HP_TcpPackServerListener(m_pListener);
}

void HPPackServer::Start()
{
    if (::HP_Server_Start(m_pServer, m_ServerIP.c_str(), m_ServerPort))
    {
        FMTLOG(fmtlog::INF, "HPPackServer::Start listen to {}:{} successed", m_ServerIP, m_ServerPort);
    }
    else
    {
        FMTLOG(fmtlog::WRN, "HPPackServer::Start listen to {}:{} failed, error code:{} error massage:{}",
                m_ServerIP, m_ServerPort, ::HP_Client_GetLastError(m_pServer), HP_Client_GetLastErrorDesc(m_pServer));
    }
}

void HPPackServer::Stop()
{
    //停止服务器
    ::HP_Server_Stop(m_pServer);
}

void HPPackServer::SendData(HP_CONNID dwConnID, const unsigned char *pBuffer, int iLength)
{
    bool ret = ::HP_Server_Send(m_pServer, dwConnID, pBuffer, iLength);
    if(!ret)
    {
        FMTLOG(fmtlog::WRN, "HPPackServer::SendData failed, sys error:{}, error code:{}, error message:{}",
                SYS_GetLastErrorStr(), HP_Client_GetLastError(m_pServer), HP_Client_GetLastErrorDesc(m_pServer));
    }
}

En_HP_HandleResult __stdcall HPPackServer::OnAccept(HP_Server pSender, HP_CONNID dwConnID, UINT_PTR soClient)
{
    TCHAR szAddress[50];
    int iAddressLen = sizeof(szAddress) / sizeof(TCHAR);
    USHORT usPort;
    ::HP_Server_GetRemoteAddress(pSender, dwConnID, szAddress, &iAddressLen, &usPort);
    std::mutex mtx;
    mtx.lock();
    Connection connection;
    memset(&connection, 0, sizeof(connection));
    connection.dwConnID = dwConnID;
    connection.pSender = pSender;
    auto it = m_sConnections.find(dwConnID);
    if (m_sConnections.end() == it)
    {
        m_sConnections.insert(std::pair<HP_CONNID, Connection>(dwConnID, connection));
    }
    mtx.unlock();
    FMTLOG(fmtlog::INF, "HPPackServer::OnAccept accept an new connection dwConnID:{} from {}:{}",  dwConnID, szAddress, usPort);
    return HR_OK;
}

En_HP_HandleResult __stdcall HPPackServer::OnSend(HP_Server pSender, HP_CONNID dwConnID, const BYTE *pData, int iLength)
{
    return HR_OK;
}

En_HP_HandleResult __stdcall HPPackServer::OnReceive(HP_Server pSender, HP_CONNID dwConnID, const BYTE *pData, int iLength)
{
    TCHAR szAddress[50];
    int iAddressLen = sizeof(szAddress) / sizeof(TCHAR);
    USHORT usPort;
    ::HP_Server_GetRemoteAddress(pSender, dwConnID, szAddress, &iAddressLen, &usPort);
    Message::PackMessage message;
    memcpy(&message, pData, iLength);
    FMTLOG(fmtlog::DBG, "HPPackServer::OnReceive receive PackMessage, MessageType:{:#X}", message.MessageType);
    // LoginRequest
    if (Message::EMessageType::ELoginRequest == message.MessageType)
    {
        auto it = m_sConnections.find(dwConnID);
        if (it != m_sConnections.end())
        {
            it->second.ClientType = message.LoginRequest.ClientType;
            strncpy(it->second.Colo, message.LoginRequest.Colo, sizeof(it->second.Colo));
            strncpy(it->second.Account, message.LoginRequest.Account, sizeof(it->second.Account));
            strncpy(it->second.PassWord, message.LoginRequest.PassWord, sizeof(it->second.PassWord));
            strncpy(it->second.UUID, message.LoginRequest.UUID, sizeof(it->second.UUID));
            FMTLOG(fmtlog::INF, "HPPackServer::OnReceive accept an new Client login from {}:{}, Account:{} PassWord:{}",
                    szAddress, usPort, message.LoginRequest.Account, message.LoginRequest.PassWord);
        }
    }
    while(!m_PackMessageQueue.Push(message));
    return HR_OK;
}

En_HP_HandleResult __stdcall HPPackServer::OnClose(HP_Server pSender, HP_CONNID dwConnID, En_HP_SocketOperation enOperation, int iErrorCode)
{
    TCHAR szAddress[50];
    int iAddressLen = sizeof(szAddress) / sizeof(TCHAR);
    USHORT usPort;
    ::HP_Server_GetRemoteAddress(pSender, dwConnID, szAddress, &iAddressLen, &usPort);

    auto it = m_sConnections.find(dwConnID);
    if (it != m_sConnections.end())
    {
        m_sConnections.erase(dwConnID);
    }
    auto it1 = m_newConnections.find(dwConnID);
    if (it1 != m_newConnections.end())
    {
        m_newConnections.erase(dwConnID);
    }
    FMTLOG(fmtlog::WRN, "HPPackServer::OnClose have an connection dwConnID:{} from {}:{} closed",  dwConnID, szAddress, usPort);

    return HR_OK;
}

En_HP_HandleResult __stdcall HPPackServer::OnShutdown(HP_Server pSender)
{
    return HR_OK;
}