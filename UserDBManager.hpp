#ifndef USERDBMANAGER_HPP
#define USERDBMANAGER_HPP

#include "Singleton.hpp"
#include "Util.hpp"
#include "FMTLogger.hpp"
#include "YMLConfig.hpp"
#include "SQLiteManager.hpp"

class UserDBManager
{
    friend class Utils::Singleton<UserDBManager>;
public:
    bool LoadDataBase(const std::string& dbPath, std::string& errorString)
    {
        m_DBManager = Utils::Singleton<Utils::SQLiteManager>::GetInstance();
        bool ret = m_DBManager->LoadDataBase(dbPath, errorString);
        if(!ret)
        {
            FMTLOG(fmtlog::WRN, "UserDBManager::LoadDataBase failed, {}", errorString);
        }
        return ret;
    }

    bool UpdateUserPermissionTable(const std::string& sql, const std::string& op, sqlite3_callback cb, std::string& errorString)
    {
        errorString.clear();
        char errorBuffer[256] = {0};
        bool ret = m_DBManager->Execute(sql, cb, op.c_str(), errorString);
        if(!ret)
        {
            sprintf(errorBuffer, "ErrorMsg:%s, SQL:%s", errorString.c_str(), sql.c_str());
            FMTLOG(fmtlog::WRN, "UserDBManager::UpdateUserPermissionTable failed, ErrorMsg:{} SQL:{}", errorString, sql);
        }
        else
        {
            sprintf(errorBuffer, "SQL: %s", sql.c_str());
            FMTLOG(fmtlog::INF, "UserDBManager::UpdateUserPermissionTable successed, sql:{}", sql);
        }
        errorString = errorBuffer;
        return ret;
    }

    bool QueryUserPermission(sqlite3_callback cb, std::string& errorString)
    {
        std::string SQL_SELECT_USER_PERMISSION = "SELECT * FROM UserPermissionTable;";
        bool ret = m_DBManager->Execute(SQL_SELECT_USER_PERMISSION, cb, "SELECT", errorString);
        if(!ret)
        {
            FMTLOG(fmtlog::WRN, "UserDBManager::Select UserPermissionTable failed, {}", errorString);
        }
        return ret;
    }

    bool UpdateAppStatusTable(const std::string& sql, const std::string& op, sqlite3_callback cb, std::string& errorString)
    {
        errorString.clear();
        char errorBuffer[256] = {0};
        bool ret = m_DBManager->Execute(sql, cb, op.c_str(), errorString);
        if(!ret)
        {
            sprintf(errorBuffer, "ErrorMsg: %s, SQL: %s", errorString.c_str(), sql.c_str());
            FMTLOG(fmtlog::WRN, "UserDBManager::UpdateAppStatusTable failed, ErrorMsg:{} sql:{}", errorString, sql);
        }
        else
        {
            sprintf(errorBuffer, "SQL: %s", sql.c_str());
            FMTLOG(fmtlog::INF, "UserDBManager::UpdateAppStatusTable successed, sql:{}", sql);
        }
        errorString = errorBuffer;
        return ret;
    }

    bool QueryAppStatus(sqlite3_callback cb, std::string& errorString)
    {
        std::string SQL_SELECT_APP_STATUS = "SELECT * FROM AppStatusTable;";
        bool ret = m_DBManager->Execute(SQL_SELECT_APP_STATUS, cb, "SELECT", errorString);
        if(!ret)
        {
            FMTLOG(fmtlog::WRN, "UserDBManager::QueryAppStatus failed, {}", errorString);
        }
        return ret;
    }
private:
    UserDBManager() {}
    UserDBManager &operator=(const UserDBManager&);
    UserDBManager(const UserDBManager&);
private:
    Utils::SQLiteManager* m_DBManager;
};


#endif // USERDBMANAGER_HPP