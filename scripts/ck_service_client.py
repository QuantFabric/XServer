import pandas as pd
import time
import datetime
import os
import sys
import clickhouse_driver # type: ignore
from loguru import logger # type: ignore
from clickhouse_client import ClickHouseClient

class CKServiceClient(ClickHouseClient):
    
    def __init__(self, host, port, user, password):
        super().__init__(host=host, port=port, user=user, password=password)
        self.batch_insert_size = 100000
    
    def create_order_status_table(self):
        SQL = """CREATE TABLE IF NOT EXISTS QuantServer.OrderStatusTable ( 
            Colo String,
            Broker String,
            Product String,
            Account String,
            Ticker String,
            ExchangeID String,
            BusinessType Int32,
            OrderRef String,
            OrderSysID String,
            OrderLocalID String,
            OrderToken Int64,
            EngineID Int64,
            UserReserved1 Int64,
            UserReserved2 Int64,
            OrderType Int32,
            OrderSide Int32,
            OrderStatus Int32,
            SendPrice Decimal(15, 5),
            SendVolume Int64,
            TotalTradedVolume Int64,
            TradedAvgPrice Decimal(15, 5),
            TradedVolume Int64,
            TradedPrice Decimal(15, 5),
            CanceledVolume Int64,
            Commission Decimal(15, 5),
            RecvMarketTime DateTime64(6),
            SendTime DateTime64(6),
            InsertTime DateTime64(6),
            BrokerACKTime DateTime64(6),
            ExchangeACKTime DateTime64(6),
            RiskID String,
            Trader String,
            ErrorID Int32,
            ErrorMsg String,
            UpdateTime DateTime64(6)
        ) ENGINE = ReplacingMergeTree(UpdateTime)
        ORDER BY (Account, Ticker, OrderRef, OrderSysID)
        PARTITION BY toYYYYMM(SendTime)
        SETTINGS index_granularity = 8192;"""
        self.execute(query=SQL, params=None)
        logger.info(f"create QuantServer.OrderStatusTable")
            
    def update_order_status_table(self, data: pd.DataFrame):
        if data.empty: 
            return        
        columns = data.columns.to_list()
        lines = list()
        for row in data.itertuples(index=False):
            line = list()
            for column in columns:
                line.append(getattr(row, column))
            lines.append(tuple(line))
        SQL = f"INSERT INTO QuantServer.OrderStatusTable ({','.join(columns)}) VALUES"
        start_time = time.time()
        for i in range(0, len(lines), self.batch_insert_size):
            lines_splice = lines[i:i + self.batch_insert_size]
            self.batch_insert(SQL, lines_splice)
        end_time = time.time()
        logger.info(f"update QuantServer.OrderStatusTable 耗时：{round(end_time-start_time, 2)}s 写入速度:{round(len(data)/(end_time-start_time), 5)}msg/s")
            
    def query_order_status_table(self, tickers=None, start_date=None, end_date=None)->pd.DataFrame:
        start_date = start_date or "2020-01-01"
        end_date = end_date or datetime.datetime.now().strftime("%Y-%m-%d")
        where = "SendTime >= %s AND SendTime <= %s"
        params = [start_date, end_date]
        if tickers:
            if isinstance(tickers, str):
                tickers = [tickers]
            placeholders = ','.join(['%s'] * len(tickers))
            where += f" AND Ticker IN ({placeholders})"
            params.extend(tickers)
        SQL = f"SELECT * FROM QuantServer.OrderStatusTable WHERE {where} ORDER BY (Account, Ticker, OrderRef, OrderSysID, SendTime)"
        _start_time = time.time()
        results = self.execute(query=SQL, params=params)
        _end_time = time.time()
        columns=["Colo", "Broker", "Product", "Account", "Ticker", "ExchangeID", "BusinessType", "OrderRef", 
                 "OrderSysID", "OrderLocalID", "OrderToken", "EngineID", "UserReserved1", "UserReserved2", "OrderType", 
                 "OrderSide", "OrderStatus",  "SendPrice", "SendVolume", "TotalTradedVolume", "TradedAvgPrice", 
                 "TradedVolume", "TradedPrice", "CanceledVolume", "Commission", "RecvMarketTime", "SendTime", "InsertTime", 
                 "BrokerACKTime", "ExchangeACKTime", "RiskID", "Trader", "ErrorID", "ErrorMsg", "UpdateTime"]
        df = pd.DataFrame(results, columns=columns)
        logger.info(f"query QuantServer.OrderStatusTable 耗时：{round(_end_time-_start_time, 2)}s 读取速度:{round(len(df)/(_end_time-_start_time), 2)}msg/s")
        return df
    
    def create_account_fund_table(self):
        SQL = """CREATE TABLE IF NOT EXISTS QuantServer.AccountFundTable ( 
            Colo String,
            Broker String,
            Product String,
            Account String,
            BusinessType Int32,
            Deposit Decimal(18, 5),
            Withdraw Decimal(18, 5),
            CurrMargin Decimal(18, 5),
            Commission Decimal(18, 5),
            CloseProfit Decimal(18, 5),
            PositionProfit Decimal(18, 5),
            Available Decimal(18, 5),
            WithdrawQuota Decimal(18, 5),
            ExchangeMargin Decimal(18, 5),
            Balance Decimal(18, 5),
            PreBalance Decimal(18, 5),
            UpdateTime DateTime64(6),
            TradingDay Date DEFAULT toDate(UpdateTime)
        ) ENGINE = ReplacingMergeTree(UpdateTime)
        ORDER BY (Colo, Account, TradingDay)
        PARTITION BY toYYYYMM(TradingDay)
        SETTINGS index_granularity = 8192;"""
        self.execute(query=SQL, params=None)
        logger.info(f"create QuantServer.AccountFundTable")
            
    def update_account_fund_table(self, data: pd.DataFrame):    
        if data.empty: 
            return      
        columns = data.columns.to_list()
        lines = list()
        for row in data.itertuples(index=False):
            line = list()
            for column in columns:
                line.append(getattr(row, column))
            lines.append(tuple(line))
        SQL = f"INSERT INTO QuantServer.AccountFundTable ({','.join(columns)}) VALUES"
        start_time = time.time()
        for i in range(0, len(lines), self.batch_insert_size):
            lines_splice = lines[i:i + self.batch_insert_size]
            self.batch_insert(SQL, lines_splice)
        end_time = time.time()
        logger.info(f"update QuantServer.AccountFundTable 耗时：{round(end_time-start_time, 2)}s 写入速度:{round(len(data)/(end_time-start_time), 5)}msg/s")
            
    def query_account_fund_table(self, start_date=None, end_date=None)->pd.DataFrame:
        start_date = start_date or "2020-01-01"
        end_date = end_date or datetime.datetime.now().strftime("%Y-%m-%d")
        params = [start_date, end_date]
        SQL = f"""
                SELECT * FROM QuantServer.AccountFundTable FINAL
                WHERE TradingDay >= %s AND TradingDay <= %s
                ORDER BY (Colo, Account, TradingDay) ASC;
              """
        _start_time = time.time()
        results = self.execute(query=SQL, params=params)
        _end_time = time.time()
        columns=["Colo", "Broker", "Product", "Account", "BusinessType", "Deposit", "Withdraw", "CurrMargin", 
                 "Commission", "CloseProfit", "PositionProfit", "Available", "WithdrawQuota", "ExchangeMargin", "Balance", 
                 "PreBalance", "UpdateTime"]
        df = pd.DataFrame(results, columns=columns)
        logger.info(f"query QuantServer.AccountFundTable 耗时：{round(_end_time-_start_time, 2)}s 读取速度:{round(len(df)/(_end_time-_start_time), 2)}msg/s")
        return df

    def create_future_position_table(self):
        SQL = """CREATE TABLE IF NOT EXISTS QuantServer.FuturePositionTable ( 
            Colo String,
            Broker String,
            Product String,
            Account String,
            Ticker String,
            ExchangeID String,
            BusinessType Int32,
            LongTdVolume Int64,
            LongYdVolume Int64,
            LongOpenVolume Int64,
            LongOpeningVolume Int64,
            LongClosingTdVolume Int64,
            LongClosingYdVolume Int64,
            ShortTdVolume Int64,
            ShortYdVolume Int64,
            ShortOpenVolume Int64,
            ShortOpeningVolume Int64,
            ShortClosingTdVolume Int64,
            ShortClosingYdVolume Int64,
            UpdateTime DateTime64(6),
            TradingDay Date DEFAULT toDate(UpdateTime)
        ) ENGINE =  ReplacingMergeTree(UpdateTime)
        ORDER BY (Colo, Account, Ticker, TradingDay)
        PARTITION BY toYYYYMM(TradingDay)
        SETTINGS index_granularity = 8192;"""
        self.execute(query=SQL, params=None)
        logger.info(f"create QuantServer.FuturePositionTable")
            
    def update_future_position_table(self, data: pd.DataFrame):   
        if data.empty: 
            return       
        columns = data.columns.to_list()
        lines = list()
        for row in data.itertuples(index=False):
            line = list()
            for column in columns:
                line.append(getattr(row, column))
            lines.append(tuple(line))
        SQL = f"INSERT INTO QuantServer.FuturePositionTable ({','.join(columns)}) VALUES"
        start_time = time.time()
        for i in range(0, len(lines), self.batch_insert_size):
            lines_splice = lines[i:i + self.batch_insert_size]
            self.batch_insert(SQL, lines_splice)
        end_time = time.time()
        logger.info(f"update QuantServer.FuturePositionTable 耗时：{round(end_time-start_time, 2)}s 写入速度:{round(len(data)/(end_time-start_time), 5)}msg/s")
            
    def query_future_position_table(self, tickers=None, start_date=None, end_date=None)->pd.DataFrame:
        start_date = start_date or "2020-01-01"
        end_date = end_date or datetime.datetime.now().strftime("%Y-%m-%d")
        where = "TradingDay >= %s AND TradingDay <= %s"
        params = [start_date, end_date]
        if tickers:
            if isinstance(tickers, str):
                tickers = [tickers]
            placeholders = ','.join(['%s'] * len(tickers))
            where += f" AND Ticker IN ({placeholders})"
            params.extend(tickers)
        SQL = f"SELECT * FROM QuantServer.FuturePositionTable WHERE {where} ORDER BY (Colo, Account, Ticker, TradingDay)"
        _start_time = time.time()
        results = self.execute(query=SQL, params=params)
        _end_time = time.time()
        columns=["Colo", "Broker", "Product", "Account", "Ticker", "ExchangeID", "BusinessType", "LongTdVolume", "LongYdVolume", "LongOpenVolume", 
                 "LongOpeningVolume", "LongClosingTdVolume", "LongClosingYdVolume", "ShortTdVolume", "ShortYdVolume", "ShortOpenVolume", "ShortOpeningVolume", 
                 "ShortClosingTdVolume", "ShortClosingYdVolume", "UpdateTime"]
        df = pd.DataFrame(results, columns=columns)
        logger.info(f"query QuantServer.FuturePositionTable 耗时：{round(_end_time-_start_time, 2)}s 读取速度:{round(len(df)/(_end_time-_start_time), 2)}msg/s")
        return df

    def create_stock_position_table(self):
        SQL = """CREATE TABLE IF NOT EXISTS QuantServer.StockPositionTable ( 
            Colo String,
            Broker String,
            Product String,
            Account String,
            Ticker String,
            ExchangeID String,
            BusinessType Int32,
            LongYdPosition Int64,
            LongPosition Int64,
            LongTdBuy Int64,
            LongTdSell Int64,
            MarginYdPosition Int64,
            MarginPosition Int64,
            MarginTdBuy Int64,
            MarginTdSell Int64,
            ShortYdPosition Int64,
            ShortPosition Int64,
            ShortTdSell Int64,
            ShortTdBuy Int64,
            ShortDirectRepaid Int64,
            SpecialPositionAvl Int64,
            UpdateTime DateTime64(6),
            TradingDay Date DEFAULT toDate(UpdateTime)
        ) ENGINE = ReplacingMergeTree(UpdateTime)
        ORDER BY (Colo, Account, Ticker, TradingDay)
        PARTITION BY toYYYYMM(TradingDay)
        SETTINGS index_granularity = 8192;"""
        self.execute(query=SQL, params=None)
        logger.info(f"create QuantServer.StockPositionTable")
            
    def update_stock_position_table(self, data: pd.DataFrame): 
        if data.empty: 
            return         
        columns = data.columns.to_list()
        lines = list()
        for row in data.itertuples(index=False):
            line = list()
            for column in columns:
                line.append(getattr(row, column))
            lines.append(tuple(line))
        SQL = f"INSERT INTO QuantServer.StockPositionTable ({','.join(columns)}) VALUES"
        start_time = time.time()
        for i in range(0, len(lines), self.batch_insert_size):
            lines_splice = lines[i:i + self.batch_insert_size]
            self.batch_insert(SQL, lines_splice)
        end_time = time.time()
        logger.info(f"update QuantServer.StockPositionTable 耗时：{round(end_time-start_time, 2)}s 写入速度:{round(len(data)/(end_time-start_time), 5)}msg/s")
            
    def query_stock_position_table(self, tickers=None, start_date=None, end_date=None)->pd.DataFrame:
        start_date = start_date or "2020-01-01"
        end_date = end_date or datetime.datetime.now().strftime("%Y-%m-%d")
        where = "TradingDay >= %s AND TradingDay <= %s"
        params = [start_date, end_date]
        if tickers:
            if isinstance(tickers, str):
                tickers = [tickers]
            placeholders = ','.join(['%s'] * len(tickers))
            where += f" AND Ticker IN ({placeholders})"
            params.extend(tickers)
        SQL = f"SELECT * FROM QuantServer.StockPositionTable WHERE {where} ORDER BY (Colo, Account, Ticker, TradingDay)"
        _start_time = time.time()
        results = self.execute(query=SQL, params=params)
        _end_time = time.time()
        columns=["Colo", "Broker", "Product", "Account", "Ticker", "ExchangeID", "BusinessType", "LongYdPosition", "LongPosition", "LongTdBuy", 
                 "LongTdSell", "MarginYdPosition", "MarginPosition", "MarginTdBuy", "MarginTdSell", "ShortYdPosition", "ShortPosition", 
                 "ShortTdSell", "ShortTdBuy", "ShortDirectRepaid", "SpecialPositionAvl", "UpdateTime"]
        df = pd.DataFrame(results, columns=columns)
        logger.info(f"query QuantServer.StockPositionTable 耗时：{round(_end_time-_start_time, 2)}s 读取速度:{round(len(df)/(_end_time-_start_time), 2)}msg/s")
        return df

    def create_risk_event_table(self):
        SQL = """CREATE TABLE IF NOT EXISTS QuantServer.RiskEventTable ( 
            Colo String,
            Broker String,
            Product String,
            Account String,
            Ticker String,
            ExchangeID String,
            RiskID String,
            Trader String,
            ReportType Int32,
            BusinessType Int32,
            FlowLimit Int32,
            CancelCount Int32,
            CancelLimit Int32,
            OrderCount Int32,
            OrderLimit Int32,
            OrderCancelLimit Int32,
            EngineID Int32,
            LongVolume Int32,
            ShortVolume Int32,
            LongLimit Int32,
            ShortLimit Int32,
            ExposureLowerLimit Int32,
            ExposureUpperLimit Int32,
            LockSide Int32,
            Event String,
            UpdateTime DateTime64(6),
            EventDate Date DEFAULT toDate(UpdateTime)
        ) ENGINE = MergeTree()
        ORDER BY (Colo, Account, EventDate, UpdateTime)
        PARTITION BY toYYYYMM(EventDate)
        SETTINGS index_granularity = 8192;"""
        self.execute(query=SQL, params=None)
        logger.info(f"create QuantServer.RiskEventTable")
            
    def update_risk_event_table(self, data: pd.DataFrame): 
        if data.empty: 
            return         
        columns = data.columns.to_list()
        lines = list()
        for row in data.itertuples(index=False):
            line = list()
            for column in columns:
                line.append(getattr(row, column))
            lines.append(tuple(line))
        SQL = f"INSERT INTO QuantServer.RiskEventTable ({','.join(columns)}) VALUES"
        start_time = time.time()
        for i in range(0, len(lines), self.batch_insert_size):
            lines_splice = lines[i:i + self.batch_insert_size]
            self.batch_insert(SQL, lines_splice)
        end_time = time.time()
        logger.info(f"update QuantServer.RiskEventTable 耗时：{round(end_time-start_time, 2)}s 写入速度:{round(len(data)/(end_time-start_time), 5)}msg/s")
            
    def query_risk_event_table(self, tickers=None, start_date=None, end_date=None)->pd.DataFrame:
        start_date = start_date or "2020-01-01"
        end_date = end_date or datetime.datetime.now().strftime("%Y-%m-%d")
        where = "UpdateTime >= %s AND UpdateTime <= %s"
        params = [start_date, end_date]
        if tickers:
            if isinstance(tickers, str):
                tickers = [tickers]
            placeholders = ','.join(['%s'] * len(tickers))
            where += f" AND Ticker IN ({placeholders})"
            params.extend(tickers)
        SQL = f"SELECT * FROM QuantServer.RiskEventTable WHERE {where} ORDER BY (Colo, Account, EventDate, UpdateTime)"
        _start_time = time.time()
        results = self.execute(query=SQL, params=params)
        _end_time = time.time()
        columns=["Colo", "Broker", "Product", "Account", "Ticker", "ExchangeID", "RiskID", "Trader", "ReportType", "BusinessType", "FlowLimit", "CancelCount", "CancelLimit", 
                 "OrderCount", "OrderLimit", "OrderCancelLimit", "EngineID", "LongVolume", "ShortVolume", "LongLimit", 
                 "ShortLimit", "ExposureLowerLimit", "ExposureUpperLimit", "LockSide", "Event", "UpdateTime"]
        df = pd.DataFrame(results, columns=columns)
        logger.info(f"query QuantServer.RiskEventTable 耗时：{round(_end_time-_start_time, 2)}s 读取速度:{round(len(df)/(_end_time-_start_time), 2)}msg/s")
        return df

    def create_event_log_table(self):
        SQL = """CREATE TABLE IF NOT EXISTS QuantServer.EventLogTable ( 
            Colo String,
            Broker String,
            Product String,
            Account String,
            Ticker String,
            ExchangeID String,
            App String,
            Event String,
            Level Int32,
            UpdateTime DateTime64(6)
        ) ENGINE = MergeTree()
        ORDER BY (Colo, Account, Ticker, UpdateTime)
        PARTITION BY toYYYYMM(UpdateTime)
        SETTINGS index_granularity = 8192;"""
        self.execute(query=SQL, params=None)
        logger.info(f"create QuantServer.EventLogTable")
            
    def update_event_log_table(self, data: pd.DataFrame):   
        if data.empty: 
            return       
        columns = data.columns.to_list()
        lines = list()
        for row in data.itertuples(index=False):
            line = list()
            for column in columns:
                line.append(getattr(row, column))
            lines.append(tuple(line))
        SQL = f"INSERT INTO QuantServer.EventLogTable ({','.join(columns)}) VALUES"
        start_time = time.time()
        for i in range(0, len(lines), self.batch_insert_size):
            lines_splice = lines[i:i + self.batch_insert_size]
            self.batch_insert(SQL, lines_splice)
        end_time = time.time()
        logger.info(f"update QuantServer.EventLogTable 耗时：{round(end_time-start_time, 2)}s 写入速度:{round(len(data)/(end_time-start_time), 5)}msg/s")
            
    def query_event_log_table(self, start_date=None, end_date=None)->pd.DataFrame:
        start_date = start_date or "2020-01-01"
        end_date = end_date or datetime.datetime.now().strftime("%Y-%m-%d")
        where = "UpdateTime >= %s AND UpdateTime <= %s"
        params = [start_date, end_date]
        SQL = f"SELECT * FROM QuantServer.EventLogTable WHERE {where} ORDER BY (Colo, Account, Ticker, UpdateTime)"
        _start_time = time.time()
        results = self.execute(query=SQL, params=params)
        _end_time = time.time()
        columns=["Colo", "Broker", "Product", "Account", "Ticker", "ExchangeID", "App", "Event", "Level", "UpdateTime"]
        df = pd.DataFrame(results, columns=columns)
        logger.info(f"query QuantServer.EventLogTable 耗时：{round(_end_time-_start_time, 2)}s 读取速度:{round(len(df)/(_end_time-_start_time), 2)}msg/s")
        return df

    def create_colo_status_table(self):
        SQL = """CREATE TABLE IF NOT EXISTS QuantServer.ColoStatusTable ( 
            Colo String,
            OSVersion String,
            KernelVersion String,
            LoadMin1 Float64,
            LoadMin5 Float64,
            LoadMin15 Float64,
            CPUS Int32,
            CPUUserRate Float64,
            CPUSysRate Float64,
            CPUIdleRate Float64,
            CPUIOWaitRate Float64,
            CPUIrqRate Float64,
            CPUSoftIrqRate Float64,
            CPUUsedRate Float64,
            MemoryTotal Float64,
            MemoryFree Float64,
            MemoryUsedRate Float64,
            DiskTotal Float64,
            DiskFree Float64,
            DiskUsedRate Float64,
            DiskMount1UsedRate Float64,
            DiskMount2UsedRate Float64,
            UpdateTime DateTime64(6)
        ) ENGINE = MergeTree()
        ORDER BY (Colo, UpdateTime)
        PARTITION BY toYYYYMM(UpdateTime)
        SETTINGS index_granularity = 8192;"""
        self.execute(query=SQL, params=None)
        logger.info(f"create QuantServer.ColoStatusTable")
            
    def update_colo_status_table(self, data: pd.DataFrame): 
        if data.empty: 
            return         
        columns = data.columns.to_list()
        lines = list()
        for row in data.itertuples(index=False):
            line = list()
            for column in columns:
                line.append(getattr(row, column))
            lines.append(tuple(line))
        SQL = f"INSERT INTO QuantServer.ColoStatusTable ({','.join(columns)}) VALUES"
        start_time = time.time()
        for i in range(0, len(lines), self.batch_insert_size):
            lines_splice = lines[i:i + self.batch_insert_size]
            self.batch_insert(SQL, lines_splice)
        end_time = time.time()
        logger.info(f"update QuantServer.ColoStatusTable 耗时：{round(end_time-start_time, 2)}s 写入速度:{round(len(data)/(end_time-start_time), 5)}msg/s")
            
    def query_colo_status_table(self, start_date=None, end_date=None)->pd.DataFrame:
        start_date = start_date or "2020-01-01"
        end_date = end_date or datetime.datetime.now().strftime("%Y-%m-%d")
        where = "UpdateTime >= %s AND UpdateTime <= %s"
        params = [start_date, end_date]
        SQL = f"SELECT * FROM QuantServer.ColoStatusTable WHERE {where} ORDER BY (Colo, UpdateTime)"
        _start_time = time.time()
        results = self.execute(query=SQL, params=params)
        _end_time = time.time()
        columns=["Colo", "OSVersion", "KernelVersion", "LoadMin1", "LoadMin5", "LoadMin15", "CPUS", "CPUUserRate", "CPUSysRate", "CPUIdleRate",
                "CPUIOWaitRate", "CPUIrqRate", "CPUSoftIrqRate", "CPUUsedRate", "MemoryTotal", "MemoryFree", "MemoryUsedRate", "DiskTotal", 
                "DiskFree", "DiskUsedRate", "DiskMount1UsedRate", "DiskMount2UsedRate", "UpdateTime"]
        df = pd.DataFrame(results, columns=columns)
        logger.info(f"query QuantServer.ColoStatusTable 耗时：{round(_end_time-_start_time, 2)}s 读取速度:{round(len(df)/(_end_time-_start_time), 2)}msg/s")
        return df

    def create_app_status_table(self):
        SQL = """CREATE TABLE IF NOT EXISTS QuantServer.AppStatusTable ( 
            Colo String,
            Account String,
            AppName String,
            PID Int32,
            Status String,
            UsedCPURate Float64,
            UsedMemSize Float64,
            StartTime DateTime64(6),
            LastStartTime DateTime64(6),
            CommitID String,
            UtilsCommitID String,
            APIVersion String,
            StartScript String,
            UpdateTime DateTime64(6)
        ) ENGINE = MergeTree()
        ORDER BY (Colo, Account, AppName, UpdateTime)
        PARTITION BY toYYYYMM(UpdateTime)
        SETTINGS index_granularity = 8192;"""
        self.execute(query=SQL, params=None)
        logger.info(f"create QuantServer.AppStatusTable")
            
    def update_app_status_table(self, data: pd.DataFrame):   
        if data.empty: 
            return       
        columns = data.columns.to_list()
        lines = list()
        for row in data.itertuples(index=False):
            line = list()
            for column in columns:
                line.append(getattr(row, column))
            lines.append(tuple(line))
        SQL = f"INSERT INTO QuantServer.AppStatusTable ({','.join(columns)}) VALUES"
        start_time = time.time()
        for i in range(0, len(lines), self.batch_insert_size):
            lines_splice = lines[i:i + self.batch_insert_size]
            self.batch_insert(SQL, lines_splice)
        end_time = time.time()
        logger.info(f"update QuantServer.AppStatusTable 耗时：{round(end_time-start_time, 2)}s 写入速度:{round(len(data)/(end_time-start_time), 5)}msg/s")
            
    def query_app_status_table(self, start_date=None, end_date=None)->pd.DataFrame:
        start_date = start_date or "2020-01-01"
        end_date = end_date or datetime.datetime.now().strftime("%Y-%m-%d")
        where = "UpdateTime >= %s AND UpdateTime <= %s"
        params = [start_date, end_date]
        SQL = f"SELECT * FROM QuantServer.AppStatusTable WHERE {where} ORDER BY (Colo,  Account, AppName, UpdateTime)"
        _start_time = time.time()
        results = self.execute(query=SQL, params=params)
        _end_time = time.time()
        columns=["Colo", "Account", "AppName", "PID", "Status", "UsedCPURate", "UsedMemSize", "StartTime", "LastStartTime", "CommitID",
                "UtilsCommitID", "APIVersion", "StartScript", "UpdateTime"]
        df = pd.DataFrame(results, columns=columns)
        logger.info(f"query QuantServer.AppStatusTable 耗时：{round(_end_time-_start_time, 2)}s 读取速度:{round(len(df)/(_end_time-_start_time), 2)}msg/s")
        return df
