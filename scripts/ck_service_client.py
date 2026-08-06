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
    
    def create_future_level2_table(self, table:str):
        SQL = """CREATE TABLE IF NOT EXISTS Future.{} ( 
            Ticker String,
            TimeStamp UInt64 CODEC(DoubleDelta, ZSTD(3)),
            TradingDay Date,
            ActionDay Date,
            UpdateTime String,
            MillSec UInt32 CODEC(Delta, ZSTD(3)),
            ExchangeID String,
            LastPrice Float64 CODEC(Delta, ZSTD(3)),
            Volume Int32 CODEC(Delta, ZSTD(3)),
            Turnover Float64 CODEC(Delta, ZSTD(3)),
            OpenPrice Float64 CODEC(Delta, ZSTD(3)),
            ClosePrice Float64 CODEC(Delta, ZSTD(3)),
            PreClosePrice Float64 CODEC(Delta, ZSTD(3)),
            OpenInterest UInt64 CODEC(Delta, ZSTD(3)),
            PreOpenInterest UInt64 CODEC(Delta, ZSTD(3)),
            SettlementPrice Float64 CODEC(Delta, ZSTD(3)),
            PreSettlementPrice Float64 CODEC(Delta, ZSTD(3)),
            CurrDelta Float64 CODEC(Delta, ZSTD(3)),
            PreDelta Float64 CODEC(Delta, ZSTD(3)),
            HighestPrice Float64 CODEC(Delta, ZSTD(3)),
            LowestPrice Float64 CODEC(Delta, ZSTD(3)),
            UpperLimitPrice Float64 CODEC(Delta, ZSTD(3)),
            LowerLimitPrice Float64 CODEC(Delta, ZSTD(3)),
            AveragePrice Float64 CODEC(Delta, ZSTD(3)),
            BidPrice1 Float64 CODEC(Delta, ZSTD(3)),
            BidVolume1 UInt32 CODEC(Delta, ZSTD(3)),
            AskPrice1 Float64 CODEC(Delta, ZSTD(3)),
            AskVolume1 UInt32 CODEC(Delta, ZSTD(3)),
            BidPrice2 Float64 CODEC(Delta, ZSTD(3)),
            BidVolume2 UInt32 CODEC(Delta, ZSTD(3)),
            AskPrice2 Float64 CODEC(Delta, ZSTD(3)),
            AskVolume2 UInt32 CODEC(Delta, ZSTD(3)),
            BidPrice3 Float64 CODEC(Delta, ZSTD(3)),
            BidVolume3 UInt32 CODEC(Delta, ZSTD(3)),
            AskPrice3 Float64 CODEC(Delta, ZSTD(3)),
            AskVolume3 UInt32 CODEC(Delta, ZSTD(3)),
            BidPrice4 Float64 CODEC(Delta, ZSTD(3)),
            BidVolume4 UInt32 CODEC(Delta, ZSTD(3)),
            AskPrice4 Float64 CODEC(Delta, ZSTD(3)),
            AskVolume4 UInt32 CODEC(Delta, ZSTD(3)),
            BidPrice5 Float64 CODEC(Delta, ZSTD(3)),
            BidVolume5 UInt32 CODEC(Delta, ZSTD(3)),
            AskPrice5 Float64 CODEC(Delta, ZSTD(3)),
            AskVolume5 UInt32 CODEC(Delta, ZSTD(3)),
        ) ENGINE = ReplacingMergeTree(TimeStamp)
        ORDER BY (Ticker, TimeStamp)
        PRIMARY KEY (Ticker, TimeStamp)
        PARTITION BY toYYYYMM(TradingDay)
        SETTINGS index_granularity = 8192;""".format(table)
        self.execute(query=SQL, params=None)
        logger.info(f"create Future.{table}")
            
    def update_future_level2_table(self, table:str, data: pd.DataFrame):        
        columns = data.columns.to_list()
        lines = list()
        for row in data.itertuples(index=False):
            line = list()
            for column in columns:
                line.append(getattr(row, column))
            lines.append(tuple(line))
        SQL = f"INSERT INTO Future.{table} ({','.join(columns)}) VALUES"
        start_time = time.time()
        for i in range(0, len(lines), self.batch_insert_size):
            lines_splice = lines[i:i + self.batch_insert_size]
            self.batch_insert(SQL, lines_splice)
        end_time = time.time()
        logger.info(f"update Future.{table} 耗时：{round(end_time-start_time, 2)}s 写入速度:{round(len(data)/(end_time-start_time), 5)}msg/s")
            
    def query_future_level2_table(self, table:str, tickers=None, start_date=None, end_date=None)->pd.DataFrame:
        if start_date is None:
            start_date = "2000-01-01"
        if end_date is None:
            end_date = datetime.datetime.now().strftime("%Y-%m-%d")
        SQL = f"""
                WITH toDate('{start_date}') AS start_date, toDate('{end_date}') AS end_date
                SELECT * FROM Future.{table}
                WHERE TradingDay >= start_date AND TradingDay <= end_date
                ORDER BY (Ticker,TimeStamp) ASC
                LIMIT 1 BY (Ticker,TimeStamp);
              """
        _start_time = time.time()
        results = self.execute(query=SQL, params=None)
        _end_time = time.time()
        columns=["Ticker", "TimeStamp", "TradingDay", "ActionDay", "UpdateTime", "MillSec", "ExchangeID", "LastPrice", 
                 "Volume", "Turnover", "OpenPrice", "ClosePrice", "PreClosePrice", "SettlementPrice", "PreSettlementPrice", 
                 "OpenInterest", "PreOpenInterest",  "CurrDelta", "PreDelta", "HighestPrice", "LowestPrice", 
                 "UpperLimitPrice", "LowerLimitPrice", "AveragePrice", "BidPrice1", "BidVolume1", "AskPrice1", "AskVolume1", 
                 "BidPrice2", "BidVolume2", "AskPrice2", "AskVolume2", "BidPrice3", "BidVolume3", "AskPrice3", "AskVolume3", 
                 "BidPrice4", "BidVolume4", "AskPrice4", "AskVolume4", "BidPrice5", "BidVolume5", "AskPrice5", "AskVolume5"]
        df = pd.DataFrame(results, columns=columns)
        logger.info(f"query Future.{table} 耗时：{round(_end_time-_start_time, 2)}s 读取速度:{round(len(df)/(_end_time-_start_time), 2)}msg/s")
        if tickers:
            if isinstance(tickers, str):
                tickers = [tickers]
            df = df.loc[df['Ticker'].isin(tickers)]
        return df
    
    def create_orderimbalance_table(self, table:str):
        SQL = """CREATE TABLE IF NOT EXISTS Future.{} ( 
            Ticker String,
            TimeStamp UInt64 CODEC(DoubleDelta, ZSTD(3)),
            TradingDay Date,
            ActionDay Date,
            UpdateTime String,
            MillSec UInt32 CODEC(Delta, ZSTD(3)),
            ExchangeID String,
            Spread Float64 CODEC(Delta, ZSTD(3)),
            DI1 Float64 CODEC(Delta, ZSTD(3)),
            DI2 Float64 CODEC(Delta, ZSTD(3)),
            DI3 Float64 CODEC(Delta, ZSTD(3)),
            DI4 Float64 CODEC(Delta, ZSTD(3)),
            DI5 Float64 CODEC(Delta, ZSTD(3)),
            OI Float64 CODEC(Delta, ZSTD(3)),
            VOI Float64 CODEC(Delta, ZSTD(3)),
            PWP Float64 CODEC(Delta, ZSTD(3)),
            VolumeAdd Float64 CODEC(Delta, ZSTD(3)),
            InterestAdd Float64 CODEC(Delta, ZSTD(3)),
        ) ENGINE = ReplacingMergeTree(TimeStamp)
        ORDER BY (Ticker, TimeStamp)
        PRIMARY KEY (Ticker, TimeStamp)
        PARTITION BY toYYYYMM(TradingDay)
        SETTINGS index_granularity = 8192;""".format(table)
        self.execute(query=SQL, params=None)
        logger.info(f"create Future.{table}")
            
    def update_orderimbalance_table(self, table:str, data: pd.DataFrame):        
        columns = data.columns.to_list()
        lines = list()
        for row in data.itertuples(index=False):
            line = list()
            for column in columns:
                line.append(getattr(row, column))
            lines.append(tuple(line))
        SQL = f"INSERT INTO Future.{table} ({','.join(columns)}) VALUES"
        start_time = time.time()
        for i in range(0, len(lines), self.batch_insert_size):
            lines_splice = lines[i:i + self.batch_insert_size]
            self.batch_insert(SQL, lines_splice)
        end_time = time.time()
        logger.info(f"update Future.{table} 耗时：{round(end_time-start_time, 2)}s 写入速度:{round(len(data)/(end_time-start_time), 5)}msg/s")
            
    def query_orderimbalance_table(self, table:str, tickers=None, start_date=None, end_date=None)->pd.DataFrame:
        if start_date is None:
            start_date = "2000-01-01"
        if end_date is None:
            end_date = datetime.datetime.now().strftime("%Y-%m-%d")
        SQL = f"""
                WITH toDate('{start_date}') AS start_date, toDate('{end_date}') AS end_date
                SELECT * FROM Future.{table}
                WHERE TradingDay >= start_date AND TradingDay <= end_date
                ORDER BY (Ticker,TimeStamp) ASC
                LIMIT 1 BY (Ticker,TimeStamp);
              """
        _start_time = time.time()
        results = self.execute(query=SQL, params=None)
        _end_time = time.time()
        columns=["Ticker", "TimeStamp", "TradingDay", "ActionDay", "UpdateTime", "MillSec", "ExchangeID", "Spread",
                 "DI1", "DI2", "DI3", "DI4", "DI5", "OI", "VOI", "PWP", "VolumeAdd", "InterestAdd"]
        df = pd.DataFrame(results, columns=columns)
        logger.info(f"query Future.{table} 耗时：{round(_end_time-_start_time, 2)}s 读取速度:{round(len(df)/(_end_time-_start_time), 2)}msg/s")
        if tickers:
            if isinstance(tickers, str):
                tickers = [tickers]
            df = df.loc[df['Ticker'].isin(tickers)]
        return df
    
    def create_1d_data_table(self, table:str):
        SQL = """CREATE TABLE IF NOT EXISTS Future.{} ( 
            Ticker String,
            TradingDay Date,
            OpenPrice Float64 CODEC(Delta, ZSTD(3)),
            HighestPrice Float64 CODEC(Delta, ZSTD(3)),
            LowestPrice Float64 CODEC(Delta, ZSTD(3)),
            ClosePrice Float64 CODEC(Delta, ZSTD(3)),
            Volume Int32 CODEC(Delta, ZSTD(3)),
            Turnover Float64 CODEC(Delta, ZSTD(3)),
            PreClosePrice Float64 CODEC(Delta, ZSTD(3)),
            SettlementPrice Float64 CODEC(Delta, ZSTD(3)),
            PreSettlementPrice Float64 CODEC(Delta, ZSTD(3)),
            OpenInterest Float64 CODEC(Delta, ZSTD(3)),
            UpperLimitPrice Float64 CODEC(Delta, ZSTD(3)),
            LowerLimitPrice Float64 CODEC(Delta, ZSTD(3)),
            DayOpen Float64 CODEC(Delta, ZSTD(3)),
            UpdateTime DateTime64,
        ) ENGINE = ReplacingMergeTree(UpdateTime)
        ORDER BY (Ticker, TradingDay)
        PRIMARY KEY (Ticker, TradingDay)
        PARTITION BY toYYYYMM(TradingDay)
        SETTINGS index_granularity = 8192;""".format(table)
        self.execute(query=SQL, params=None)
        logger.info(f"create Future.{table}")

    def update_1d_data_table(self, table:str, data: pd.DataFrame):        
        columns = data.columns.to_list()
        lines = list()
        for row in data.itertuples(index=False):
            line = list()
            for column in columns:
                line.append(getattr(row, column))
            line.append(datetime.datetime.now())
            lines.append(tuple(line))
        columns.append("UpdateTime")
        SQL = f"INSERT INTO Future.{table} ({','.join(columns)}) VALUES"
        start_time = time.time()
        for i in range(0, len(lines), self.batch_insert_size):
            lines_splice = lines[i:i + self.batch_insert_size]
            self.batch_insert(SQL, lines_splice)
        end_time = time.time()
        logger.info(f"update Future.{table} 耗时：{round(end_time-start_time, 2)}s 写入速度:{round(len(data)/(end_time-start_time), 5)}msg/s")
            
    def query_1d_data_table(self, table:str, tickers=None, start_date=None, end_date=None)->pd.DataFrame:
        if start_date is None:
            start_date = "2000-01-04"
        if end_date is None:
            end_date = datetime.datetime.now().strftime("%Y-%m-%d")
        SQL = f"""
                WITH toDate('{start_date}') AS start_date, toDate('{end_date}') AS end_date
                SELECT * FROM Future.{table}
                WHERE TradingDay >= start_date AND TradingDay <= end_date
                ORDER BY (Ticker,TradingDay) ASC
                LIMIT 1 BY (Ticker,TradingDay);
              """
        _start_time = time.time()
        results = self.execute(query=SQL, params=None)
        _end_time = time.time()
        columns=["Ticker", "TradingDay", "OpenPrice", "HighestPrice", "LowestPrice", "ClosePrice", 
                    "Volume", "Turnover", "PreClosePrice", "SettlementPrice", "PreSettlementPrice",
                    "OpenInterest", "UpperLimitPrice", "LowerLimitPrice", "DayOpen", 'UpdateTime']
        df = pd.DataFrame(results, columns=columns)
        logger.info(f"query Future.{table} 耗时：{round(_end_time-_start_time, 2)}s 读取速度:{round(len(df)/(_end_time-_start_time), 2)}msg/s")
        if tickers:
            if isinstance(tickers, str):
                tickers = [tickers]
            df = df.loc[df['Ticker'].isin(tickers)]
        return df

    def create_xmin_data_table(self, table:str):
        SQL = """CREATE TABLE IF NOT EXISTS Future.{} ( 
            Ticker String,
            TimeStamp DateTime64,
            TradingDay Date,
            OpenPrice Float64 CODEC(Delta, ZSTD(3)),
            HighestPrice Float64 CODEC(Delta, ZSTD(3)),
            LowestPrice Float64 CODEC(Delta, ZSTD(3)),
            ClosePrice Float64 CODEC(Delta, ZSTD(3)),
            Volume Int32 CODEC(Delta, ZSTD(3)),
            Turnover Float64 CODEC(Delta, ZSTD(3)),
            OpenInterest Float64 CODEC(Delta, ZSTD(3)),
            UpdateTime DateTime64,
        ) ENGINE = ReplacingMergeTree(UpdateTime)
        ORDER BY (Ticker, TimeStamp)
        PRIMARY KEY (Ticker, TimeStamp)
        PARTITION BY toYYYYMM(TradingDay)
        SETTINGS index_granularity = 8192;""".format(table)
        self.execute(query=SQL, params=None)
        logger.info(f"create Future.{table}")

    def update_xmin_data_table(self, table:str, data: pd.DataFrame):        
        columns = data.columns.to_list()
        lines = list()
        for row in data.itertuples(index=False):
            line = list()
            for column in columns:
                line.append(getattr(row, column))
            line.append(datetime.datetime.now())
            lines.append(tuple(line))
        columns.append("UpdateTime")
        SQL = f"INSERT INTO Future.{table} ({','.join(columns)}) VALUES"
        start_time = time.time()
        for i in range(0, len(lines), self.batch_insert_size):
            lines_splice = lines[i:i + self.batch_insert_size]
            self.batch_insert(SQL, lines_splice)
        end_time = time.time()
        logger.info(f"update Future.{table} 耗时：{round(end_time-start_time, 2)}s 写入速度:{round(len(data)/(end_time-start_time), 5)}msg/s")
            
    def query_xmin_data_table(self, table:str, tickers=None, start_date=None, end_date=None)->pd.DataFrame:
        if start_date is None:
            start_date = "2010-01-04"
        if end_date is None:
            end_date = datetime.datetime.now().strftime("%Y-%m-%d")
        SQL = f"""
                WITH toDate('{start_date}') AS start_date, toDate('{end_date}') AS end_date
                SELECT * FROM Future.{table}
                WHERE TradingDay >= start_date AND TradingDay <= end_date
                ORDER BY (Ticker,TimeStamp) ASC
                LIMIT 1 BY (Ticker,TimeStamp);
              """
        _start_time = time.time()
        results = self.execute(query=SQL, params=None)
        _end_time = time.time()
        columns=["Ticker", "TimeStamp", "TradingDay", "OpenPrice", "HighestPrice", "LowestPrice", "ClosePrice", 
                 "Volume", "Turnover", "OpenInterest", 'UpdateTime']
        df = pd.DataFrame(results, columns=columns)
        logger.info(f"query Future.{table} 耗时：{round(_end_time-_start_time, 2)}s 读取速度:{round(len(df)/(_end_time-_start_time), 2)}msg/s")
        if tickers:
            if isinstance(tickers, str):
                tickers = [tickers]
            df = df.loc[df['Ticker'].isin(tickers)]
        return df