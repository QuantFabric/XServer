import sys
sys.path.append(".")
import pack_message
import time
import signal
import datetime
import os
import struct
import yaml
import copy
from loguru import logger # type: ignore
from HPSocket import TcpPack
from HPSocket import helper
import HPSocket.pyhpsocket as HPSocket
import queue
recv_queue = queue.Queue()



def convert_to_message(data:bytes):
    msg_type, = struct.unpack('I', data[0:4]) 
    msg = pack_message.PackMessage()
    # 注意内存对齐
    if msg_type == pack_message.EMessageType.EOrderStatus:
        order_status_format = "16s 16s 16s 16s 20s 16s B 32s 32s 32s i i i i B B B d I I d I d I d 32s 32s 32s 32s 32s 16s 16s i 256s 32s"
        order_status_data = struct.unpack(order_status_format, data[8:772])
        msg.MessageType = pack_message.EMessageType.EOrderStatus
        msg.OrderStatus.Colo = order_status_data[0].decode('utf-8').strip('\x00')
        msg.OrderStatus.Broker = order_status_data[1].decode('utf-8').strip('\x00')
        msg.OrderStatus.Product = order_status_data[2].decode('utf-8').strip('\x00')
        msg.OrderStatus.Account = order_status_data[3].decode('utf-8').strip('\x00')
        msg.OrderStatus.Ticker = order_status_data[4].decode('utf-8').strip('\x00')
        msg.OrderStatus.ExchangeID = order_status_data[5].decode('utf-8').strip('\x00')
        msg.OrderStatus.BusinessType = order_status_data[6] % 256
        msg.OrderStatus.OrderRef = order_status_data[7].decode('utf-8').strip('\x00')
        msg.OrderStatus.OrderSysID = order_status_data[8].decode('utf-8').strip('\x00')
        msg.OrderStatus.OrderLocalID = order_status_data[9].decode('utf-8').strip('\x00')
        msg.OrderStatus.OrderToken = order_status_data[10]
        msg.OrderStatus.EngineID = order_status_data[11]
        msg.OrderStatus.UserReserved1 = order_status_data[12]
        msg.OrderStatus.UserReserved2 = order_status_data[13]
        msg.OrderStatus.OrderType = order_status_data[14] % 256
        msg.OrderStatus.OrderSide = order_status_data[15] % 256
        msg.OrderStatus.OrderStatus = order_status_data[16] % 256
        msg.OrderStatus.SendPrice = order_status_data[17]
        msg.OrderStatus.SendVolume = order_status_data[18]
        msg.OrderStatus.TotalTradedVolume = order_status_data[19]
        msg.OrderStatus.TradedAvgPrice = order_status_data[20]
        msg.OrderStatus.TradedVolume = order_status_data[21]
        msg.OrderStatus.TradedPrice = order_status_data[22]
        msg.OrderStatus.CanceledVolume = order_status_data[23]
        msg.OrderStatus.Commission = order_status_data[24]
        msg.OrderStatus.RecvMarketTime = order_status_data[25].decode('utf-8').strip('\x00')
        msg.OrderStatus.SendTime = order_status_data[26].decode('utf-8').strip('\x00')
        msg.OrderStatus.InsertTime = order_status_data[27].decode('utf-8').strip('\x00')
        msg.OrderStatus.BrokerACKTime = order_status_data[28].decode('utf-8').strip('\x00')
        msg.OrderStatus.ExchangeACKTime = order_status_data[29].decode('utf-8').strip('\x00')
        msg.OrderStatus.RiskID = order_status_data[30].decode('utf-8').strip('\x00')
        msg.OrderStatus.Trader = order_status_data[31].decode('utf-8').strip('\x00')
        msg.OrderStatus.ErrorID = order_status_data[32]
        msg.OrderStatus.ErrorMsg = order_status_data[33].decode('utf-8').strip('\x00')
        msg.OrderStatus.UpdateTime = order_status_data[34].decode('utf-8').strip('\x00')
    elif msg_type == pack_message.EMessageType.EAccountFund:
        account_fund_format = "16s 16s 16s 16s B d d d d d d d d d d d 32s"
        account_fund_data = struct.unpack(account_fund_format, data[8:200])
        msg.MessageType = pack_message.EMessageType.EAccountFund
        msg.AccountFund.Colo = account_fund_data[0].decode('utf-8').strip('\x00')
        msg.AccountFund.Broker = account_fund_data[1].decode('utf-8').strip('\x00')
        msg.AccountFund.Product = account_fund_data[2].decode('utf-8').strip('\x00')
        msg.AccountFund.Account = account_fund_data[3].decode('utf-8').strip('\x00')
        msg.AccountFund.BusinessType = account_fund_data[4]
        msg.AccountFund.Deposit = account_fund_data[5]
        msg.AccountFund.Withdraw = account_fund_data[6]
        msg.AccountFund.CurrMargin = account_fund_data[7]
        msg.AccountFund.Commission = account_fund_data[8]
        msg.AccountFund.CloseProfit = account_fund_data[9]
        msg.AccountFund.PositionProfit = account_fund_data[10]
        msg.AccountFund.Available = account_fund_data[11]
        msg.AccountFund.WithdrawQuota = account_fund_data[12]
        msg.AccountFund.ExchangeMargin = account_fund_data[13]
        msg.AccountFund.Balance = account_fund_data[14]
        msg.AccountFund.PreBalance = account_fund_data[15]
        msg.AccountFund.UpdateTime = account_fund_data[16].decode('utf-8').strip('\x00')
    elif msg_type == pack_message.EMessageType.EAccountPosition:
        account_position_format = "16s 16s 16s 16s 20s 16s B"
        account_position_data = struct.unpack(account_position_format, data[8:109])
        msg.MessageType = pack_message.EMessageType.EAccountPosition
        msg.AccountPosition.Colo = account_position_data[0].decode('utf-8').strip('\x00')
        msg.AccountPosition.Broker = account_position_data[1].decode('utf-8').strip('\x00')
        msg.AccountPosition.Product = account_position_data[2].decode('utf-8').strip('\x00')
        msg.AccountPosition.Account = account_position_data[3].decode('utf-8').strip('\x00')
        msg.AccountPosition.Ticker = account_position_data[4].decode('utf-8').strip('\x00')
        msg.AccountPosition.ExchangeID = account_position_data[5].decode('utf-8').strip('\x00')
        msg.AccountPosition.BusinessType = account_position_data[6] % 256
        if msg.AccountPosition.BusinessType == pack_message.EBusinessType.EFUTURE:
            account_position_format = "i i i i i i i i i i i i"
            account_position_data = struct.unpack(account_position_format, data[112:160])
            msg.AccountPosition.FuturePosition.LongTdVolume = account_position_data[0]
            msg.AccountPosition.FuturePosition.LongYdVolume = account_position_data[1]
            msg.AccountPosition.FuturePosition.LongOpenVolume = account_position_data[2]
            msg.AccountPosition.FuturePosition.LongOpeningVolume = account_position_data[3]
            msg.AccountPosition.FuturePosition.LongClosingTdVolume = account_position_data[4]
            msg.AccountPosition.FuturePosition.LongClosingYdVolume = account_position_data[5]
            msg.AccountPosition.FuturePosition.ShortTdVolume = account_position_data[6]
            msg.AccountPosition.FuturePosition.ShortYdVolume = account_position_data[7]
            msg.AccountPosition.FuturePosition.ShortOpenVolume = account_position_data[8]
            msg.AccountPosition.FuturePosition.ShortOpeningVolume = account_position_data[9]
            msg.AccountPosition.FuturePosition.ShortClosingTdVolume = account_position_data[10]
            msg.AccountPosition.FuturePosition.ShortClosingYdVolume = account_position_data[11]
            msg.AccountPosition.UpdateTime = struct.unpack("32s", data[168:200])[0].decode('utf-8').strip('\x00')
        elif msg.AccountPosition.BusinessType == pack_message.EBusinessType.ESTOCK:
            account_position_format = "i i i i i i i i i i i i i i"
            account_position_data = struct.unpack(account_position_format, data[112:168])
            msg.AccountPosition.StockPosition.LongYdPosition = account_position_data[0]
            msg.AccountPosition.StockPosition.LongPosition = account_position_data[1]
            msg.AccountPosition.StockPosition.LongTdBuy = account_position_data[2]
            msg.AccountPosition.StockPosition.LongTdSell = account_position_data[3]
            msg.AccountPosition.StockPosition.MarginYdPosition = account_position_data[4]
            msg.AccountPosition.StockPosition.MarginPosition = account_position_data[5]
            msg.AccountPosition.StockPosition.MarginTdBuy = account_position_data[6]
            msg.AccountPosition.StockPosition.MarginTdSell = account_position_data[7]
            msg.AccountPosition.StockPosition.ShortYdPosition = account_position_data[8]
            msg.AccountPosition.StockPosition.ShortPosition = account_position_data[9]
            msg.AccountPosition.StockPosition.ShortTdSell = account_position_data[10]
            msg.AccountPosition.StockPosition.ShortTdBuy = account_position_data[11]
            msg.AccountPosition.StockPosition.ShortDirectRepaid = account_position_data[12]
            msg.AccountPosition.StockPosition.SpecialPositionAvl = account_position_data[13]
            msg.AccountPosition.UpdateTime = struct.unpack("32s", data[168:200])[0].decode('utf-8').strip('\x00')

    return msg


def print_msg(msg):
    if msg.MessageType == pack_message.EMessageType.EFutureMarketData:
        logger.debug("Colo:{} Ticker:{} ExchangeID:{} TradingDay:{} ActionDay:{} UpdateTime:{} MillSec:{} LastPrice:{} "
                     "Volume:{} Turnover:{} OpenPrice:{} ClosePrice:{} PreClosePrice:{} SettlementPrice:{} PreSettlementPrice:{} "
                     "OpenInterest:{} PreOpenInterest:{} HighestPrice:{} LowestPrice:{} UpperLimitPrice:{} LowerLimitPrice:{} "
                     "BidPrice1:{} BidVolume1:{} AskPrice1:{} AskVolume1:{} RecvLocalTime:{} CurrentTime:{}", 
                    msg.FutureMarketData.Colo, msg.FutureMarketData.Ticker, msg.FutureMarketData.ExchangeID, msg.FutureMarketData.TradingDay, 
                    msg.FutureMarketData.ActionDay, msg.FutureMarketData.UpdateTime, msg.FutureMarketData.MillSec, msg.FutureMarketData.LastPrice,
                    msg.FutureMarketData.Volume, msg.FutureMarketData.Turnover, msg.FutureMarketData.OpenPrice, msg.FutureMarketData.ClosePrice,
                    msg.FutureMarketData.PreClosePrice, msg.FutureMarketData.SettlementPrice, msg.FutureMarketData.PreSettlementPrice,
                    msg.FutureMarketData.OpenInterest, msg.FutureMarketData.PreOpenInterest, msg.FutureMarketData.HighestPrice, 
                    msg.FutureMarketData.LowestPrice, msg.FutureMarketData.UpperLimitPrice, msg.FutureMarketData.LowerLimitPrice,
                    msg.FutureMarketData.BidPrice1, msg.FutureMarketData.BidVolume1, msg.FutureMarketData.AskPrice1, 
                    msg.FutureMarketData.AskVolume1, msg.FutureMarketData.RecvLocalTime, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"))
    elif msg.MessageType == pack_message.EMessageType.EOrderStatus:
        logger.debug("Colo:{} Broker:{} Product:{} Account:{} Ticker:{} ExchangeID:{} BusinessType:{} OrderRef:{} "
                     "OrderSysID:{} OrderLocalID:{} OrderToken:{} EngineID:{} UserReserved1:{} UserReserved2:{} "
                     "OrderType:{} OrderSide:{} OrderStatus:{} SendPrice:{} SendVolume:{} TotalTradedVolume:{} "
                     "TradedAvgPrice:{} TradedVolume:{} TradedPrice:{} CanceledVolume:{} Commission:{} RecvMarketTime:{} "
                     "SendTime:{} InsertTime:{} BrokerACKTime:{} ExchangeACKTime:{} RiskID:{} Trader:{} ErrorID:{} "
                     "ErrorMsg:{} UpdateTime:{}", 
                    msg.OrderStatus.Colo, msg.OrderStatus.Broker, msg.OrderStatus.Product, msg.OrderStatus.Account,
                    msg.OrderStatus.Ticker, msg.OrderStatus.ExchangeID, msg.OrderStatus.BusinessType, msg.OrderStatus.OrderRef,
                    msg.OrderStatus.OrderSysID, msg.OrderStatus.OrderLocalID, msg.OrderStatus.OrderToken, msg.OrderStatus.EngineID,
                    msg.OrderStatus.UserReserved1, msg.OrderStatus.UserReserved2, msg.OrderStatus.OrderType, msg.OrderStatus.OrderSide,
                    msg.OrderStatus.OrderStatus, msg.OrderStatus.SendPrice, msg.OrderStatus.SendVolume, msg.OrderStatus.TotalTradedVolume,
                    msg.OrderStatus.TradedAvgPrice, msg.OrderStatus.TradedVolume, msg.OrderStatus.TradedPrice, msg.OrderStatus.CanceledVolume,
                    msg.OrderStatus.Commission, msg.OrderStatus.RecvMarketTime, msg.OrderStatus.SendTime, msg.OrderStatus.InsertTime,
                    msg.OrderStatus.BrokerACKTime, msg.OrderStatus.ExchangeACKTime, msg.OrderStatus.RiskID, msg.OrderStatus.Trader,
                    msg.OrderStatus.ErrorID, msg.OrderStatus.ErrorMsg, msg.OrderStatus.UpdateTime)
    elif msg.MessageType == pack_message.EMessageType.EAccountFund:
        logger.debug("Colo:{} Broker:{} Product:{} Account:{} BusinessType:{} Deposit:{} Withdraw:{} CurrMargin:{} "
                     "Commission:{} CloseProfit:{} PositionProfit:{} Available:{} WithdrawQuota:{} ExchangeMargin:{} "
                     "Balance:{} PreBalance:{} UpdateTime:{}", 
                    msg.AccountFund.Colo, msg.AccountFund.Broker, msg.AccountFund.Product, msg.AccountFund.Account,
                    msg.AccountFund.BusinessType, msg.AccountFund.Deposit, msg.AccountFund.Withdraw, msg.AccountFund.CurrMargin,
                    msg.AccountFund.Commission, msg.AccountFund.CloseProfit, msg.AccountFund.PositionProfit, 
                    msg.AccountFund.Available, msg.AccountFund.WithdrawQuota, msg.AccountFund.ExchangeMargin,
                    msg.AccountFund.Balance, msg.AccountFund.PreBalance, msg.AccountFund.UpdateTime)
    elif msg.MessageType == pack_message.EMessageType.EAccountPosition:
        if msg.AccountPosition.BusinessType == pack_message.EBusinessType.EFUTURE:
            logger.debug("Colo:{} Broker:{} Product:{} Account:{} Ticker:{} ExchangeID:{} BusinessType:{} "
                        "LongTdVolume:{} LongYdVolume:{} LongOpenVolume:{} LongOpeningVolume:{} "
                        "LongClosingTdVolume:{} LongClosingYdVolume:{} ShortTdVolume:{} ShortYdVolume:{} "
                        "ShortOpenVolume:{} ShortOpeningVolume:{} ShortClosingTdVolume:{} "
                        "ShortClosingYdVolume:{} UpdateTime:{}", 
                        msg.AccountPosition.Colo, msg.AccountPosition.Broker, msg.AccountPosition.Product, 
                        msg.AccountPosition.Account, msg.AccountPosition.Ticker, msg.AccountPosition.ExchangeID,
                        msg.AccountPosition.BusinessType, msg.AccountPosition.FuturePosition.LongTdVolume,
                        msg.AccountPosition.FuturePosition.LongYdVolume, msg.AccountPosition.FuturePosition.LongOpenVolume,
                        msg.AccountPosition.FuturePosition.LongOpeningVolume, msg.AccountPosition.FuturePosition.LongClosingTdVolume,
                        msg.AccountPosition.FuturePosition.LongClosingYdVolume, msg.AccountPosition.FuturePosition.ShortTdVolume,
                        msg.AccountPosition.FuturePosition.ShortYdVolume, msg.AccountPosition.FuturePosition.ShortOpenVolume,
                        msg.AccountPosition.FuturePosition.ShortOpeningVolume, msg.AccountPosition.FuturePosition.ShortClosingTdVolume,
                        msg.AccountPosition.FuturePosition.ShortClosingYdVolume, msg.AccountPosition.UpdateTime)
        elif msg.AccountPosition.BusinessType == pack_message.EBusinessType.ESTOCK:
            logger.debug("Colo:{} Broker:{} Product:{} Account:{} Ticker:{} ExchangeID:{} BusinessType:{} "
                        "LongYdPosition:{} LongPosition:{} LongTdBuy:{} LongTdSell:{} "
                        "MarginYdPosition:{} MarginPosition:{} MarginTdBuy:{} MarginTdSell:{} "
                        "ShortYdPosition:{} ShortPosition:{} ShortTdBuy:{} ShortTdSell:{} "
                        "ShortDirectRepaid:{} SpecialPositionAvl:{} UpdateTime:{}", 
                        msg.AccountPosition.Colo, msg.AccountPosition.Broker, msg.AccountPosition.Product, 
                        msg.AccountPosition.Account, msg.AccountPosition.Ticker, msg.AccountPosition.ExchangeID,
                        msg.AccountPosition.BusinessType, msg.AccountPosition.StockPosition.LongYdPosition, 
                        msg.AccountPosition.StockPosition.LongPosition, msg.AccountPosition.StockPosition.LongTdBuy,
                        msg.AccountPosition.StockPosition.LongTdSell, msg.AccountPosition.StockPosition.MarginYdPosition,
                        msg.AccountPosition.StockPosition.MarginPosition, msg.AccountPosition.StockPosition.MarginTdBuy,
                        msg.AccountPosition.StockPosition.MarginTdSell, msg.AccountPosition.StockPosition.ShortYdPosition,
                        msg.AccountPosition.StockPosition.ShortPosition, msg.AccountPosition.StockPosition.ShortTdBuy,
                        msg.AccountPosition.StockPosition.ShortTdSell, msg.AccountPosition.StockPosition.ShortDirectRepaid,
                        msg.AccountPosition.StockPosition.SpecialPositionAvl, msg.AccountPosition.UpdateTime)



class HPPackClient(TcpPack.HP_TcpPackClient):
    EventDescription = TcpPack.HP_TcpPackServer.EventDescription

    @EventDescription
    def OnSend(self, Sender, ConnID, Data):
        logger.info('[%d, OnSend] data len=%d' % (ConnID, len(Data)))

    @EventDescription
    def OnConnect(self, Sender, ConnID):
        logger.info('[%d, OnConnect] Success.' % ConnID)

    @EventDescription
    def OnReceive(self, Sender, ConnID, Data):
        recv_queue.put(Data)
        msg_type, = struct.unpack('i', Data[0:4]) 
        logger.info('[%d, OnReceive] data len=%d msg_type:%#X' % (ConnID, len(Data), msg_type))

    def SendData(self, msg):
        self.Send(self.Client, msg)


def signal_handler(sig, frame):
    if sig == signal.SIGINT:
        logger.info("收到SIGINT信号,正在退出...")
    elif sig == signal.SIGTERM:
        logger.info("收到SIGTERM信号,正在退出...")
    
    sys.exit(0)


class XServerClient(object):
    def __init__(self, program_name):
        self.program_name = program_name
        self.hp_pack_client = None
        self.ck_client = None

        self.start_time = int(time.time())
        self.end_time = 0

        self.xserver_info = ""

    def connect_to_clickhouse(self, host:str, port:str, user:str, password:str):
        # self.ck_client = CKFutureClient(host=host, port=port, user=user, password=password)
        pass

    def connect_to_xserver(self, ip:str, port:int, user:str, password:str):
        # 启动客户端连接XServer
        self.hp_pack_client = HPPackClient()
        self.hp_pack_client.Start(host=ip, port=port, head_flag=0x169, size=0XFFFF)
        logger.info(f"Connect to XServer:{ip}:{port}")

        self.xserver_info = f"{ip}:{port}"
        # 发送登录请求
        msg = pack_message.PackMessage()
        msg.MessageType = pack_message.EMessageType.ELoginRequest
        msg.LoginRequest.ClientType = pack_message.EClientType.EXMONITOR
        msg.LoginRequest.Account = user
        msg.LoginRequest.PassWord = password
        self.hp_pack_client.SendData(msg.to_bytes())

    def run(self):
        # 注册中断信号
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # 主要处理逻辑
        while True:
            timestamp_sec:int = int(time.time())
            # 收取数据
            data = recv_queue.get()
            if data:
                msg = convert_to_message(data)
                if msg.MessageType == pack_message.EMessageType.EOrderStatus:
                    # 更新订单记录
                    print_msg(msg)
                    pass
                elif msg.MessageType == pack_message.EMessageType.EAccountFund:
                    # 更新账户资金数据
                    print_msg(msg)
                elif msg.MessageType == pack_message.EMessageType.EAccountPosition:
                    # 更新账户仓位信息
                    print_msg(msg)
                elif msg.MessageType == pack_message.EMessageType.ELoginResponse:
                    # 发送EventLog
                    new_msg = pack_message.PackMessage()
                    new_msg.MessageType = pack_message.EMessageType.EEventLog
                    new_msg.EventLog.Colo = "XServer"
                    new_msg.EventLog.Account = self.program_name
                    new_msg.EventLog.App = self.program_name
                    new_msg.EventLog.Event = f"Client Connected to XServer[{self.xserver_info}]"
                    new_msg.EventLog.Level = pack_message.EEventLogLevel.EINFO
                    new_msg.EventLog.UpdateTime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                    self.hp_pack_client.SendData(new_msg.to_bytes())

            # 比较时间
            # if timestamp_sec > self.end_time:
            #     logger.info(f"当前时间:{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}，已经收盘，退出程序")
            #     break
        sys.stdout.flush()


if __name__ == "__main__":
    output_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'output')
    program_name = "QuantClient"
    logger.remove()
    # 输出至标准输出
    logger.add(sys.stdout, level="DEBUG")
    # 输出至日志文件
    logger.add(f"{output_path}/{program_name}_{datetime.datetime.now().strftime('%Y%m%d')}.log", level="DEBUG", rotation="500 MB")

    ck_params = {
        'host': '192.168.1.168',
        'port': '9000',
        'user': 'xtrader',
        'password': 'xtrader@123.com',
    }

    xserver_params = {
        'ip': '192.168.1.168',
        'port': 8000,
        'user': 'ckclient',
        'password': '123456',
    }
    
    client = XServerClient(program_name=program_name)
    client.connect_to_clickhouse(**ck_params)
    client.connect_to_xserver(**xserver_params)
    client.run()