### XServer
- 中间件，主要功能如下：
  - 转发GUI客户端上行控制命令到不同Colo交易服务器，如转发XMonitor的报单撤单请求消息到XTrader、风控控制命令消息至XRiskJudge；
  - 转发交易相关数据到GUI客户端，如转发XMarketCenter行情数据、XTrader订单回报至XMonitor。
  - 管理XMonitor客户端登录用户的权限校验。
  - 盘后提供历史数据回放。

#### Python客户端
- Python环境安装：
    ```bash
    conda create -n XQuant python=3.9
    conda activate XQuant
    pip3 install HPSocket -i https://mirrors.aliyun.com/pypi/simple/
    pip3 install loguru -i https://mirrors.aliyun.com/pypi/simple/
    pip install pyyaml -i https://mirrors.aliyun.com/pypi/simple/
    pip install clickhouse_driver -i https://mirrors.aliyun.com/pypi/simple/
    ```
- 基于Python客户端可以将所有交易记录存储到ClickHouse，通过Web服务方式提供查询。  
