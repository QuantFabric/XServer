### XServer
- 中间件，主要功能如下：
  - 转发GUI客户端上行控制命令到不同Colo交易服务器，如转发XMonitor的报单撤单请求消息到XTrader、风控控制命令消息至XRiskJudge；
  - 转发交易相关数据到GUI客户端，如转发XMarketCenter行情数据、XTrader订单回报至XMonitor。
  - 管理XMonitor客户端登录用户的权限校验。
  - 盘后提供历史数据回放。