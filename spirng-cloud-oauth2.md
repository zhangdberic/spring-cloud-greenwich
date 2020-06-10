# spring cloud oauth2

## 服务器端(server)



默认的token规则：

	private int refreshTokenValiditySeconds = 60 * 60 * 24 * 30; // default 30 days.
	private int accessTokenValiditySeconds = 60 * 60 * 12; // default 12 hours.
	private boolean supportRefreshToken = false;
	private boolean reuseRefreshToken = true;
刷新令牌(refresh_token)有效期默认为30天；

访问令牌(access_token)有效期默认为12小时；

默认不支持刷新令牌；

默认每次刷新令牌都重新改变access_token值；

每个客户端都可以定制这些token属性，如果没有获取到，则使用系统默认的属性值。

