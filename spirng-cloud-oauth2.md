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



redis缓存管理：

clientDetails缓存，是否启动缓存，缓存过期时间(默认5秒)；redis的key，oauth2_client_${clientId}，

user缓存，是否启动缓存，缓存过期时间(默认5秒)；redis的key，oauth2_user_${username}，



## oauth2后台管理

对表数据进行管理，对Redis进行管理。

功能：

客户端管理：增加客户端、修改客户端、删除客户端、授权。

用户管理：增加用户、修改用户、删除用户、授权。只有密码模式和code模式有用。

权限管理：增加权限、修改权限、删除权限。

