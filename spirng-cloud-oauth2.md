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

每个客户端都可以定制这些token属性，如果没有设置，则使用系统默认的属性值。



redis缓存管理：

clientDetails缓存，是否启动缓存，缓存过期时间(默认5秒)；redis的key，oauth2_client_${clientId}，

user缓存，是否启动缓存，缓存过期时间(默认5秒)；redis的key，oauth2_user_${username}，



客户端认证(client credentials)模式

请求例子：

```
 curl -H "Accept: application/json" http://192.168.5.31:7020/oauth/token -d "grant_type=client_credentials&client_id=test&client_secret=12345678"
```

返回结果：

```
{"access_token":"71d58c43-7807-41a8-b9c5-ae0e25fdf3e3","token_type":"bearer","expires_in":42871,"scope":"read write"}
```

不支持刷新

官方文档也写不支持刷新

查看代码java类：ClientCredentialsTokenGranter，看这个方法内的注释：// The spec says that client credentials should not be allowed to get a refresh token，实际调试代码验证也是这样。allowRefresh实例变量永远为false。

```
	@Override
	public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
		OAuth2AccessToken token = super.grant(grantType, tokenRequest);
		if (token != null) {
			DefaultOAuth2AccessToken norefresh = new DefaultOAuth2AccessToken(token);
			// The spec says that client credentials should not be allowed to get a refresh token
			if (!allowRefresh) {
				norefresh.setRefreshToken(null);
			}
			token = norefresh;
		}
		return token;
	}
```

测试

```
curl -i -H "Accept: application/json" -H "Authorization: Bearer b2ec7d2e-faf6-4909-911e-87a2c73a9f6f" -X GET http://192.168.5.31:7020/auth/test?testId=aaa -v
```

返回

```
{"testId":"aaa"}
```



## PasswordEncoder

spring boot security常用的PasswordEncoder执行比较：

测试用例：

```java
public class PasswordEncoderTest {
	
	protected void testPasswordEncoder(PasswordEncoder passwordEncoder,String textPassword) {
		long beginTime = System.currentTimeMillis();
		String encPassword = passwordEncoder.encode(textPassword);
		long spendTime = System.currentTimeMillis() - beginTime;
		System.out.println(encPassword);
		System.out.println(passwordEncoder.getClass()+" enc password spend time["+spendTime+"] mills.");
		beginTime = System.currentTimeMillis();
		passwordEncoder.matches(textPassword, encPassword);
		spendTime = System.currentTimeMillis() - beginTime;
		System.out.println(passwordEncoder.getClass()+" matches password spend time["+spendTime+"] mills.\r\n");
	}
	
	@Test
	public void generatePassword() {
		String textPassword = "Heige-123";
		this.testPasswordEncoder( new BCryptPasswordEncoder(), textPassword);
		this.testPasswordEncoder( new Pbkdf2PasswordEncoder(), textPassword);
		this.testPasswordEncoder( new SCryptPasswordEncoder(), textPassword);
		this.testPasswordEncoder( new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("SHA-256"), textPassword);
	}
	

}
```

执行结果：

```
$2a$10$VKupW6F6lDXDG2CWvGeNxuZkfj27m2M.1P3xAoSw9uhPLWzq1W3fi
class org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder enc password spend time[193] mills.
class org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder matches password spend time[86] mills.

8adc402c5bf7cad6fe483872cddf4e1253011cb95e7ab56e2137d21c6bb222e73d9e34cc2b786118
class org.springframework.security.crypto.password.Pbkdf2PasswordEncoder enc password spend time[703] mills.
class org.springframework.security.crypto.password.Pbkdf2PasswordEncoder matches password spend time[431] mills.

$e0801$7VhJ9Baw7UEe8/+cbVIp0BoDYDptgXxTrCL1vIkY1cIWwu2ckpAHaK+/Ln6mxgV3IxafqHUyXgKZu7qA+g6aBQ==$vyaomdji1+yUCoWXYoyPcKeCsPEdtnTO5+R5nMNdXGY=
class org.springframework.security.crypto.scrypt.SCryptPasswordEncoder enc password spend time[197] mills.
class org.springframework.security.crypto.scrypt.SCryptPasswordEncoder matches password spend time[71] mills.

{CTxIRcliy81FAZEvxAPFQnLj8CZxqqEJq6pme2C8kZ4=}b9e66ad611bb7177794994b552a17f4a53668022f52622a63cc647c1bbc3fed0
class org.springframework.security.crypto.password.MessageDigestPasswordEncoder enc password spend time[0] mills.
class org.springframework.security.crypto.password.MessageDigestPasswordEncoder matches password spend time[0] mills.
```

### BCrypt



## oauth2后台管理

对表数据进行管理，对Redis进行管理。

功能：

客户端管理：增加客户端、修改客户端、删除客户端、授权。

用户管理：增加用户、修改用户、删除用户、授权。只有密码模式和code模式有用。

权限管理：增加权限、修改权限、删除权限。

