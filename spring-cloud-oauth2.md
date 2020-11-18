

# spring cloud oauth2

## 服务器端(server)

### pom.xml

```xml
		<!-- spring cloud config client -->
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-starter-config</artifactId>
		</dependency>
		<!-- spring cloud bus -->
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-starter-bus-amqp</artifactId>
		</dependency>
		<!-- spring cloud eureka client -->
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
		</dependency>
		<!-- spring cloud oauth2 -->
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-starter-oauth2</artifactId>
		</dependency>
		<!-- spring boot web -->
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>
		<!-- spring cloud redis -->
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-data-redis</artifactId>
		</dependency>
		<!-- spring cloud data jpa -->
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-data-jpa</artifactId>
		</dependency>
```

这里最重要的就是：spring-cloud-starter-oauth2，其它的附属依赖包，提供config、eureka、jpa等。

### yaml

#### bootstrap.yml

```yaml
spring:
  application:
    name: dy-oauth2
  profiles:
    active: dev
# 开发环境        
---
spring:
  profiles: dev
  cloud:
    config:
      uri: http://192.168.5.54:9000
      profile: ${spring.profiles}  # 指定从config server配置的git上拉取的文件(例如:dy-eureka-dev.yml)
      username: dy-config   # config server的basic认证的user
      password: 12345678 # config server的basic认证的password
    inetutils:
      # 指定获取ip地址的范围(可以是ip段)
      preferred-networks: 192.168
# 测试环境        
---
spring:
  profiles: test
  cloud:
    config:
      uri: http://192.168.5.54:9000
      profile: ${spring.profiles}  # 指定从config server配置的git上拉取的文件(例如:dy-eureka-dev.yml)
      username: dy-config   # config server的basic认证的user
      password: 12345678 # config server的basic认证的password
    inetutils:
      # 指定获取ip地址的范围(可以是ip段)
      preferred-networks: 192.168       
```

#### dy-oauth2.yml

```yaml
server:
  port: 7020
  # tomcat 字符集
  tomcat: 
    uri-encoding: UTF-8  
spring:
  cloud:
    config:
      # 允许使用java -Dxxx=yyy,来覆盖远程属性，例如:java -Dserver.port=8071
      overrideSystemProperties: false
  # tomcat 字符集设置      
  http: 
    encoding: 
      charset: UTF-8
      enabled: true
      force: true
      
# actuator       
management:
  endpoint:
    health:
      show-details: always           
  endpoints:
    web:
      exposure:
        include:
        - "*"
```



#### dy-oauth2-dev.yml

例如：gitlab上的dy-oauth2-dev.yml

```yaml
# 开发环境配置 
spring:
  # devtools
  devtools: 
    restart: 
      enabled: false
  # 和spring-cloud-starter-bus-amqp配合,用于属性刷新
  rabbitmq:
    host: 192.168.5.76
    port: 5672
    username: zhangdb
    password: 12345678
  # oauth2 token redis
  redis:
    host: 192.168.5.76 
    port: 6379
    timeout: 1000
    password: 12345678
    pool:
      minIdle: 1
      maxIdle: 8
      maxWait: 3
      maxActive: 8
  # oauth2 client and user jdbc
  # jpa
  jpa:
    database-platform: z1.util.jpa.hibernate.OracleDialect
  # oracle dbcp2
  datasource:
    driver-class-name: oracle.jdbc.driver.OracleDriver
    url: jdbc:oracle:thin:@//192.168.5.36:1521/dyitdb
    username: oauth2
    password: 12345678
    dbcp2:
      initial-size: 1
      min-idle: 1
      max-idle: 8
      test-on-borrow: true
      validation-query: select 1 from dual
      validation-query-timeout: 1000
# eureka 客户端
eureka:
  instance: 
    # 使用ip地址注册到eureka服务器(多ip的情况下和bootstrap.xml的spring.inetutils.preferred-networks属性配合使用),默认值false使用主机名注册(/etc/hosts的第一行)
    prefer-ip-address: true
    # 注册到eureka服务器的实例id,格式为:本机ip地址:服务名:端口(多ip情况下和bootstrap.xml的spring.inetutils.preferred-networks属性配合使用)
    instance-id: ${spring.cloud.client.ip-address}:${spring.application.name}:${server.port}
  client:
    service-url:
      # eureka注册中心位置
      defaultZone: http://dy-eureka:12345678@192.168.5.76:8761/eureka/
```

### java代码

#### OauthServerApplication

注意加入了@EnableAuthorizationServer源注释，开启了oauth2服务器。

```java
@SpringBootApplication
@EnableAuthorizationServer
public class OauthServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(OauthServerApplication.class, args);
	}

}
```

#### AuthorizationServerConfiguration(认证服务器配置类)

认证服务器配置类，其提供了客户端信息获取、token存取、用户信息获取、authorization_code存取等配置，在整个spring cloud oauth2中扮演者很重要的角色。我们通过这个配置作为整个代码讲解的入口，并展开来说明各个功能和配置。

##### clientDetailsService(客户端信息获取)

```java
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		// 四种模式都会用到的client信息服务
		clients.withClientDetails(this.clientDetailsService);
	}
```

**CacheJdbcClientDetailsService**

实现了ClientDetailsService接口，其提供了Jdbc存储ClientDetails和缓存功能。提供了两层cache，第1层ThreadLocal，第2层Redis，优先查找ThreadLocal如果没有再查找Redis，如果还没有再从数据库中读取(表结构见OAUTH_CLIENT_DETAILS)。当前代码，有个缺点是在一段时间内可能有脏数据存在（缓存在Redis中clientDetails数据,数据库中人为已经修改了)。因为目前没有设计oauth2后台系统，因此折中考虑后只能使用这个办法，即使有脏数据业务上也是能容忍的。

```java
@Configuration
public class CacheJdbcClientDetailsService extends JdbcClientDetailsService {

	protected static final ThreadLocal<ClientDetails> threadLocalClientDetails = new ThreadLocal<ClientDetails>();

	public CacheJdbcClientDetailsService(@Autowired DataSource dataSource) {
		super(dataSource);
	}

	@Bean
	public RedisTemplate<String, ClientDetails> cacheClientDetailRedisTemplate(
			RedisConnectionFactory redisConnectionFactory) {
		RedisTemplate<String, ClientDetails> redisTemplate = new RedisTemplate<>();
		redisTemplate.setConnectionFactory(redisConnectionFactory);
		return redisTemplate;
	}

	@Autowired
	private RedisTemplate<String, ClientDetails> cacheClientDetailRedisTemplate;

	/** oauth2属性 */
	@Autowired
	private Oauth2Properties oauth2Properties;

	@Override
	public ClientDetails loadClientByClientId(String clientId) throws InvalidClientException {
		ClientDetails clientDetails = threadLocalClientDetails.get();
		if (clientDetails != null) {
			return clientDetails;
		}

		long cacheExpireTime = this.oauth2Properties.getClientDetail().getCacheExpireTime();
		if (cacheExpireTime > 0) {
			clientDetails = this.cacheClientDetailRedisTemplate.opsForValue().get(clientId);
			if (clientDetails == null) {
				clientDetails = super.loadClientByClientId(clientId);
				this.cacheClientDetailRedisTemplate.opsForValue().set(clientIdKey(clientId), clientDetails,
						cacheExpireTime, TimeUnit.SECONDS);
			}
		} else {
			clientDetails = super.loadClientByClientId(clientId);
		}
		
		threadLocalClientDetails.set(clientDetails);
		return clientDetails;
	}

	protected String clientIdKey(String clientId) {
		return "auth2_client_" + clientId;
	}

}
```

**Oauth2ThreadLocalFilter**

设置本过滤器的目的就是为在事后(请求结束后)，释放ThreadLocal。其被注册到系统过滤器WebAsyncManagerIntegrationFilter之前(第1个被执行的过滤器)，也就在任何过滤器执行后其会执行。

```java
public class Oauth2ThreadLocalFilter extends GenericFilterBean {

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		try {
			chain.doFilter(request, response);
		}finally {
			CacheJdbcClientDetailsService.threadLocalClientDetails.remove();
		}
		
	}

}
```

注册Oauth2ThreadLocalFilter代码，这里只需要关注http.addFilterBefore(new Oauth2ThreadLocalFilter(), WebAsyncManagerIntegrationFilter.class);代码

```java
@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

	/**
	 * 自定义安全配置
	 * 注意：一定要以http.antMatcher(...)方法开头匹配，否则会覆盖SecurityConfiguration类的相关配置.
	 * 这里定义的配置有两个作用：
	 * 1.安全限制，定义外界请求访问系统的安全策略。
	 * 2.根据规则生成过滤链(FilterChainProxy,过滤器的排列组合)，不同的规则生成的过滤链不同的。
	 * 系统默认的/oauth/xxx相关请求也是基于ResourceServerConfiguration实现的,只不过系统默认已经配置完了。
	 */
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.addFilterBefore(new Oauth2ThreadLocalFilter(), WebAsyncManagerIntegrationFilter.class);
		http.authorizeRequests().anyRequest().authenticated().and().csrf().disable();
	}

}

```

##### DefaultTokenServices(token)操作

```java
	@Bean
	@Primary
	public AuthorizationServerTokenServices tokenService() {
		DefaultTokenServices tokenServices = new DefaultTokenServices();
		tokenServices.setClientDetailsService(this.clientDetailsService);
		tokenServices.setTokenStore(tokenStore());
		//tokenServices.setAccessTokenValiditySeconds(accessTokenValiditySeconds); // 设置accessToken过期时间(默认12小时)
        //tokenServices.setSupportRefreshToken(false); // 设置是否支持令牌刷新(默认为false不支持刷新)
        //tokenServices.setRefreshTokenValiditySeconds(refreshTokenValiditySeconds); // 设置refreshToken过期时间(默认30天)
        //tokenServices.setReuseRefreshToken(true); // 设置刷新令牌操作后是否复用还有重建一个refreshToken,默认(true复用),前提是支持令牌刷新
		return tokenServices;
	}
```

###### 创建AccessToken

创建AccessToken的代码可以查看，DefaultTokenServices#createAccessToken(OAuth2Authentication authentication, OAuth2RefreshToken refreshToken)，会创建一个DefaultOAuth2AccessToken对象(OAuth2AccessToken接口实现)，其内属性赋值算法如下：

value(accessToken值)：UUID.randomUUID().toString()

expiration(过期时间)：

1. ClientDetails#getAccessTokenValiditySeconds()来获取过期时间；
2. DefaultTokenServices的accessTokenValiditySeconds属性，默认为12个小时；

refreshToken(刷新token)：DefaultTokenServices默认是不支持刷新的(supportRefreshToken=false)，如果要支持刷新，参见下面的token刷新章节;

tokenType(token类型)：支持两种Bearer和OAuth2，默认是Bearer;

scope(访问范围)：理解为也是从ClientDetails的scope属性获取的；

additionalInformation(附件信息)：默认是Empty(Map)；

如果你对默认创建的DefaultOAuth2AccessToken还不满意，可以实现DefaultTokenServices#accessTokenEnhancer接口来增强DefaultOAuth2AccessToken。

###### 根据AccessToken获取OAuth2Authentication

根据AccessToken获取OAuth2Authentication的代码可以查看，DefaultTokenServices# loadAuthentication(String accessTokenValue)，其会根据请求的accessTokenValue来获取OAuth2Authentication对象。请求处理流程(任何一处代码获取不到对象都会抛出InvalidTokenException异常)：

1. 通过tokenStore#readAccessToken(accessTokenValue)方法来获取OAuth2AccessToken；

2. 验证是否过期；

3. 再通过tokenStore#readAuthentication(accessToken)方法来获取OAuth2Authentication；

4. 通过clientDetailsService#loadClientByClientId(clientId)方法验证clientId是否有效；

   

##### RedisTokenStore(token存储)

```java
	@Bean
	public TokenStore tokenStore() {
		return new RedisTokenStore(this.redisConnectionFactory);
	}
```

使用spring cloud oauth2原生提供的RedisTokenStore，无须再自己实现，其提供了token存储服务，不只存储了访问令牌(access_token)，而且其还会根据数据库读取client和user的认证数据，然后把认证的数据也缓存，缓存过期时间就是access_token的过期时间(expires_in)，也就是说在这个时间内，即使你修改了数据库的client和user相关信息，例如：清空了authorites字段，但原来的hasAuthority和hasRole判断任会返回true，因为客户端信息(client_details)还在缓存中还没有过期。解决的办法：TokenStore提供了两个方法，用于根据clientId和userName来获取OAuth2AccessToken相关集合，你可以通过获取到的OAuth2AccessToken来调用TokenStore#removeAccessToken来删除缓存中的AccessToken数据，强制客户端重新认证，见cn.dongyuit.cloud.oauth2.authorization.ClearTokenStoreAccessToken类实现。

###### Redis缓存信息

**序列化**

既然要缓存，就需要序列化缓存的值，这里序列化使用了JdkSerializationStrategy(jdk序列化策略)

**缓存内容**

1. key=access:+accessToken，例如：access:01234567-01234567-01234567-01234567，value=OAuth2AccessToken(对象)

2. key=auth:+accessToken，例如：auth:01234567-01234567-01234567-01234567，value=OAuth2Authentication(对象)

3. key=auth_to_access:+MD5(username(可选)+clientid+scope(可选))，例如：auth_to_access:123123123，value=OAuth2AccessToken(对象)

4. key=client_id_to_access:clientId，例如：client_id_to_access:1234，value=OAuth2AccessToken(对象)

5. key=clientId:userName，用于代码(code)模式有关，value=OAuth2AccessToken(对象)

   如果支持刷新令牌，则还有：

6. key=refresh_to_access:+refreshToken，例如：refresh_to_access:88888888-11111111-22222222-33333333，value=accssTokenValue(字符串)

7. key=access_to_refresh:+accssTokenValue，例如：access_to_refresh:01234567-01234567-01234567-01234567，value=refreshTokenValue(字符串)

**过期时间**

以上所有Redis缓存内容的过期时间都是通过token.getExpiresIn();，而这个过期时间最终来至于"上面章节**创建AccessToken**的 expiration(过期时间)"。

###### AccessToken存储

入口方法，DefaultTokenServices#createAccessToken(OAuth2Authentication authentication)

1. 首先根据authentication从Redis中获取OAuth2AccessToken(RedisTokenStore#getAccessToken(OAuth2Authentication authentication))，参见"缓存内容"的key=auth_to_access:auth_to_access:+MD5(username(可选)+clientid+scope(可选))，也就是根据请求认证信息来获取OAuth2AccessToken对象；
2. 如果无法获取到OAuth2AccessToken，则使用创建OAuth2AccessToken；
3. 调用RedisTokenStore#storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication)来存储token和认证信息；具体存储(缓存)内容见"上面章节的缓存内容"。

###### 根据accessToken获取缓存内容

入口方法，DefaultTokenServices#loadAuthentication(String accessTokenValue)

1.通过tokenValue(字符串)获取OAuth2AccessToken

```java
	public OAuth2AccessToken readAccessToken(String tokenValue) {
		byte[] key = serializeKey(ACCESS + tokenValue);  // 参照上面文章[缓存内容]，redis key=access:+accessToken
		byte[] bytes = null;
		RedisConnection conn = getConnection();
		try {
			bytes = conn.get(key);
		} finally {
			conn.close();
		}
		OAuth2AccessToken accessToken = deserializeAccessToken(bytes);
		return accessToken;
	}
```

2.通过tokenValue(字符串)获取OAuth2Authentication

```java
	@Override
	public OAuth2Authentication readAuthentication(String token) {
		byte[] bytes = null;
		RedisConnection conn = getConnection();
		try {
			bytes = conn.get(serializeKey(AUTH + token)); // // 参照上面文章[缓存内容]，redis key=auth:+accessToken
		} finally {
			conn.close();
		}
		OAuth2Authentication auth = deserializeAuthentication(bytes);
		return auth;
	}
```

##### PasswordEncoder(密码编码器)

spring boot security新版本只保留了BCrypt、Pbkdf2、SCrypt三个加密实现，其它都已经被禁用了包括SHA256。

PasswordEncoder的接口实现，应该使用PasswordEncoderFactories.createDelegatingPasswordEncoder()静态方法创建PasswordEncoder实例，其提供了基于委托加密字符串。

```java
	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
```

默认情况下使用BCrypt加密，其会在生成的加密字符串前加入{bcrypt},例如：

```
{bcrypt}$2a$10$wDeaJTAs3KA/BilZmz.k8u7zqjl7spY.fV8juqWNmydDn3KzXWdLm
```

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

从执行结果上，看BCrypt算法是一个折中的方案，在安全上和性能上都是能够接受的，一个8位明文密码使用BCrypt加密hash处理需要190ms，验证密码则需要86ms。

**BCrypt**

BCrypt上网查一下资料很多，但总结一点就是，BCrypt就是为了慢，因为慢所以也安全，举个例子SHA256计算hash值1ms内搞定，而BCrypt则需要190ms多，是SHA256的200倍左右。慢是故意的就是为了让你破解也慢。因此在设计程序的时候，要考虑使用BCrypt加密和验证是否符合你的响应时间要求，你可能说可以缓存呀，但问题来了，如果缓存了还安全吗？这个需要设计程序来衡量利弊。

#### 获取AccessToken

参见：OAuth2AuthenticationProcessingFilter#doFilter(ServletRequest req, ServletResponse res, FilterChain chain)

参见：BearerTokenExtractor类

#### 获取OAuth2Authentication

客户端发送HTTP请求的时候，oauth2能从请求中获取OAuth2Authentication(认证信息)，下面的文档讲解如何从请求中获取OAuth2Authentication对象。

##### 请求参数为client_id和client_secret

根据client_id和client_secret来创建AccessToken服务，参见AbstractTokenGranter#getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest)方法，其会根据请求的ClientDetails和TokenRequest来创建OAuth2Authentication对象；ClientDetails这个是通过请求参数client_id从数据库中获取的，TokenRequest是对请求参数client_id、scope、grantType等属性的封装；

client(客户端模式)下，OAuth2Authentication对象为client信息；

```
 curl -H "Accept: application/json" http://192.168.5.31:7020/oauth/token -d "grant_type=client_credentials&client_id=test&client_secret=12345678"
```

password(密码模式)和code(代码)下，OAuth2Authentication对象为User信息；

```

```

##### 请求参数为AccessToken

token模式为Bearer，则oauth2会从请求头中获取Authorization的Bearer的值(accessToken)，然后从Redis中获取OAuth2Authentication，代码参见“上面章节AccessToken存储"；

请求HTTP代码：

```
curl -i -H "Accept: application/json" -H "Authorization: Bearer da0d8c14-11e3-4a33-9136-705f2eea283e" -X GET http://192.168.1.253:7020/auth/user -v
```

**通过SecurityContextHolder**

通过spring security持有者上下文来获取

```java
OAuth2Authentication OAuth2Authentication = (OAuth2Authentication)SecurityContextHolder.getContext().getAuthentication();
```

##### BearerTokenExtractor

TokenExtractor tokenExtractor = new BearerTokenExtractor();

**Authentication** authentication = **this**.tokenExtractor.extract(request);

##### OAuth2Authentication参数

根据OAuth2Authentication获取当前client_details信息

```java
	@RequestMapping(value = { "/auth/client" }, produces = "application/json")
	public ClientDetails currentClient(OAuth2Authentication user) {
		String clientId = user.getName();
		ClientDetails clientDetails = this.clientDetailsService.loadClientByClientId(clientId) ;
		return clientDetails;
	}
```

根据OAuth2Authentication获取当前user Authentication信息，只能用于密码(password)模式和代码(code)模式。

```java
	@RequestMapping(value = { "/auth/user" }, produces = "application/json")
	public Map<String, Object> currentUser(OAuth2Authentication user) {
		Map<String, Object> userinfo = new HashMap<>();
		if(user!=null) {
			Authentication authentication = user.getUserAuthentication();
			if(authentication!=null) {
				userinfo.put("user", authentication.getPrincipal());
				userinfo.put("authorities", AuthorityUtils.authorityListToSet(authentication.getAuthorities()));
			}
		}
		return userinfo;
	}
```



#### 访问安全策略配置

这篇文档 https://www.jianshu.com/p/fe1194ca8ecd 讲解的很好，其很好分析了ResourceServerConfigurerAdapter和WebSecurityConfigurerAdapter的区别。

##### FilterChainProxy(理论)

查看源代码org.springframework.security.web.FilterChainProxy，其继承了spring的GenericFilterBean，这个代码相对简单，看10分钟就会能明白。

```java
public class FilterChainProxy extends GenericFilterBean {
    ...
	
	private List<SecurityFilterChain> filterChains;

    ...

	public FilterChainProxy() {
	}

    // 那个SecurityFilterChain匹配上了，则使用这个SecurityFilterChain内的过滤链。
	private List<Filter> getFilters(HttpServletRequest request) {
		for (SecurityFilterChain chain : filterChains) {
			if (chain.matches(request)) {
				return chain.getFilters();
			}
		}

		return null;
	}    
}
```

从图中可以看出spring security自己有一个叫`FilterChainProxy`代理`类，该类也实现了servlet接口。`FilterChainProxy内部有一个List<SecurityFilterChain> filterChains,而SecurityFilterChain是一个接口也是一个chain，每个chain里有若干个filter。既然有多个filter chain，那么来了一个http请求，这个请求（通过该请求的url来判断）应该由哪个或者哪些filter chain来进行处理呢？在spring security里一个请求只会被一个filter chain进行处理，也就是spring security通过遍历filterChains这个集合时，只要找到能处理该请求的filter chain就不再进行其他的filter chain匹配。如下图：

![](images/SecurityFilterChain.webp)

SecurityFilterChain代码如下：

一个SecurityFilterChain里由多个Filter组成，请求如果被matches方法匹配，那么就会逐个执行getFilters()内的过滤器。

```java
import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

public interface SecurityFilterChain {

	boolean matches(HttpServletRequest request);

	List<Filter> getFilters();
}
```

举例：

```
举例，如果上图，并且客户端发送请求，URL为/bar/abc

FilterChainProxy处理流程如下：
FilterChainProxy本身由三个SecurityFilterChain组成，第1个为/foo/**匹配SecurityFilterChain，第2个为/bar/**匹配SecurityFilterChain，第3个为/**匹配SecurityFilterChain。

当请求/bar/abc达到FilterChainProxy，第1个/foo/**的SecurityFilterChain无法匹配不会执行，第2个/bar/**的SecurityFilterChain匹配成功，其会逐个执行这个SecurityFilterChain内的Filter(见下面章节)执行结束后则退出，不再执行第3个/**匹配SecurityFilterChain了。

如果请求URL为/foo/123，则第1个/foo/**匹配SecurityFilterChain成功，逐个执行这个SecurityFilterChain内的Filter(见下面章节)执行结束后则退出。
如果请求URL为/heige/nb，则第3个/**匹配SecurityFilterChain成功，逐个执行这个SecurityFilterChain内的Filter(见下面章节)执行结束后则退出。
```

##### oauth2的FilterChainProxy

上面的介绍是理论上的说明，实际情况是基于spring cloud oauth2的FilterChainProxy一般情况下有三个SecurityFilterChain，你可以Debug观察一下，特别是观察SecurityFilterChain内的Filter列表的最后一个Filter(FilterSecurityInterceptor)，其内有一个securityMetadataSource属性，内有requestMap属性，你可以直观的看到URL匹配规则和安全定义了。

**第1个SecurityFilterChain**：oauth2提供的原生服务，例如：/oauth/token、/oauth/tokeh_key和/oauth/check_token ，Debug调试SecurityFilterChain显示如下：

```
[ OrRequestMatcher [requestMatchers=[Ant [pattern='/oauth/token'], Ant [pattern='/oauth/token_key'], Ant [pattern='/oauth/check_token']]]
```

Debug调试SecurityFilterChain内的Filter列表的最后一个Filter(FilterSecurityInterceptor)显示如下：

```
{Ant [pattern='/oauth/token']=[fullyAuthenticated], Ant [pattern='/oauth/token_key']=[denyAll()], Ant [pattern='/oauth/check_token']=[isAuthenticated()]}
```

你可以通过覆盖AuthorizationServerConfigurerAdapter的代码，来重新定义访问安全规则：

```java
@Configuration
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		// 允许表单认证
		security.allowFormAuthenticationForClients();
		// 设置请求URL：/oauth/tokey_key和/oauth/check_token的安全规则
		security.tokenKeyAccess("denyAll()").checkTokenAccess("isAuthenticated()");
	}    
}
```

**第2个SecurityFilterChain**：你在ResourceServerConfiguration中定义的规则，Debug调试SecurityFilterChain显示如下：

为什么ResourceServerConfiguration的HttpSecurity规则生成的SecurityFilterChain优于WebSecurityConfiguration生成的SecurityFilterChain，因为其spring bean order为3，而WebSecurityConfiguration的spring bean order为100，因此ResourceServerConfiguration的configure(HttpSecurity http)方法先执行。

```java
[ Ant [pattern='/auth/**']
```

Debug调试SecurityFilterChain内的Filter列表的最后一个Filter(FilterSecurityInterceptor)显示如下：

```
{Ant [pattern='/auth/user']=[#oauth2.throwOnError(authenticated)], Ant [pattern='/auth/**']=[#oauth2.throwOnError(denyAll)]}
```

ResourceServerConfiguration的HttpSecurity规则代码如下：

```java
@Configuration
@EnableResourceServer
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
   	@Override
	public void configure(HttpSecurity http) throws Exception {
   		http.antMatcher("/auth/**").authorizeRequests().
		antMatchers("/auth/user").authenticated().
        antMatchers("/auth/**").denyAll();
    }
}
```

**第3个SecurityFilterChain**：你在WebSecurityConfiguration中定义的规则，Debug调试SecurityFilterChain显示如下：

为什么any request(任一情况)，这和HttpSecurity规则代码httpSecurity.authorizeRequests()开头有关，其定义了any request规则。

```
[ any request
```

Debug调试SecurityFilterChain内的Filter列表的最后一个Filter(FilterSecurityInterceptor)显示如下：

```
{Ant [pattern='/foo/**']=[authenticated], Ant [pattern='/bar/**']=[authenticated], Ant [pattern='/xxx/**']=[hasAnyRole('ROLE_authuser')], Ant [pattern='/**']=[permitAll]}
```

ResourceServerConfiguration的HttpSecurity规则代码如下：

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {
   	@Override
	public void configure(HttpSecurity httpSecurity) throws Exception {
httpSecurity.authorizeRequests().antMatchers("/foo/**","/bar/**").authenticated().and().httpBasic().and().csrf().disable();
httpSecurity.authorizeRequests().antMatchers("/xxx/**").hasAnyRole("authuser").antMatchers("/**").permitAll();        
    }
}
```

##### 为SecurityFilterChain增加过滤器

通过调用HttpSecurity的addFilterBefore方法在WebAsyncManagerIntegrationFilter前加入了Oauth2ThreadLocalFilter过滤器(最先执行)，你可以通过调试FilterChainProxy内的第2个SecurityFilterChain来查看过滤器顺序。

```java
@Configuration
@EnableResourceServer
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.addFilterBefore(new Oauth2ThreadLocalFilter(), WebAsyncManagerIntegrationFilter.class);    
   		http.antMatcher("/auth/**").authorizeRequests().
		antMatchers("/auth/user").authenticated().
        antMatchers("/auth/**").denyAll();
    }
}
```



##### ResourceServerConfiguration(资源服务器安全配置)

一般理解为用于服务(Service)的安全规则配置。其提供了oauth2对外提供服务的访问控制，例如，提供对：oauth2原生提供的服务/oauth/token、/oauth/token_key、/oauth/check_token，自定义的服务/auth/user的访问控制。

因为ResourceServerConfiguration其定义的spring bean order为3，高于WebSecurityConfiguration定义的spring bean order 100，ResourceServerConfiguration的configure(HttpSecurity http)方法会先执行，其生成的SecurityFilterChina的也会先进行URL匹配(见上面的FilterChinaProxy介绍)，如果匹配到就不会再执行WebSecurityConfiguration的configure(HttpSecurity http)方法生成的SecurityFilterChina了。因此注意：ResourceServerConfiguration和WebSecurityConfiguration定义的URL pattern访问安全规则最好不要有交集；

注意：ResourceServerConfiguration和WebSecurityConfiguration区别，还和授权模式有关，client_credentials模式的请求验证使用ResourceServerConfiguration设置的规则，authorization_code模式的请求验证使用WebSecurityConfiguration设置的规则。例如：某个client_details，同时支持client_credentials和authorization_code两种授权模式，如果你使用client_credentials模式请求，授权读取的是client_details的authorities，在ResourceServerConfiguration处理鉴权。如果你使用authorization_code模式请求，授权读取的是user的authorities，在WebSecurityConfiguration处理鉴权。



```java
/**
 * 资源服务安全配置类
 * 用于服务(service)的安全规则配置，区别于SecurityConfiguration用于web(http)的安全规则配置。
 * @author Administrator
 *
 */
@Configuration
@EnableResourceServer
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

	/**
	 * 自定义安全配置
	 * 注意：一定要以http.antMatcher(...)方法开头匹配，否则会覆盖SecurityConfiguration类的相关配置.
	 * 这里定义的配置有两个作用：
	 * 1.安全限制，定义外界请求访问系统的安全策略。
	 * 2.根据规则生成过滤链(FilterChainProxy,过滤器的排列组合)，不同的规则生成的过滤链不同的。
	 * 系统默认的/oauth/xxx相关请求也是要基于ResourceServerConfiguration实现的,只不过系统默认已经配置完了。
	 */
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.addFilterBefore(new Oauth2ThreadLocalFilter(), WebAsyncManagerIntegrationFilter.class);
        // 访问
		http.antMatcher("/auth/**").authorizeRequests().
		antMatchers("/auth/user").authenticated().
		antMatchers("/auth/client").authenticated().
        antMatchers("/auth/**").denyAll();
        // 多URL匹配规则,例子
//		http.requestMatchers().antMatchers("/auth/**","/9999/**").and()
//		.authorizeRequests().antMatchers("/auth/user", "/9999/1").authenticated().
//		antMatchers("/auth/**").denyAll().antMatchers("/9999/*").permitAll();        
	}

}
```

##### WebSecurityConfiguration(web服务器安全配置)

用于web(http)的安全配置，区别于ResourceServerConfiguration用于服务(service)的安全配置。提供对：/actuator/xxx的访问、code代码模式下/oauth/authorize(授权URL)、/login(登录页)、/oauth/confirm_access(用户授权确认)的访问控制等。WebSecurityConfiguration生成的规则优先级最低其会被最后匹配。

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		AuthenticationManager manager = super.authenticationManagerBean();
		return manager;
	}

	/**
	 * 自定义安全配置
	 * 注意：不应以http.antMatcher(...)方法开头匹配，否则会和ResourceServerConfiguration安全规则配置冲突，应以authorizeRequests()开头.
	 * 这里定义的配置有两个作用：
	 * 1.安全限制，定义外界请求访问系统的安全策略。
	 * 2.根据规则生成过滤链(FilterChainProxy,过滤器的排列组合)，不同的规则生成的过滤链不同的。
	 */
	@Override
	public void configure(HttpSecurity httpSecurity) throws Exception {
		
		// 授权码模式(authorization_code)配置
		// 授权码模式下,会用到/oauth/authorize(授权URL)、/login(登录页)、/oauth/confirm_access(用户授权确认),
		httpSecurity.authorizeRequests().antMatchers("/login").permitAll().and().formLogin().permitAll()
		.and().authorizeRequests().antMatchers("/oauth/authorize","/oauth/confirm_access").authenticated();

		
		// actuator
		httpSecurity.authorizeRequests()
		.antMatchers("/actuator/**").hasRole("actuator")
		.and().httpBasic()
		.and().csrf().disable();
		
		// 禁止所有
		httpSecurity.authorizeRequests().anyRequest().denyAll();
		
	}

}
```

##### 认证用户来源

基于oauth2的security认证不来之于spring的配置文件，而是来至于数据库的OAUTH_USER表，因为你在定义AuthorizationServerConfiguration类的时候，配置了AuthorizationServerEndpointsConfigurer使用的用户数据来源。

```java
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.tokenStore(this.tokenStore());
		// 用于password模式用户身份认证
		endpoints.authenticationManager(this.authenticationManager);
		// 用于password模式用户身份查询
		endpoints.userDetailsService(this.userServiceDetail);   // 这个位置
		// access_token和refresh_token存取服务
		endpoints.tokenServices(this.tokenService());
		// 用于authorization code模式code认证
		endpoints.authorizationCodeServices(this.redisAuthorizationCodeServices);
	}
```

#### /actuator访问

参见"认证用户来源"，访问/actuator需要认证，其用户名和密码不来至于配置项spring.security.user.name和password，而是来至于OAUTH_USER表了，因此最好在OAUTH_USER表上创建一个dy-oauth的用户，用于actuator访问，例如：用户名actuator，密码12345678，角色为actuator。

eureka配置的spring boot admin的客户端用户名和密码修改为：

```yaml
eureka:
    metadata-map:
      # 当前应用配置的spring security用户名和密码
      user.name: dy-oauth
      user.password: 12345678
```

#### HttpSecurity方法说明

httpSecurity.authorizeRequests()开头会生成 any request 的SecurityFilterChain。

httpSecurity.requestMatchers().antMatchers(...)开头会生成OrRequestMatcher的SecurityFilterChain。

httpSecurity.antMatcher()开头会生成Ant的SecurityFilterChain。

越靠前定义的规则会被优先匹配，匹配到执行后，则退出，不会再进行匹配。因此在设计httpSecurity的时候要注意顺序。

access(attribute)，基于认证代码表达式的方式来定义规则，特别适合于从外部获取访问规则，例如：

```java
config.antMatchers("/person/*").access("hasRole('ADMIN') or hasRole('USER')") .antMatchers("/person/{id}").access("@rbacService.checkUserId(authentication,#id)") .anyRequest() .access("@rbacService.hasPermission(request,authentication)");
```



#### @PreAuthorize

上面的ResourceServerConfiguration使用HttpSecurity代码来设置访问规则。这里将使用基于@PreAuthroize来声明访问规则。

调整ResourceServerConfiguration代码，类头加入@EnableGlobalMethodSecurity(prePostEnabled = true)声明，并调整HttpSecurity代码设置。

```java
@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

	/**
	 * 自定义安全配置
	 * 注意：一定要以http.antMatcher(...)或者http.requestMatchers().antMatchers(...)方法开头匹配，否则会覆盖SecurityConfiguration类的相关配置.
	 * 这里定义的配置有两个作用：
	 * 1.安全限制，定义外界请求访问系统的安全策略。
	 * 2.根据规则生成过滤链(FilterChainProxy,过滤器的排列组合)，不同的规则生成的过滤链不同的。
	 */
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.addFilterBefore(new Oauth2ThreadLocalFilter(), WebAsyncManagerIntegrationFilter.class);
        
//		http.antMatcher("/auth/**").authorizeRequests().
//		antMatchers("/auth/user").authenticated().
//		antMatchers("/auth/client").hasAuthority("authuser").
//      antMatchers("/auth/**").denyAll();
		
		http.antMatcher("/auth/**").authorizeRequests().anyRequest().authenticated();
    }
}
```

注释掉的是原来基于代码类设置的规则，本处修改为http.antMatcher("/auth/**").authorizeRequests().anyRequest().authenticated()，也就是说请求URL以 /auth 开头的都需要认证(需要携带accessToken)。这个规则设置，为下面基于/auth/xxx 开头的@RestController方法@PreAuthorize规则匹配声明了URL匹配入口。

```java
	@RequestMapping(value = { "/auth/client" }, produces = "application/json")
	@PreAuthorize("hasAuthority('authuser')")
	public ClientDetails currentClient(OAuth2Authentication user) {
		String clientId = user.getName();
		ClientDetails clientDetails = this.clientDetailsService.loadClientByClientId(clientId) ;
		return clientDetails;
	}
	
```

这里一定要注意：@PreAuthorize("hasAuthority('authuser')")声明的URL(/auth/client)，必须在ResourceServerConfiguration声明了匹配入口(/auth/**)，否则也是不行的。为了便于理解，你可以把声明的代码调整为如下，但意义是一样的，就是让你方便理解：

```
    http.antMatcher("/auth/**").authorizeRequests().anyRequest().permitAll(); // auth开通的请求全部放行
```

```
	@RequestMapping(value = { "/auth/client" }, produces = "application/json")
	@PreAuthorize("hasAuthority('authuser')")  // 要求请求的用户拥有authuser权限
```

如果你有多个URL入口，可以使用如下规则：

```
http.requestMatchers().antMatchers("/auth/**","/9999/**").anyRequest().permitAll();
```

举个例子：

请求URL:

```
curl -i -H "Accept: application/json" -X GET http://192.168.5.31:7020/auth/client?access_token=bcf85382-57db-4274-89c7-a82dda08d2d4 -v
```

其会先执行http.antMatcher("/auth/**").authorizeRequests().anyRequest().authenticated();这个规则，然后会执行@PreAuthorize("hasAuthority('authuser')")这个规则。

@PreAuthorize内的value

```
hasRole，对应 public final boolean hasRole(String role) 方法，含义为必须含有某角色（非ROLE_开头），如有多个的话，必须同时具有这些角色，才可访问对应资源。

hasAnyRole，对应 public final boolean hasAnyRole(String... roles) 方法，含义为只具有有某一角色（多多个角色的话，具有任意一个即可），即可访问对应资源。

hasAuthority，对应 public final boolean hasAuthority(String authority) 方法，含义同 hasRole，不同点在于这是权限，而不是角色，区别就在于权限往往带有前缀（如默认的ROLE_），而角色只有标识。

hasAnyAuthority，对应 public final boolean hasAnyAuthority(String... authorities) 方法，含义同 hasAnyRole，不同点在于这是权限，而不是角色，区别就在于权限往往带有前缀（如默认的ROLE_），而角色只有标识

permitAll，对应 public final boolean permitAll() 方法，含义为允许所有人（可无任何权限）访问。

denyAll，对应 public final boolean denyAll() 方法，含义为不允许任何（即使有最大权限）访问。

isAnonymous，对应 public final boolean isAnonymous() 方法，含义为可匿名（不登录）访问。

isAuthenticated，对应 public final boolean isAuthenticated() 方法，含义为身份证认证后访问。

isRememberMe，对应 public final boolean isRememberMe() 方法，含义为记住我用户操作访问。

isFullyAuthenticated，对应 public final boolean isFullyAuthenticated() 方法，含义为非匿名且非记住我用户允许访问。
```

##### 问题

基于@PreAuthorize声明访问规则，其规则优先级低于ResourceServerConfiguration#configure(HttpSecurity http)方法声明的规则，因此如果你在configure(HttpSecurity http)声明了的规则要谨慎，例如，你在ResourceServerConfiguration定义了 antMatchers("/auth/**").denyAll();，那么即使你声明了@PreAuthorize("permitAll()")，请求返回的还是access_denied错误，因为ResourceServerConfiguration内定义的规则优先级高。

因此你要思考用那种方案：

完全使用ResourceServerConfiguration#configure(HttpSecurity http)代码规则，可以做到规则：antMatchers(/auth/**) -> 定义访问规则 -> denyAll()；

使用@PreAuthorize和ResourceServerConfiguration混合方案，可以做到规则：antMatchers(/auth/**) -> 定义访问规则 -> permitAll()，因为@PreAuthorize声明的规则优先级在ResourceServerConfiguration定义规则之后，你无法在ResourceServerConfiguration中定义denyAll();来结尾。

对比两种方案，最明显的就是当请求一个不存在的URL时，第1种返回access_denied，第2种返回404。

#### 大项目定义访问规则

一个大的项目不可能在一个ResourceServerConfiguration#configure(HttpSecurity http)或者WebSecurityConfiguration#configure(HttpSecurity http)中定义所有的访问规则，因此有两种方法：

1.基于@PreAuthorize声明规则方式，入口使用ResourceServerConfiguration或WebSecurityConfiguration来声明，具体的URL使用@PreAuthorize来保护。但有个小问题，见@PreAuthorize的问题章节。

2.定义接口(HttpSecurityConfiguration)，由各个模块来定义安全规则，例如：

```java
public interface HttpSecurityConfiguration {
	
	public void configure(HttpSecurity httpSecurity) throws Exception;

}
```

ResourceServerConfiguration和WebSecurityConfiguration，引入一个List<HttpSecurityConfiguration> ，例如：

```java
@Configuration
@EnableResourceServer
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
	
	@Autowired
	private List<HttpSecurityConfiguration> httpSecurityConfigurations;
    
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.addFilterBefore(new Oauth2ThreadLocalFilter(), WebAsyncManagerIntegrationFilter.class);
        // 开始，定义允许请求URL /auth/** 开头访问
ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry expressionInterceptUrlRegistry = http.antMatcher("/auth/**").authorizeRequests();
        // 执行各个模块定义的访问规则
		for(HttpSecurityConfiguration securityConfiguration:this.httpSecurityConfigurations) {
			securityConfiguration.configure(http);
		}
        // 结尾使用denyAll()
	    expressionInterceptUrlRegistry.antMatchers("/auth/**").denyAll();
		
	}
}
```



#### json格式还是xml格式

调用oauth2服务返回的信息格式，最好根据请求头Accept来决定，这样即使oauth2鉴权错误的时候，其也会根据Accept请求头来返回相应的格式，例如：

curl -i -H "Accept: application/json" -H "Authorization: Bearer da0d8c14-11e3-4a33-9136-705f2eea283e" -X GET http://192.168.5.31:7020/auth/test?testId=aaa -v

返回：

```json
{"error":"invalid_token","error_description":"Invalid access token: da0d8c14-11e3-4a33-9136-705f2eea283e"}
```

curl -i -H "Accept: application/xml" -H "Authorization: Bearer da0d8c14-11e3-4a33-9136-705f2eea283e" -X GET http://192.168.5.31:7020/auth/test?testId=aaa -v

```xml
<InvalidTokenException><error>invalid_token</error><error_description>Invalid access token: da0d8c14-11e3-4a33-9136-705f2eea283e</error_description></InvalidTokenException>
```

#### 返回错误信息

客户端模式，获取accessToken错误，client_id或者client_secret错误，或者请求参数不完整。

```json
{"error":"invalid_client","error_description":"Bad client credentials"}
```

没有认证，请求没有提供accessToken

```json
{"error":"unauthorized","error_description":"Full authentication is required to access this resource"}
```

提供的accessToken无效，accessToken错误或者已经过期。

```json
{"error":"invalid_token","error_description":"Invalid access token: bcf85382-57db-4274-89c7-a82dda08d2d41"}
```

定义为拒绝访问，请求的url被匹配到denyAll()定义。

这里有个特别有意思的问题，按理来说如果HTTP请求被定义为denyAll()的ur匹配到，则应该直接返回access_denied错误代码，但oauth2目前的实现是，只有认证通过了才会返回access_denied错误代码，否则返回上面的unauthorized或者invalid_token代码。

```json
{"error":"access_denied","error_description":"Access is denied"}
```



### 表结构

#### OAUTH_CLIENT_DETAILS(客户端信息表)

```sql
create table OAUTH_CLIENT_DETAILS
(
  client_id               VARCHAR2(256) not null,
  resource_ids            VARCHAR2(256),
  client_secret           VARCHAR2(256), 
  scope                   VARCHAR2(256),
  authorized_grant_types  VARCHAR2(256), 
  web_server_redirect_uri VARCHAR2(256),
  authorities             VARCHAR2(256),
  access_token_validity   INTEGER,
  refresh_token_validity  INTEGER,
  additional_information  VARCHAR2(3072),
  autoapprove             VARCHAR2(256)
);
alter table OAUTH_CLIENT_DETAILS
  add constraint PK_OAUTH_CLIENT_DETAILS primary key (CLIENT_ID);
```

字段说明：

**client_id** 客户端ID

**resource_ids** 允许访问的资源服务器ID(多个用逗号分隔)，资源服务器上可以通过，如下设置：

```java
	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
		resources.resourceId("oauth-server");
	}
```

如果资源服务器(ResourceServerConfiguration)上配置了resourceId，而你的客户端OAUTH_CLIENT_DETAILS.resource_ids字段没有设置相关的值，则无权访问这个资源服务器。

**client_secret** 客户端秘钥

其应该是一个加密值，你应该使用如下代码来生成：

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
		String textPassword = "12345678";
//		this.testPasswordEncoder( new BCryptPasswordEncoder(), textPassword);
//		this.testPasswordEncoder( new Pbkdf2PasswordEncoder(), textPassword);
//		this.testPasswordEncoder( new SCryptPasswordEncoder(), textPassword);
//		this.testPasswordEncoder( new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("SHA-256"), textPassword);
		this.testPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder(), textPassword);
	}
	

}
```

**scope**  范围(多个用逗号分隔，例如：web,service,mobile)，自定义字符串，定义允许的范围。

**authorized_grant_types**  允许的授权模式(例如：password,authorization_code,implicit,client_credentials,refresh_token)，除了refresh_token是特殊模式外，其它的是oauth2常用的四种模式。refresh_token模式和client_credentials模式不能一起使用，client_credentials模式不支持刷新令牌。

**web_server_redirect_uri** 在code_authorization模式下的登录成功后，应用回调url，必须和/oauth/authorize请求的请求参数redirect_uri相同，一般为http://应用ip:应用port/login，例如：http://192.168.5.32:6002/login，客户端可以通过修改security.oauth2.login-path=/login来配置回调URL。

**authorities** 客户端授权，只要在implicit,client_credentials模式下才有意义，因为在password和authorization_code模式下使用的user的授权。

**access_token_validity** 设定客户端的access_token的有效时间值(单位:秒),可选, 若不设定值则使用默认的有效时间值(60 * 60 * 12, 12小时)。

**refresh_token_validity** 设定客户端的refresh_token的有效时间值(单位:秒),可选, 若不设定值则使用默认的有效时间值(60 * 60 * 24 * 30, 30天)。

**additional_information** 这是一个预留的字段,在Oauth的流程中没有实际的使用,可选,但若设置值,必须是JSON格式的数据,例如：

```json
{"country":"CN","country_code":"086"}
```

**autoapprove** 设置用户是否自动Approval操作, 默认值为 'false', 可选值包括 'true','false', 'read','write'.
该字段只适用于grant_type="authorization_code"的情况,当用户登录成功后,若该值为'true'或支持的scope值,则会跳过用户Approve的页面, 直接授权(单点登录)。

#### OAUTH_USER(用户信息表)

```sql
-- Create table
create table OAUTH_USER
(
  user_id  NUMBER not null,
  username VARCHAR2(45) not null,
  password VARCHAR2(256) not null,
  enabled  CHAR(1) default '1'
);
alter table OAUTH_USER
  add constraint PK_OAUTH_USER primary key (USER_ID);
```

user_id 用户id

username 用户名

password 密码

enabled 是否允许，1允许，0不允许

#### OAUTH_AUTHORITY(授权表)

```sql
create table OAUTH_AUTHORITY
(
  authority_id NUMBER not null,
  name         VARCHAR2(100)
);
alter table OAUTH_AUTHORITY
  add constraint PK_OAUTH_ROLE_ID primary key (AUTHORITY_ID);
```

authority_id 授权id

name 授权名

#### OAUTH_USER_AUTHORITY(用户授权表)

OAUTH_USER和OAUTH_AUTHORITY的多对多中间表

```sql
create table OAUTH_USER_AUTHORITY
(
  user_id      NUMBER not null,
  authority_id NUMBER not null
);
alter table OAUTH_USER_AUTHORITY
  add constraint PK_OAUTH_USER_ROLE primary key (USER_ID, AUTHORITY_ID);
```

user_id 用户id

authority_id 授权id

## oauth2的四种授权模式

### 客户端认证(client credentials)模式

#### 表数据

涉及到的表

OAUTH_CLIENT_DETAILS

涉及到字段

client_id、client_secret、scope、authorized_grant_types、authoritie

例如：

client_id=test_cient

client_secret={bcrypt}$2a$10$wDeaJTAs3KA/BilZmz.k8u7zqjl7spY.fV8juqWNmydDn3KzXWdLm

scope=web,mobile,service

authorized_grant_types=client_credentials # 固定值

authorities=authuser

#### 例子

##### 获取令牌(access_token)

请求：

```bash
 curl -H "Accept: application/json" http://192.168.5.31:7020/oauth/token -d "grant_type=client_credentials&client_id=test_client&client_secret=12345678"
```

返回结果：

```json
{"access_token":"71d58c43-7807-41a8-b9c5-ae0e25fdf3e3","token_type":"bearer","expires_in":42871,"scope":"read write"}
```

##### 服务调用(Bearer模式)

请求例子：

```bash
curl -i -H "Accept: application/json" -H "Authorization: Bearer da0d8c14-11e3-4a33-9136-705f2eea283e" -X GET http://192.168.5.31:7020/auth/client -v
```

返回结果：

```json
{"scope":["service"],"client_id":"test_client","client_secret":"{bcrypt}$2a$10$R1OhSuvgd.KN3zNyxn/xOOU0O8HKgO/SFGV6YrZMjU7t67df88FQm","authorized_grant_types":["client_credentials"],"authorities":["authuser"]}
```

无效令牌

```
{"error":"invalid_token","error_description":"Invalid access token: 615647bb-76ba-48c2-bb57-2cdd3790bf41a"}
```



##### 服务调用(URL参数access_token模式)

```bash
curl -i -H "Accept: application/json" -X GET http://192.168.1.253:7020/auth/user?access_token=da0d8c14-11e3-4a33-9136-705f2eea283e -v
```

返回结果：

```json
{"scope":["service"],"client_id":"test_client","client_secret":"{bcrypt}$2a$10$R1OhSuvgd.KN3zNyxn/xOOU0O8HKgO/SFGV6YrZMjU7t67df88FQm","authorized_grant_types":["client_credentials"],"authorities":["authuser"]}
```

#### 不支持刷新

官方文档也写client credentials不支持刷新，

查看代码java类：ClientCredentialsTokenGranter，看这个方法内的注释：// The spec says that client credentials should not be allowed to get a refresh token，实际调试代码验证也是这样。allowRefresh实例变量永远为false。

```java
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



### 授权码模式(authorization code)

#### 1.理论

**授权码（authorization code）方式，指的是第三方应用先申请一个授权码，然后再用该码获取令牌。**

这种方式是最常用的流程，安全性也最高，它适用于那些有后端的 Web 应用。授权码通过前端传送，令牌则是储存在后端，而且所有与资源服务器的通信都在后端完成。这样的前后端分离，可以避免令牌泄漏。

第一步，A 网站提供一个链接，用户点击后就会跳转到 B 网站，B网站授权用户数据给 A 网站使用。下面就是 A 网站跳转 B 网站的一个示意链接。

> ```javascript
> https://b.com/oauth/authorize?
> response_type=code&
> client_id=CLIENT_ID&
> redirect_uri=CALLBACK_URL&
> scope=read&
> state=random
> ```

上面 URL 中，`response_type`参数表示要求返回授权码（`code`），`client_id`参数让 B 知道是谁在请求，`redirect_uri`参数是 B 接受或拒绝请求后的跳转网址，`scope`参数表示要求的授权范围（这里是只读），state参数生成一个随机数(存放到会话中)。

![img](https://www.wangbase.com/blogimg/asset/201904/bg2019040902.jpg)

第二步，用户跳转后，B 网站会要求用户登录（输入用户名和密码），然后询问是否同意给予 A 网站授权。用户表示同意，这时 B 网站就会跳回`redirect_uri`参数指定的网址。跳转时，会传回一个授权码，就像下面这样。

> ```javascript
> https://www.baidu.com/?code=98LIVE&state=D45s12
> ```

上面 URL 中，`code`参数就是授权码，state参数为/oauth/authorize发送请求的state参数，B站原样返回A站和会话中的state比较，防止有人恶意重定向请求到A站。

![img](https://www.wangbase.com/blogimg/asset/201904/bg2019040907.jpg)

第三步，A 网站拿到授权码以后，就可以在后端(后台)，向 B 网站请求令牌。

> ```javascript
> POST 请求
> 
> https://b.com/oauth/token?
> client_id=CLIENT_ID&
> client_secret=CLIENT_SECRET&
> grant_type=authorization_code&
> code=AUTHORIZATION_CODE&
> redirect_uri=CALLBACK_URL
> ```

上面 URL 中，`client_id`参数和`client_secret`参数用来让 B 确认 A 的身份（`client_secret`参数是保密的，因此只能在后端发请求），`grant_type`参数的值是`AUTHORIZATION_CODE`，表示采用的授权方式是授权码，`code`参数是上一步拿到的授权码，`redirect_uri`参数是第一步的redirect_uri参数雨当前参数两者必须相同(安全验证用)。

![img](https://www.wangbase.com/blogimg/asset/201904/bg2019040904.jpg)

第四步，B 网站收到请求以后，就会颁发令牌，并返回如下json信息。

> ```javascript
> {    
> "access_token":"ACCESS_TOKEN",
> "token_type":"bearer",
> "expires_in":2592000,
> "refresh_token":"REFRESH_TOKEN",
> "scope":"read",
> "uid":100101,
> "info":{...}
> }
> ```

上面 JSON 数据中，`access_token`字段就是令牌，A 网站在后端拿到了。

![img](https://www.wangbase.com/blogimg/asset/201904/bg2019040905.jpg)



#### 2.配置

##### 2.1 pom.xml

```xml
		<!-- spring cloud security oauth2 -->
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-security</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.security.oauth</groupId>
			<artifactId>spring-security-oauth2</artifactId>
		</dependency>		
```

##### 2.2 CodeAuthorizationApplication

```java
@SpringBootApplication
public class CodeAuthorizationApplication {	

	public static void main(String[] args) {
		SpringApplication.run(CodeAuthorizationApplication.class, args);
	}
}
```

没有什么特殊的源注释(配置)，特殊的源注释在其它security相关类上声明。

##### 2.3 application.yml

```yaml
server:
  session:
    cookie:
      # 重命名session.cookie名称,防止覆盖oauth server的JSESSIONID
      name: testclient
      
# oauth2 代码模式(code_authorization)客户端配置
oauth2-server: http://localhost:6001
security:
  oauth2:
    client:
      grant-type: code_credentials    # 授权码模式
      client-id: test_client        # 在oauth 服务端注册的client-id
      client-secret: 123456     # 在oauth 服务端注册的secret
      access-token-uri: ${oauth2-server}/oauth/token    #获取token 地址
      user-authorization-uri: ${oauth2-server}/oauth/authorize  # 认证地址
      scope: web
    resource:
      token-info-uri: ${oauth2-server}/oauth/check_token  # 检查token
      user-info-uri: ${oauth2-server}/auth/user   # 用户信息
    sso:
      login-path: /login  # 回调登录页      
```

server.session.cookie.name=testclient

oauth2的客户端，必须重新设置session的cookie名称，否则在同一域名内会相互覆盖。因为默认spring boot的默认session cookie名称为JSESSIONID，而你为了完成单点登录需要三个项目，oauth2服务器，oauth2客户端1，oauth2客户端2，如果三个项目都使用JSESSION的cookie名称，并且在同一关域内（例如：测试为location），那么三个项目的session cookie会相互覆盖，因此必须为两个测试oauth2客户端重命名session的cookie名称。

问题：目前基于code_authorization模式下，还不能实现基于eureka方式来发现oauth server服务(/oauth2/*)，只能使用oauth2-server： http://localhost:6001，方式来声明一个配置文件变量的方式，尽量来减少将来的oauth2 server服务位置修改带来的影响。这个问题待以后解决。

#### 3.测试

##### 表数据

oauth2 服务器端，要配置允许这个第三方应用访问oauth2服务器。

**OAUTH_CLIENT_DETAILS表** 

| 字段名                      | 数据(样例)                                                   |
| --------------------------- | ------------------------------------------------------------ |
| CLIENT_ID                   | test_client_code                                             |
| RESOURCE_IDS                |                                                              |
| CLIENT_SECRET               | {bcrypt}$2a$10$R1OhSuvgd.KN3zNyxn/xOOU0O8HKgO/SFGV6YrZMjU7t67df88FQm |
| SCOPE                       | web,app                                                      |
| **AUTHORIZED_GRANT_TYPES**  | authorization_code                                           |
| **WEB_SERVER_REDIRECT_URI** | https://www.baidu.com                                        |
| AUTHORITIES                 | tgms                                                         |
| ACCESS_TOKEN_VALIDITY       |                                                              |
| REFRESH_TOKEN_VALIDITY      |                                                              |
| ADDITIONAL_INFORMATION      |                                                              |
| **AUTOAPPROVE**             | true                                                         |

code_authorization模型下，有三个字段会被使用：

AUTHORIZED_GRANT_TYPES，必须含有authorization_code字样。

WEB_SERVER_REDIRECT_URI，认证成功后重定向到应用的URL，必须和/oauth/authorize和/oauth/token请求的请求参数redirect_uri相同，一般为http://应用ip:应用port/login，例如：http://192.168.5.31:1111/login，客户端可以通过修改security.oauth2.login-path=/login来配置回调URL。

AUTOAPPROVE，是否自动授权（是否需要用户手工点击授权），字段值为true或者与请求参数scope值相同时，则不需要用户手工授权，变为自动授权。默认为NULL的时候，需要用户手工授权。一般自动授权用于单点登录，非自动授权用于用户授权自身数据给第三方应用。

CLIENT_SECRET，这里加密前的密码为12345678

**OAUTH_USER表**

oauth2_user表加入允许登录的用户。

| 字段名   | 数据(样例)                                                   |
| -------- | ------------------------------------------------------------ |
| USER_ID  | 2                                                            |
| USERNAME | user1                                                        |
| PASSWORD | {bcrypt}$2a$10$R1OhSuvgd.KN3zNyxn/xOOU0O8HKgO/SFGV6YrZMjU7t67df88FQm |
| ENABLED  | 1                                                            |

PASSWORD，这里加密前的密码为12345678

##### WebSecurityConfiguration(oauth服务器端)

```java
	@Override
	public void configure(HttpSecurity httpSecurity) throws Exception {
		
		// 授权码模式(authorization_code)配置
		// 授权码模式下,会用到/oauth/authorize(授权URL)、/login(登录页)、/oauth/confirm_access(用户授权确认),
		httpSecurity.authorizeRequests().antMatchers("/login").permitAll().and().formLogin().permitAll()
		.and().authorizeRequests().antMatchers("/oauth/authorize","/oauth/confirm_access").authenticated();
		
		// actuator
		httpSecurity.authorizeRequests()
		.antMatchers("/actuator/**").hasRole("actuator") // 需要在OAUTH_USER表中增加一个用户并且由actuator角色
		.and().httpBasic()
		.and().csrf().disable();
		
		// 禁止所有
		httpSecurity.authorizeRequests().anyRequest().denyAll();
		
	}
```

这里给/login、/oauth/authorize和/oauth/confirm_access的URL进行授权

/login，登录

/oauth/authorize，授权

/oauth/confirm_access，用户手工授权(AUTOAPPROVE)，确认页面。

##### 基于浏览器完成测试

1.浏览器地址栏：http://192.168.5.31:7020/oauth/authorize?response_type=code&client_id=test_client_code&redirect_uri=https://www.baidu.com&scope=web&state=123456

2.登录页面输入user1和12345678，提交。

3.获取地址栏上的code值：https://www.baidu.com/?code=98LIVE&state=123456

4.curl发送请求：curl -v -X POST  "http://192.168.5.31:7020/oauth/token" -d "client_id=test_client_code&client_secret=12345678&grant_type=authorization_code&code=98LIVE&redirect_uri=https://www.baidu.com"，这里注意code参数值。



##### 基于CURL完成测试

###### /login(模拟登录)

```java
curl -v -X POST http://192.168.5.31:7020/login -d "username=user1&password=12345678"
```
记录返回的JSESSIONID值，下面要用。
```
Set-Cookie: JSESSIONID=EF70DCE4DCA8C35AA66052E391E27250; Path=/; HttpOnly
```

基于浏览器的页面测试是不需要这步的，其在执行下面/oauth/authorize请求的时候，oauth2 server判断还没有认证(登录)，会重定向到/login页面。

###### /oauth/authorize(认证)

```
curl -v -H "Cookie: JSESSIONID=EF70DCE4DCA8C35AA66052E391E27250" "http://192.168.5.31:7020/oauth/authorize?response_type=code&client_id=test_client_code&redirect_uri=https://www.baidu.com&scope=web&state=123456"
```

记录返回的code，下面要用。

```
Location: https://www.baidu.com?code=9GUyrk&state=123456
```

###### /oauth/token(获取access_token)

```
curl -v -X POST  "http://192.168.5.31:7020/oauth/token" -d "client_id=test_client_code&client_secret=12345678&grant_type=authorization_code&code=9GUyrk&redirect_uri=https://www.baidu.com"
```

记录返回access_token

```json
{"access_token":"35034ca7-54c0-4f5b-9f01-25b4bf119832","token_type":"bearer","expires_in":43199,"scope":"web"}
```

###### /auth/user(获取登录用户信息)

测试一下是否可以通过access_token来调用oauth2服务器端上的服务了。

```
curl -v -H "Accept: application/json" "http://192.168.5.31:7020/auth/user?access_token=35034ca7-54c0-4f5b-9f01-25b4bf119832"
```



```json
{"user":{"id":2,"username":"user1","password":"{bcrypt}$2a$10$R1OhSuvgd.KN3zNyxn/xOOU0O8HKgO/SFGV6YrZMjU7t67df88FQm","enabled":true,"authorities":[],"accountNonExpired":true,"credentialsNonExpired":true,"accountNonLocked":true},"authorities":[]}
```

###### /oauth/check_token(检查access_token是否合法)

前提是AuthorizationServerConfiguration设置checkTokenAccess访问权限为公开security.checkTokenAccess("permitAll()");

```
curl -v -X POST -H "Accept: application/json" "http://192.168.5.31:7020/oauth/check_token?token=35034ca7-54c0-4f5b-9f01-25b4bf119832"
```



```
{"active":true,"exp":1604790905,"user_name":"user1","client_id":"test_client_code","scope":["web"]}
```





#### 3.测试

##### 3.1 页面测试

启动三个项目：

sc-oauth2（认证服务器），端口6001

sc-oauth2-codeauthorization（第三方应用1），端口6002

sc-oauth2-codeauthorization1（第三方应用2），端口6003

发送请求：http://localhost:6002/

发现还没登录，则会自动重定向到http://localhost:6001/login，正确输入User和Password，点击登录；

登录成功后，重定向回http://localhost:6002/，显示 ”客户端主页(6002)-测试成功“。

再发送请求：http://localhost:6003/，则无需登录（因为上面已经登录)，直接显示 ”客户端主页(6003)-测试成功“。

##### 3.2 /oauth2/* 

结合3.1 的页面测试，把这个认证请求的全过程说明一下，重点说明请求的URL：

发送请求http://localhost:6002/到sc-oauth2-codeauthorization服务器，

sc-oauth2-codeauthorization验证还没登录，则生成URL：/oauth/authorize?**（例如：http://localhost:6001/oauth/authorize?client_id=test_client&redirect_uri=http://localhost:6002/login&response_type=code&scope=web&state=dj43AZ），并重定向到sc-oauth2。

sc-oauth2收到/oauth/authorize?**请求，会进入登录页（http://localhost:6001/login）,提示最终用户输入用户名和密码。

最终用户输入用户名和密码提交到http://localhost:6001/login，其验证成功后，会重定向会sc-oauth2-codeauthorization的/login?**，并带上code和state两个参数（例如：http://localhost:6002/login?code=NNYMgO&state=dj43AZ）。

sc-oauth2-codeauthorization根据code生成URL：/oauth2/token（例如：http://localhost:6001/oauth/token，/oauth2/token的请求介绍见：sc-auth2文档），并使用RestTemplate发送这个请求到sc-oauth2来获取access_token。

sc-oauth2-codeauthorization获取access_token成功后，会重定向回最初发送请求的url（例如：http://localhost:6002/），因为已经登录了，就可以顺利的进入sc-oauth2-codeauthorization的"/"，页面了。

###### /oauth2/authorize

作用：客户端认证，客户端认证成功后，其会跳转到oauth server的登录页(/login)。

例如：

http://localhost:6001/oauth/authorize?client_id=test_client&redirect_uri=http://localhost:6002/login&response_type=code&scope=web&state=dj43AZ

client_id 请求客户端id

redirect_url 回调应用的url

response_type 响应类型，固定为code

scope 客户端范围

state 状态码，请求时自定义一个随机码，用户登录成功后，重定向回到redirect_uri时，会带上这个参数，为了安全。例如：登录成功后(用户名和密码输入正确后)，回调的URL如下：http://localhost:6002/login?code=NNYMgO&state=dj43AZ

##### 3.3 cookie

按照上面的页面测试，开启了三个项目，如果按照上面的步骤，会生成三个cookie，oauth2 server的JSESSIONID的cookie(会话)、sc-oauth2-codeauthorization的testclient的cookie(会话)、sc-oauth2-codeauthorization1的testclient1的cookie(会话)。其中testclient和testclient1，是两个sc-oauth2-codeauthorization项目在配置server.session.cookie.name中指定的。同时，这三个cookie也是维系整个oauth2登录体系的令牌。

#### 4.logout登出

##### 4.1 单点登出

**第三方应用配置登出**

在第三方应用（例如：sc-oauth2-codeauthorization）的SecurityConfiguration类配置，配置登出成功url，其在调用本应用成功后会调用oauth2服务器端url，完成oauth server的登出。

```java
	@Value("${security.oauth2.client.client-id}")
	private String clientId;
    
	@Override
	public void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http.csrf().disable().authorizeRequests().antMatchers("/login").permitAll().
		and().logout().logoutSuccessUrl("http://localhost:6001/auth/exit?clientId="+this.clientId).
		and().authorizeRequests().antMatchers("/**").authenticated();
		// @formatter:on
	}
```

这里的URL：http://localhost:6001/auth/exit?clientId="+this.clientId，会发送登出请求到oauth2 server。

**oauth server 登出处理**

```java
	@Autowired 
	private ClientDetailsService clientDetailsService;

	@RequestMapping(value="/auth/exit",params="clientId")
	public void exit(HttpServletRequest request, HttpServletResponse response,@RequestParam String clientId) {
		ClientDetails clientDetails = this.clientDetailsService.loadClientByClientId(clientId);
		if(clientDetails!=null && !CollectionUtils.isEmpty(clientDetails.getRegisteredRedirectUri())) {
			// oauth server 登出
			new SecurityContextLogoutHandler().logout(request, null, null);
			// 使用在client_details注册回调uri中最后一个作为退出回调uri
			String[] clientRedirectUris = clientDetails.getRegisteredRedirectUri().toArray(new String[0]);
			String appRedirectUrl = clientRedirectUris[clientRedirectUris.length-1];
			try {
				response.sendRedirect(appRedirectUrl);
			} catch (IOException ex) {
				throw new RuntimeException(ex);
			}
		}

	}
```

通过执行spring security的new SecurityContextLogoutHandler().logout(request, null, null)，完成服务器端登出(session invalid)。通过clientId请求参数获取client_detials的回调url，重定向到发起请求的client端。

### 两种认证传递方式

client_credentials模式，认证通过后，通过请求参数access_token来传递会话ID。

authorization_code模式，认证通过后，通过JSESSIONID来传递会话ID。

### 需要两个授权模式同时存在

### 运政系统重构

我思考过一个问题，如果拆分运政系统，想法是，把一个运政系统拆分为6个独立的应用：业户应用、线路应用、车辆应用、从业人员应用、处罚应用、其它应用(包括，主界面、登录、安全、菜单和系统参数等)。如果有必要再单能一个数据模型应用，专门存放Jpa Entity(或者domain+hbm.xml)，供其他应用通过jpa获取数据使用。

这个几个应用首先需要一个单点登录系统，这个可以使用authorization_code模式来实现。应用之间的服务调用通过client_credentials模式来实现。也就是说不同应用之间的**界面穿插**通过单点登录后用户的COOKIE JSESSIONID来完成，不用应用之间的**功能调用**通过access_token来完成。本应用内的功能(url)访问规则通过WebSecurityConfigration来实现，本应用对外提供的服务(service)访问规则通过ResourceServerConfiguration来实现。为了应用之间服务(client_credentials模式)调用方便，专门封装一个TgmsServerInvokeRestTemplate客户端，其内部封装了如何获取access_token，过期后重新获取access_token等功能。

流程：

1.用户通过oauth server服务单点登录，登录成功回调为主界面URL。

2.主界面通过/auth/user服务获取登录用信息，并读取用户菜单列表，显示界面左侧，并读取用户代办事宜显示界面后侧。

3.用户点击菜单，进入不同应用的不同功能，例如：

3.1.用户点击新增车辆(/car/new)，则请求到"车辆应用"，车辆应用处理流程如下：

​      3.1.1. 车辆应用验证本应用没有登录，则发送/oauth/authorize请求到oauth server进行登录处理。

​      3.1.1. 根据WebSecurityConfigration定义的规则(例如:antMatchers("/car/new",carNew)，验证这个用户是否有访问新增车辆URL的权限。

​      3.1.2 进入到新增车辆界面(NewCarFormController，@RequestMapping("/car/new"))。

​      3.1.2.1.新增车辆界面上有一个输入框(渐进输入模糊查询)，为选择隶属用户，发送请求到"业户应用"，模糊查询用户(/ent/find)，并选择。

​      3.1.3.提交(newCarFormSubmit)，代码其中有一步，调用业户应用提供的服务(验证用户 /ent/check)验证entId对应的业户是否存在并且有效，基于TgmsServerInvokeRestTemplate来完成调用(/ent/check?access_token=xxxxxxxxxxx&entId=123456&yzryxh=696969)，验证成功后保存新车辆数据到数据库。

4.验证用户服务

   4.1. 根据ResourceServerConfiguration的规则antMatcher("/ent/**",hasRole(tgms))，任何有tgms角色的clientDetails都可以访问ent内所有服务。

   4.2. /ent/check controller方法，获取entId，检查entId是否存在，是否有效。并日志记录查询操作，记录日志操作通过调用"其它应用“的/log/add服务完成。这有个问题，就是操作人(运政人员序号)如何获取，这个/ent/check的controller方法(method)，我们针对这个问题定义了两个Controller参数Long yzryxh和OAuth2Authentication authentication，如果是服务调用，则调用方(服务调用客户端)会带yzryxh参数，如果是通过页面调用则会根据COOKIE(JESSIONID)来自动获取认证信息(oauth2客户端自动完成)来填充OAuth2Authentication对象，controller内部代码根据OAuth2Authentication是否为空来判断从哪里来获取操作人信息。



## zuul+oauth2

### **第一种模式(不推荐)**

身份认证、鉴权全部由zuul来完成，后端的服务不进行身份认证和鉴权。

zuul作为oauth2的客户端，其内的ResourceServerConfiguration定义所有服务的访问规则，也就说身份认证和鉴权全部在zuul端完成，zuul验证成功的请求后端的服务无须再进行认证和鉴权了。



张三只能访问服务a(/service1/a)、服务b(/service1/b)、服务c(/service2/c)。

李四只能访问服务c(/service2/c)、服务d(/service3/d)、服务e(/service3/e)。



zuul的ResourceServerConfiguration的定义，这个可以通过使用spring表达式，从数据库中获取规则；

antMatcher("/service1/a").hasAuthority("servicea");

antMatcher("/service1/b").hasAuthority("serviceb");

antMatcher("/service2/c").hasAuthority("servicec");

antMatcher("/service3/d").hasAuthority("serviced");

antMatcher("/service3/e").hasAuthority("servicee");

人员权限表。

张三，持有servicea、serviceb、servicec权限。

李四，持有servicec、serviced、servicee权限。

认证和鉴权

张三登录，访问/service1/a，因为其持有servicea权限，可以通过验证，并经过zuul路由到/service1服务器，并访问/service1/a；

​               ，访问/service1/b，因为其持有serviceb权限，可以通过验证，并经过zuul路由到/service1服务器，并访问/service1/b；

​               ，访问/service2/c，因为其持有servicec权限，可以通过验证，并经过zuul路由到/service2服务器，并访问/service2/c；

​               ，访问/service3/d，因为其没有serviced权限，无法通过验证，直接被拒绝访问；

李四登录，访问/service2/c，因为其持有servicec权限，可以通过验证，并经过zuul路由到/service2服务器，并访问/service2/c；

​               ，访问/service3/d，因为其持有serviced权限，可以通过验证，并经过zuul路由到/service3服务器，并访问/service3/d；

​               ，访问/service3/e，因为其持有servicee权限，可以通过验证，并经过zuul路由到/service3服务器，并访问/service3/e；

​               ，访问/service1/a，因为其没有servicea权限，无法通过验证，直接被拒绝访问；



弊端：内网服务之间访问，无法进行鉴权。例如：服务a可以不需要认证和鉴权就可以访问服务b。解决：服务之间不允许直接调用必须通过服务网关，服务只允许zuul访问(白名单ip)。这种模式，各个服务无须再使用eureka的服务发现，只需要服务注册就可以了。但问题又来了，内部服务之间的调用不再服务发现了，Ribbon和Feign意义不大了。



### 第二种模式(不推荐)

zuul不负责身份认证、鉴权，其只负责请求转发，身份认证、鉴权还是由各个后端服务来完成。



张三只能访问服务a(/service1/a)、服务b(/service1/b)、服务c(/service2/c)。

李四只能访问服务c(/service2/c)、服务d(/service3/d)、服务e(/service3/e)。



service1的ResourceServerConfiguration定义：

antMatcher("/service1/a").hasAuthority("servicea");

antMatcher("/service1/b").hasAuthority("serviceb");



service2的ResourceServerConfiguration定义：

antMatcher("/service2/c").hasAuthority("servicec");



service3的ResourceServerConfiguration定义：

antMatcher("/service3/d").hasAuthority("serviced");

antMatcher("/service3/e").hasAuthority("servicee");



人员权限表。

张三，持有servicea、serviceb、servicec权限。

李四，持有servicec、serviced、servicee权限。

认证和鉴权

张三登录，访问/service1/a，zuul路由请求到service1服务器，service1服务器通过验证，并访问/service1/a；

​               ，访问/service1/b，zuul路由请求到service1服务器，service1服务器通过验证，并访问/service1/b；

​               ，访问/service2/c，zuul路由请求到service2服务器，service2服务器通过验证，并访问/service2/c；

​               ，访问/service3/d，zuul路由请求到service2服务器，service3无法通过验证，直接被拒绝访问；

李四登录，访问/service2/c，zuul路由请求到service2服务器，service2服务器通过验证，并访问/service2/c；

​               ，访问/service3/d，zuul路由请求到service3服务器，service2服务器通过验证，并访问/service3/d；

​               ，访问/service3/e，zuul路由请求到service3服务器，service3服务器通过验证，并访问/service3/e；

​               ，访问/service1/a，zuul路由请求到service1服务器，service1无法通过验证，直接被拒绝访问；



弊端：每个内部服务都要自己定义ResourceServerConfiguration访问规则，每个服务都要连接到oauth service服务器进行认证和鉴权。



### 第三种模式(推荐)

对前两种的折中和混合

重新定义内部服务调用和外部服务调用之间的关系，内部服务调用应该是在一个相对可信的范围内，只需要简单的认证和粗粒度的鉴权。外部服务调用必须有严格认证和细粒度的鉴权，例如：我们拿运政系统来举例子，参见上面"运政系统重构"，各个应用对外提供的服务(service)只进行了基本的鉴权认证(认证+hasRole(tgms))，因为运政系统各个应用之间的服务调用建立在一个相对可信的环境中。下面我们重点来分析，第三方应用通过zuul来访问运政系统各个应用提供的服务。

所有第三方应用，都必须基于client_credentials授权模式，在OAUTH_CLIENT_DETAILS表定义第三方应用信息，并在authorities字段记录其拥有的权限列表(逗号分隔)。



### 外部系统调用服务

举例子：大连运政系统调用省运政系统上的服务。

#### OAUTH_CLIENT_DETAILS表 

| 字段名                  | 数据(样例)                                                   |
| ----------------------- | ------------------------------------------------------------ |
| CLIENT_ID               | dlyz                                                         |
| RESOURCE_IDS            |                                                              |
| CLIENT_SECRET           | {bcrypt}$2a$10$R1OhSuvgd.KN3zNyxn/xOOU0O8HKgO/SFGV6YrZMjU7t67df88FQm |
| SCOPE                   | service                                                      |
| AUTHORIZED_GRANT_TYPES  | client_credentials                                           |
| WEB_SERVER_REDIRECT_URI |                                                              |
| AUTHORITIES             | car_new,car_update,ent_find,ent_check,ROLE_tgms              |
| ACCESS_TOKEN_VALIDITY   |                                                              |
| REFRESH_TOKEN_VALIDITY  |                                                              |
| ADDITIONAL_INFORMATION  |                                                              |
| AUTOAPPROVE             |                                                              |

authorities字段内容car_new,car_update,ent_find,ent_check,ROLE_tgms，前四个权限是为了通过zuul细粒度鉴权，最后一个ROLE_tgms是为通过zuul后可以访问运政系统各个应用内的服务

#### ZUUL的ResourceServerConfiguration定义

zuul上定义了细粒度的访问规则，如下：

antMatchers("/oauth/token").permitAll();

antMatchers("/car/new").hasAuthority("car_new");

antMatchers("/car/update").hasAuthority("car_update");

antMatchers("/ent/find").hasAuthority("ent_find");

antMatchers("/ent/check").hasAuthority("ent_check");

antMatchers("/other/user/add").hasAuthority("other_user_add");

#### tgms_car的ResourceServerConfiguration定义

这里的tgms_car为运政系统的车辆应用(独立应用)

车辆应用定义了粗粒度的访问规则，如下：

antMatchers("/car/**").hasRole("tgms");

#### 模拟大连运政发起服务调用请求

**调用客户端**

发送请求：http://10.60.33.21/api/car/new?access_token=023u84b32uo2342p3o2m3n4

**ZUUL**

1.验证access_token有效；

2.antMatchers("/car/new").hasAuthority("car_new");，规则匹配成功；

3.转发请求到tgms_car；

**tgms_car**

1.验证access_token有效；

2.antMatchers("/car/**").hasRole("tgms");，规则匹配成功；



### 内部系统调用服务

举例子：用户应用调用车辆应用上的服务。

#### OAUTH_CLIENT_DETAILS表 

| 字段名                  | 数据(样例)                                                   |
| ----------------------- | ------------------------------------------------------------ |
| CLIENT_ID               | ent_tgms                                                     |
| RESOURCE_IDS            |                                                              |
| CLIENT_SECRET           | {bcrypt}$2a$10$R1OhSuvgd.KN3zNyxn/xOOU0O8HKgO/SFGV6YrZMjU7t67df88FQm |
| SCOPE                   | service,web,app                                              |
| AUTHORIZED_GRANT_TYPES  | client_credentials,authorization_code                        |
| WEB_SERVER_REDIRECT_URI | http://10.60.33.30/login                                     |
| AUTHORITIES             | ROLE_tgms                                                    |
| ACCESS_TOKEN_VALIDITY   |                                                              |
| REFRESH_TOKEN_VALIDITY  |                                                              |
| ADDITIONAL_INFORMATION  |                                                              |
| AUTOAPPROVE             | true                                                         |

这里同时支持两种授权模式，authorization_code授权模式见上面的文章"运政系统重构"。client_credentials模式为了应用之间服务调用，authorities字段内容ROLE_tgms表示拥有tgms角色。

#### gms_car的ResourceServerConfiguration定义

这里的tgms_car为运政系统的车辆应用(独立应用)

车辆应用定义了粗粒度的访问规则，如下：

antMatchers("/car/**").hasRole("tgms");

#### 模式用户应用对车辆应用服务调用请求

ribbon http://tgms_car/car/list?entId=xxxx，模拟获取某个用户下所有车辆

**tgms_car应用**

1.验证access_token有效；

2.antMatchers("/car/**").hasRole("tgms");，规则匹配成功；









## oauth2后台管理

对表数据进行管理，对Redis进行管理。

功能：

客户端管理：增加客户端、修改客户端、删除客户端、客户端授权。

用户管理：增加用户、修改用户、删除用户、授权。只有密码模式和code模式有用。

权限管理：增加权限、修改权限、删除权限。

