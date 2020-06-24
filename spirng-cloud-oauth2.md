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

这里最重要的就是：spring-cloud-starter-oauth2，其它的依赖包，都是config、eureka、jpa等。

### yaml

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

### 代码解读

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

#### AuthorizationServerConfiguration



token存储

token存储服务，不只存储了访问令牌(access_token)，而且其还会根据数据库读取client的认证数据，然后把认证的数据缓存，缓存过期时间就是access_token的过期时间(expires_in)，也就是说在这个时间内，即使你修改了数据库的client相关信息，例如：清空了authorites字段，但原来的hasAuthority和hasRole判断任会返回true，因为客户端信息(client_details)还在缓存中还没有过期。RedisTokenStore#storeAccessToken

DefaultTokenServices#loadAuthentication(String accessTokenValue)



### 系统默认的token规则

	private int refreshTokenValiditySeconds = 60 * 60 * 24 * 30; // default 30 days.
	private int accessTokenValiditySeconds = 60 * 60 * 12; // default 12 hours.
	private boolean supportRefreshToken = false;
	private boolean reuseRefreshToken = true;
刷新令牌(refresh_token)有效期默认为30天；

访问令牌(access_token)有效期默认为12小时；

默认不支持刷新令牌；

默认每次刷新令牌都重新改变access_token值；

每个客户端都可以定制这些token属性，如果没有设置，则使用系统默认的属性值。

### redis缓存管理

clientDetails缓存，是否启动缓存，缓存过期时间(默认5秒)；redis的key，oauth2_client_${clientId}，

user缓存，是否启动缓存，缓存过期时间(默认5秒)；redis的key，oauth2_user_${username}，

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
		this.testPasswordEncoder( new BCryptPasswordEncoder(), textPassword);
//		this.testPasswordEncoder( new Pbkdf2PasswordEncoder(), textPassword);
//		this.testPasswordEncoder( new SCryptPasswordEncoder(), textPassword);
//		this.testPasswordEncoder( new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("SHA-256"), textPassword);
//		this.testPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder(), textPassword);
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
该字段只适用于grant_type="authorization_code"的情况,当用户登录成功后,若该值为'true'或支持的scope值,则会跳过用户Approve的页面, 直接授权。

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

client_id、client_secret、scope、authorized_grant_types、authorities；

例如：

client_id=test

client_secret={bcrypt}$2a$10$wDeaJTAs3KA/BilZmz.k8u7zqjl7spY.fV8juqWNmydDn3KzXWdLm

scope=web,mobile,service

authorized_grant_types=client_credentials # 固定值

authorities=authuser

#### 例子

##### 获取令牌(access_token)

请求：

```bash
 curl -H "Accept: application/json" http://192.168.5.31:7020/oauth/token -d "grant_type=client_credentials&client_id=test&client_secret=12345678"
```

返回结果：

```json
{"access_token":"71d58c43-7807-41a8-b9c5-ae0e25fdf3e3","token_type":"bearer","expires_in":42871,"scope":"read write"}
```

##### 服务调用(Bearer模式)

请求例子：

```bash
curl -i -H "Accept: application/json" -H "Authorization: Bearer da0d8c14-11e3-4a33-9136-705f2eea283e" -X GET http://192.168.1.253:7020/auth/user -v
```

返回结果：

```json
{}
```

##### 服务调用(URL参数access_token模式)

```bash
curl -i -H "Accept: application/json" -X GET http://192.168.1.253:7020/auth/user?access_token=da0d8c14-11e3-4a33-9136-705f2eea283e -v
```

返回结果：

```json
{}
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



### ResourceServerConfiguration

```java
/**
 * 资源服务安全配置类
 * 用于服务(service)的安全规则配置，区别于SecurityConfiguration用于web(http)的安全规则配置。
 * @author zhangdb
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
	 * 系统默认的/oauth/xxx相关请求也是基于ResourceServerConfiguration实现的,只不过系统默认已经配置完了。
	 */
	@Override
	public void configure(HttpSecurity http) throws Exception {
		// 提供给client端用于认证
		http.antMatcher("/auth/**").authorizeRequests().
		antMatchers("/auth/user").authenticated().
        antMatchers("/auth/**").denyAll();
	}
}
```

因为ResourceServerConfiguration的HttpSecurity配置，只有使用http.antMatcher(...)方法开头才不能覆盖SecurityConfiguration的HttpSecurity配置，因此在配置的时候需要一些技巧，例如：

```
第一个http.antMatcher("/auth/**").authorizeRequests()配置了整个安全配置链要管理的URL范围；技巧，提供服务的情况下可以设置"/service/**"；
第二个antMatchers("/auth/user").authenticated()配置了/auth/user的url访问必须是已认证请求(已经正确获取了token)；
第三个antMatchers("/auth/**").denyAll()配置了除了上面的配置，其它所有的/auth开通的URL请求都是禁止的；
```

注意：http security的安全过滤规则是配置越靠前优先级别越高；

测试验证：

发送请求：http://192.168.1.253:7020/auth/user，可以正常返回值，并且响应码为200，证明antMatchers("/auth/user").authenticated()配置正确。

```
curl -i -H "Accept: application/json" -H "Authorization: Bearer da0d8c14-11e3-4a33-9136-705f2eea283e" -X GET http://192.168.1.253:7020/auth/user -v
```

发送请求：http://192.168.1.253:7020/auth/test?testId=aaa，返回值错误{"error":"access_denied","error_description":"Access is denied"}，并且响应码为403，证明antMatchers("/auth/**").denyAll()配置正确。

```
curl -i -H "Accept: application/json" -H "Authorization: Bearer da0d8c14-11e3-4a33-9136-705f2eea283e" -X GET http://192.168.1.253:7020/auth/test?testId=aaa -v
```



## PasswordEncoder

spring boot security新版本只保留了BCrypt、Pbkdf2、SCrypt三个加密实现，其它都已经被禁用了包括SHA256。

PasswordEncoder的接口实现，应该使用PasswordEncoderFactories.createDelegatingPasswordEncoder()静态方法创建出了PasswordEncoder实例，其提供了基于委托加密字符串。

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

### BCrypt

BCrypt上网查一下资料很多，但总结一点就是，BCrypt就是慢，因为慢所以也安全，举个例子SHA256计算hash值1ms内搞定，而BCrypt则需要190ms多，是SHA256的200倍左右。慢是故意的就是为了让你破解也慢。因此在设计程序的时候，要考虑使用BCrypt加密和验证是否符合你的响应时间要求，你可能说可以缓存呀，但问题来了，如果缓存了还安全吗？这个需要设计程序来衡量利弊。



## 编码(code)

### 获取当前认证信息

```java
OAuth2Authentication authentication = (OAuth2Authentication) SecurityContextHolder.getContext().getAuthentication();

// 获取客户端id
String clientId = authentication.getOAuth2Request().getClientId();
```

### 调用/oauth/token重新加载认证信息

当数据库中的client_details数据已经被修改，但当前会话认证数据(OAuth2Authentication)没有被同步修改。因为使用TokenStore存储的OAuth2Authentication对象(序列化和反序列化)信息还是上一次使用/oauth/token获取的信息，这就需要再次调用/oauth/token重新获取OAuth2Authentication信息并存储。

### ~~动态访问控制~~

```
@Service
public class AuthorizationRuler {
	
	public boolean canAccess(HttpServletRequest request,Authentication authentication) {
		System.out.println(request);
		System.out.println(authentication);
		System.out.println(request.getRequestURL());
		return true;
	}

}
```

ResourceServerConfiguration类

```
	@Bean
    public OAuth2WebSecurityExpressionHandler oAuth2WebSecurityExpressionHandler(ApplicationContext applicationContext) {
        OAuth2WebSecurityExpressionHandler expressionHandler = new OAuth2WebSecurityExpressionHandler();
        expressionHandler.setApplicationContext(applicationContext);
        return expressionHandler;
    }

	@Autowired
	private OAuth2WebSecurityExpressionHandler oauth2WebSecurityExpressionHandler;
	
	
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.expressionHandler(this.oauth2WebSecurityExpressionHandler);
    }
    
	@Override
	public void configure(HttpSecurity http) throws Exception { 	   http.antMatcher("/**").authorizeRequests().anyRequest().access("@authorizationRuler.canAccess(request,authentication)");    
	}
	
```

### oauth2环境下加入过滤器

例如：下面加入了一个ThreadLocal过滤器，其为了在清理ThreadLocal内的变量。

1.创建一个过滤器，非常标准的过滤器，继承spring的GenericFilterBean

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

2.指定过滤器执行的位置，通过ResourceServerConfiguration的HttpSecurity设置，下面的例子指定了Oauth2ThreadLocalFilter过滤器，在WebAsyncManagerIntegrationFilter过滤器前执行；

```java
		http.addFilterBefore(new Oauth2ThreadLocalFilter(), WebAsyncManagerIntegrationFilter.class);
```



## HttpSecurity

HttpSecurity是oauth2的规则配置类，其配置访问控制，配置安全属性等。在oauth2中HttpSecurity的访问规则，分为两部分，1.资源(Resource)访问控制，2.web访问控制，资源访问控制理解为**服务(service)**的访问控制，web访问控制理解为**系统**的访问控制，例如：登录访问控制、业务功能的增、删、改查控制。

资源访问控制：资源访问控制由ResourceServerConfigurerAdapter类configure(HttpSecurity http)方法来实现；web访问控制：web访问控制由WebSecurityConfigurerAdapter类(HttpSecurity http)方法来实现；

正常情况下你需要分别定义类并分别继承上面的两个类，来完成不同的访问控制。

ResourceServerConfigurerAdapter类的HttpSecurity必须基于http.antMatcher(...)方法开头匹配，而WebSecurityConfigurerAdapter类的HttpSecurity不能基于http.antMatcher(...)方法开头匹配，否则两个规则会相互覆盖。

### ResourceServerConfiguration

ResourceServerConfigurerAdapter类的HttpSecurity访问规则应该先使用http.antMatcher(...)方来限制整个访问规则的url范围。

```java
/**
 * 资源服务安全配置类
 * 用于服务(service)的安全规则配置，区别于SecurityConfiguration用于web(http)的安全规则配置。
 * @author zhangdb
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
	 * 系统默认的/oauth/xxx相关请求也是基于ResourceServerConfiguration实现的,只不过系统默认已经配置完了。
	 */
	@Override
	public void configure(HttpSecurity http) throws Exception {
		// 提供给client端用于认证
		http.antMatcher("/auth/**").authorizeRequests().
		antMatchers("/auth/user").authenticated().
        antMatchers("/auth/**").denyAll();
	}
}
```

因为ResourceServerConfiguration的HttpSecurity配置，只有使用http.antMatcher(...)方法开头才不能覆盖SecurityConfiguration的HttpSecurity配置，因此在配置的时候需要一些技巧，例如：

```
第一个http.antMatcher("/auth/**").authorizeRequests()配置了整个安全配置链要管理的URL范围；技巧，提供服务的情况下可以设置"/service/**"；
第二个antMatchers("/auth/user").authenticated()配置了/auth/user的url访问必须是已认证请求(已经正确获取了token)；
第三个antMatchers("/auth/**").denyAll()配置了除了上面的配置，其它所有的/auth开通的URL请求都是禁止的；
```

注意：http security的安全过滤规则是配置越靠前优先级别越高；

测试验证：

发送请求：http://192.168.1.253:7020/auth/user，可以正常返回值，并且响应码为200，证明antMatchers("/auth/user").authenticated()配置正确。

```
curl -i -H "Accept: application/json" -H "Authorization: Bearer da0d8c14-11e3-4a33-9136-705f2eea283e" -X GET http://192.168.1.253:7020/auth/user -v
```

发送请求：http://192.168.1.253:7020/auth/test?testId=aaa，返回值错误{"error":"access_denied","error_description":"Access is denied"}，并且响应码为403，证明antMatchers("/auth/**").denyAll()配置正确。

```
curl -i -H "Accept: application/json" -H "Authorization: Bearer da0d8c14-11e3-4a33-9136-705f2eea283e" -X GET http://192.168.1.253:7020/auth/test?testId=aaa -v
```

### WebSecurityConfiguration

WebSecurityConfiguration的访问规则，应该局限在系统的访问控制(例如：登录、登出，业务操作、js和css等)，而且不应该使用http.antMatcher(...)开头访问控制，否则会和ResourceServerConfiguration规则覆盖。

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
	public void configure(HttpSecurity http) throws Exception {
		// 授权码模式(authorization_code)配置
		// 授权码模式下,会用到/oauth/authorize(授权URL)、/login(登录页)、/oauth/confirm_access(用户授权确认),
		// 但由于/oauth/**相关的请求安全规则配置由系统默认生成,则无需再配置。
		//
		// @formatter:off
		//http.authorizeRequests().antMatchers("/login").permitAll().and().formLogin().permitAll();
		// @formatter:on

	}

}
```

### 基于源注释的访问规则

修改ResourceServerConfiguration类加入@EnableGlobalMethodSecurity源注释，并且定义一个开放的访问规则，而具体业务规则在每个业务的Controller方法上控制，这样可以方便开发人员来控制自己开发功能的访问规则。

#### ResourceServerConfiguration

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
        // 这里定义一个开放的访问规则,具体的业务访问规则在相关的Controller是通过@PreAuthorize定义
		http.authorizeRequests().anyRequest().authenticated().and().csrf().disable();
	}

}
```

例如：获取当前登录用户信息；访问规则限制必须是**已认证**。

```java
@RestController
public class UserController {
	/**
	 * 根据请求头Authorization的值来获取UserDetails信息
	 * 例如：Authorization=Bearer c53ff76b-0e9d-4dc1-9ebf-3d8acc89506f
	 * @param user
	 * @return
	 */
	@PreAuthorize("isAuthenticated()")
	@RequestMapping(value = { "/auth/user" }, produces = "application/json")
	public Map<String, Object> user(OAuth2Authentication user) {
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
}
```

#### 规则动态函数

##### 已认证

@PreAuthorize("isAuthenticated()")

##### 有xxx权限

@PreAuthorize("hasAuthority('xxx')")

##### 有xxx角色

@PreAuthorize("hasRole('xxx')")

## oauth2提供的服务

### /oauth/token



### /auth/user



## 好文章

http://www.ruanyifeng.com/blog/2019/04/oauth-grant-types.html





## oauth2后台管理

对表数据进行管理，对Redis进行管理。

功能：

客户端管理：增加客户端、修改客户端、删除客户端、授权。

用户管理：增加用户、修改用户、删除用户、授权。只有密码模式和code模式有用。

权限管理：增加权限、修改权限、删除权限。

