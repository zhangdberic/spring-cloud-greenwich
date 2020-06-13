spring cloud network

## inetutils

Spring Cloud所有组件的本机网络信息都是使用org.springframework.cloud.commons.util.InetUtil来获取。

spring-cloud-commons项目为Spring Cloud生态提供了顶层的抽象和基础设施的实现。
网络这基础设施也是在这里有对应的实现：InetUtils、InetUtilsProperties和UtilAutoConfiguration提供了网络配置相关的功能。

spring-cloud获取本机主机名、网卡信息都是使用InetUtil类完完成的，例如：eureka客户端获取本机hostname和ip，然后注册到eureka服务器。

```
spring.cloud.inetutils.default-hostname
spring.cloud.inetutils.default-ip-address
spring.cloud.inetutils.ignored-interfaces
spring.cloud.inetutils.preferred-networks
spring.cloud.inetutils.timeout-seconds
spring.cloud.inetutils.use-only-site-local-interfaces
```

default-hostname：设置默认的hostname，在程序无法获取到本机hostname的时候使用；

default-ip-address：设置默认的ip，在程序无法获取到本机ip的时候使用；

ignored-interfaces：忽律的网络接口名，例如：忽律虚拟网卡docker*，支持正则表达式；

preferred-networks：有效的ip，你也可以设置为有效的ip段前置，例如：192.168；

timeout-seconds：获取主机名的超时时间，当前你获取主机名的时候，有可能触发DNS查找，这个非常耗时；

use-only-site-local-interfaces：有效获取内网的ip；



preferred-networks非常有用，例如：你的服务器配置了两个段的ip地址，10.60.9.x和192.168.5.x，你只希望使用192.168的ip作为服务注册的ip，这时你可以在**bootstrap.xml文件设置**：

```
spring.cloud.inetutils.preferred-networks=192.168
```



## spring.cloud.client.*

spring cloud相关组件在启动的时候，会自动获取当前主机的主机名(hostname)和ip地址(ip-address)，存放到环境变量中，你可以在配置文件中通过${spring.cloud.client.*}使用。

**注册环境变量程序(HostInfoEnvironmentPostProcessor)：**

```java
	@Override
	public void postProcessEnvironment(ConfigurableEnvironment environment,
			SpringApplication application) {
		InetUtils.HostInfo hostInfo = getFirstNonLoopbackHostInfo(environment);
		LinkedHashMap<String, Object> map = new LinkedHashMap<>();
		map.put("spring.cloud.client.hostname", hostInfo.getHostname());
		map.put("spring.cloud.client.ip-address", hostInfo.getIpAddress());
		MapPropertySource propertySource = new MapPropertySource(
				"springCloudClientHostInfo", map);
		environment.getPropertySources().addLast(propertySource);
	}
```

**配置文件中使用spring.cloud.client.ip-address属性**

```yaml
# eureka 客户端
eureka:
  instance: 
    prefer-ip-address: true
    instance-id: ${spring.cloud.client.ip-address}:${spring.application.name}:${server.port}
```

**spring.cloud.client.ip-address和spring.cloud.inetutils.preferred-networks配合使用**

需要在bootstrap.xml中，设置spring.cloud.inetutils.preferred-network，否则spring.cloud.client.ip-address无法达到预期效果。https://blog.csdn.net/xichenguan/article/details/76632033

bootstrap.xml

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
      uri: http://192.168.5.76:9000
      profile: ${spring.profiles}  # 指定从config server配置的git上拉取的文件(例如:dy-eureka-dev.yml)
      username: dy-config   # config server的basic认证的user
      password: 12345678 # config server的basic认证的password
    inetutils:
      # 指定获取ip地址的查询范围(可以是ip段)
      preferred-networks: 192.168 
```

