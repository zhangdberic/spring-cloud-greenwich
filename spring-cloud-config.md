# spring cloud config

## 安装和配置

### pom.xml

```xml
	<!-- 相关依赖包 -->
	<dependencies>
		<!-- spring cloud config server -->
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-config-server</artifactId>
		</dependency>
		<!-- spring cloud bus -->
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-starter-bus-amqp</artifactId>
		</dependency>		
		<!-- spring boot security  -->
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>	
		<!-- spring boot actuator -->
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-actuator</artifactId>
		</dependency>			
	</dependencies>
```

spring-cloud-config-server：config server核心包。

spring-cloud-starter-bus-amqp：基于rabbitmq实现的属性刷新，服务器端publish，客户端listener，有刷新改变则publish消息。

spring-boot-starter-security：实现config server访问的安全认证，使用用户名和密码才能访问配置服务器。

spring-boot-starter-actuator：spring boot actuator，实现属性刷新。

如果你不需要考虑安全，不需要使用属性刷新，则只需要spring-cloud-config-server包就可以提供config server服务。

### yaml

#### bootstramp.yml

```yaml
spring:
  profiles:
     # 默认设置为开发环境
    active: dev
  application:
    name: dy-config # 应用名称
```

#### application.yml

```yaml
# 默认的配置文件
server:
  port: 9000
  # tomcat 字符集
  tomcat: 
    uri-encoding: UTF-8   
  # tomcat 字符集设置
spring:        
  http: 
    encoding: 
      charset: UTF-8
      enabled: true
      force: true
```

#### application-dev.yml

```yaml
# 开发环境配置 
encrypt:
  key: 12345678 # 配置文件加密秘钥
spring:
  # 开启安全认证
  security:
    user:
      name: dy-config
      password: 12345678
  cloud:
    config:
      server:
        git:
          # Spring Cloud Config配置中心使用gitlab的话，要在仓库后面加后缀.git，而GitHub不需要
          uri: http://39.105.202.xxx:pppp/zhangdb/config-repo.git
          # 搜索属性文件路径,可以是正则表达式,默认只搜索根目录下的文件,配置为/**搜索所有子目录下的文件
          search-paths: /**
          # 因为github的账户和密码不能泄露,因此需要在启动脚本中加入--spring.cloud.config.server.git.username=xxxx --spring.cloud.config.server.git.password=xxxx 
          username: uuuuu
          password: xxxxxxx
        encrypt:
          enabled: false # 直接返回密文，而并非解密后的原文(需要客户端解密)
  # 属性刷新使用队列          
  rabbitmq:
    host: 192.168.5.76
    port: 5672
    username: zhangdb
    password: 12345678    
```

### @EnableConfigServer

在main方法加入@EnableConfigServer源注释，用于加载config server相关的spring bean。

```java
@SpringBootApplication
@EnableConfigServer
public class ConfigServerApplication {
	
	public static void main(String[] args) {
		SpringApplication.run(ConfigServerApplication.class, args);
	}

}
```

## gitlab创建属性文件

### 创建属性文件

config-repo仓库

​	dy-eureka(目录)

​		dy-eureka.yml(文件)

​		dy-eureka-dev.yml(文件)

这里使用dy-eureka为例，一般在config-repo仓库下创建dy-eureka目录，然后在下面按照文件名规则创建：

dy-eureka.yml（公共属性文件）、dy-eureka-dev.yml（开发环境属性文件）、dy-eureka-test.yml（测试环境属性文件）；

### 合并属性和覆盖

当你通过config server访问dy-eureka-dev.yml文件（例如：http://192.168.5.76:9000/dy-eureka-dev.yml），config server会自动会先读取dy-eureka.yml（公共属性文件），然后再读取dy-eureka-dev.yml（开发环境属性文件），然后把两个属性文件内容合并返回给请求调用者，如果两个文件有重复的属性，则使用dev文件属性覆盖公共属性。

### 变量

yaml文件内任何一个属性都可以作为变量，都可以使用${xxx}使用变量，你也可以专门定义某个属性为变量，例如：

```yaml
server:
  port: 8761
check:
  url: http://localhost:${server.port}
```

### 例子：dy-eurkeka

#### dy-eureka.yml(公共属性)

```yaml
server:
  port: 8761
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
```

#### dy-eureka-dev.yml(开发环境属性)

```yaml
# 开发环境配置 
spring:
  # 开启安全认证       
  security:
    user:
      name: dy-eureka
      password: 12345678
  # 和spring-cloud-starter-bus-amqp配合,用于属性刷新
  rabbitmq:
    host: 192.168.5.76
    port: 5672
    username: zhangdb
    password: 12345678
eureka:
  server:
    # 关闭自我保护模式
    enable-self-preservation: false
  instance: 
    hostname: 192.168.5.76
  client:
    # 开发环境关闭获取注册信息
    fetch-registry: false
    # 开发环境不注册到自己
    register-with-eureka: false
    service-url:
      # eureka注册中心位置
      defaultZone: http://${spring.security.user.name}:${spring.security.user.password}@${eureka.instance.hostname}:${server.port}/eureka/
```

#### 请求返回内容

请求URL：http://192.168.5.76:9000/dy-eureka-dev.yml

```yaml
eureka:
  client:
    fetch-registry: false
    register-with-eureka: false
    service-url:
      defaultZone: http://dy-eureka:12345678@192.168.5.76:8761/eureka/
  instance:
    hostname: 192.168.5.76
  server:
    enable-self-preservation: false
server:
  port: 8761
  tomcat:
    uri-encoding: UTF-8
spring:
  cloud:
    config:
      overrideSystemProperties: false
  http:
    encoding:
      charset: UTF-8
      enabled: true
      force: true
  rabbitmq:
    host: 192.168.5.76
    password: 12345678
    port: 5672
    username: zhangdb
  security:
    user:
      name: dy-eureka
      password: 12345678
```

