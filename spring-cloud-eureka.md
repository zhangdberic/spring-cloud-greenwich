# spring cloud eureka

## 服务器端(安装和配置)

### pom.xml

```xml
		<!-- spring cloud eureka server -->
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-starter-netflix-eureka-server</artifactId>
		</dependency>
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
		<!-- spring boot actuator -->
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-actuator</artifactId>
		</dependency>
		<!-- spring boot security -->
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
```

spring-cloud-starter-netflix-eureka-server：eureka server的核心依赖包。

spring-cloud-starter-config：提供了基于config server的eureka配置，eureka配置都放在gitlab上由config server来统一管理。

spring-cloud-starter-bus-amqp：支持属性刷新。

spring-boot-starter-actuator：提供了spring boot acturator支持。

spring-boot-starter-security：eureka server的认证访问，基于用户名和密码访问eureka sever。

这里只有spring-cloud-starter-netflix-eureka-server是必须的依赖包，其它根据情况添加。

### yaml

#### bootstrap.yml

/src/main/resources目录下创建bootstrap.yml文件，内容如下：

```yaml
spring:
  application:
    name: dy-eureka
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
# 测试环境
---
spring:
  profiles: test
  cloud:
    config:
      uri: http://192.168.5.76:9000
      profile: ${spring.profiles}  # 指定从config server配置的git上拉取的文件(例如:dy-eureka-test.yml)
      username: dy-config   # config server的basic认证的user
      password: 12345678 # config server的basic认证的password      
# 学习环境
---
spring:
  profiles: study
  cloud:
    config:
      uri: http://10.60.33.xx:9000
      profile: ${spring.profiles}  # 指定从config server配置的git上拉取的文件(例如:dy-eureka-study.yml)
      username: dy-config   # config server的basic认证的user
      password: xxxxxx # config server的basic认证的password
# 生产环境(eureka1)
---
spring:
  profiles: proc_eureka1
  cloud:
    config:
      uri: http://10.60.32.xxx:9000
      profile: ${spring.profiles}  # 指定从config server配置的git上拉取的文件(例如:dy-eureka-proc_eureka1.yml)
      username: dy-config   # config server的basic认证的user
      password: xxxxxx # config server的basic认证的password 
# 生产环境(eureka2)
---
spring:
  profiles: proc_eureka2
  cloud:
    config:
      uri: http://10.60.32.xxx:9000
      profile: ${spring.profiles}  # 指定从config server配置的git上拉取的文件(例如:dy-eureka-proc_eureka2.yml)
      username: dy-config   # config server的basic认证的user
      password: xxxxxx # config server的basic认证的password                            
```

这里配置了5个环境，每个环境属性都设置了当前的profile和连接git配置。

#### dy-eureka.yml

gitlab上config-repo/dy-eureka/dy-eureka.yml，**公共的eureka属性**，内容如下：

```yml
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

#### dy-eureka-dev.yml

gitlab上config-repo/dy-eureka/dy-eureka-dev.yml，**开发环境eureka属性，因为是开发环境配置了单机eureka，其无需获取eureka内的服务注册信息，也无需注册到eureka上**，内容如下：

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
    # eureka的主机名(单机模式配置localhost)  
    hostname: localhost
  client:
    # 开发环境关闭获取注册信息
    fetch-registry: false
    # 开发环境不注册到自己
    register-with-eureka: false
    service-url:
      # eureka注册中心位置
      defaultZone: http://${spring.security.user.name}:${spring.security.user.password}@${eureka.instance.hostname}:${server.port}/eureka/
```

#### dy-eureka-test.yml

gitlab上config-repo/dy-eureka/dy-eureka-test.yml，**测试环境eureka属性，因为是测试环境配置了单机eureka，其无需获取eureka内的服务注册信息，也无需注册到eureka上**，内容如下：

```yaml
# 测试环境配置 
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
    # eureka的主机名(单机模式配置localhost)  
    hostname: localhost
  client:
    # 开发环境关闭获取注册信息
    fetch-registry: false
    # 开发环境不注册到自己
    register-with-eureka: false
    service-url:
      # eureka注册中心位置
      defaultZone: http://${spring.security.user.name}:${spring.security.user.password}@${eureka.instance.hostname}:${server.port}/eureka/

```

#### dy-eureka-study.yml

gitlab上config-repo/dy-eureka/dy-eureka-study.yml，**学习环境eureka属性，因为是学习环境配置了单机eureka，其无需获取eureka内的服务注册信息，也无需注册到eureka上**，内容如下：

```yaml
# 学习环境配置 
spring:
  # 开启安全认证       
  security:
    user:
      name: dy-eureka
      password: 12345678
  # 和spring-cloud-starter-bus-amqp配合,用于属性刷新
  rabbitmq:
    host: 10.60.33.xx
    port: 5672
    username: zhangdb
    password: 12345678
eureka:
  server:
    # 关闭自我保护模式
    enable-self-preservation: false
  instance: 
    # eureka的主机名(单机模式配置localhost)  
    hostname: localhost
  client:
    # 开发环境关闭获取注册信息
    fetch-registry: false
    # 开发环境不注册到自己
    register-with-eureka: false
    service-url:
      # eureka注册中心位置
      defaultZone: http://${spring.security.user.name}:${spring.security.user.password}@${eureka.instance.hostname}:${server.port}/eureka/

```

#### dy-eureka-proc_eureka1.yml

gitlab上config-repo/dy-eureka/dy-eureka-proc_eureka1.yml，内容如下：

两台eureka服务器相互注册，并且每隔30秒相互抓取(获取)对方的服务注册信息，来实现eureka集群。

eureka1注册本身的eureka服务到eureka2服务器上，并且每隔30秒(默认)获取eureka2上的服务注册信息。

eureka2注册本身的eureka服务到eureka1服务器上，并且每隔30秒(默认)获取eureka1上的服务注册信息。

```yaml
# 生成环境配置(eureka1)
spring:
  # 开启安全认证       
  security:
    user:
      name: dy-eureka
      password: xxxxxx
  # 和spring-cloud-starter-bus-amqp配合,用于属性刷新
  rabbitmq:
    host: 10.60.32.198
    port: 5672
    username: zhangdb
    password: xxxxxx
eureka:
  instance: 
    # eureka的主机名(配置为本机ip地址)
    hostname: 10.60.32.xx1
  client:
    service-url:
      # eureka注册中心位置(集群环境下为另一台eureka服务器,理解为注册本机eureka到另一台eureka服务器,并且每隔30秒获取另一台eureka服务器上的服务注册信息)
      defaultZone: http://${spring.security.user.name}:${spring.security.user.password}@10.60.32.xx2:${server.port}/eureka/

```

#### dy-eureka-proc_eureka2.yml

```yaml
# 生产环境配置(eureka2)
spring:
  # 开启安全认证       
  security:
    user:
      name: dy-eureka
      password: xxxxxx
  # 和spring-cloud-starter-bus-amqp配合,用于属性刷新
  rabbitmq:
    host: 10.60.32.198
    port: 5672
    username: zhangdb
    password: xxxxxx
eureka:
  instance: 
    # eureka的主机名(配置为本机ip地址)
    hostname: 10.60.32.xx2
  client:
    service-url:
      # eureka注册中心位置(集群环境下为另一台eureka服务器,理解为注册本机eureka到另一台eureka服务器,并且每隔30秒获取另一台eureka服务器上的服务注册信息)
      defaultZone: http://${spring.security.user.name}:${spring.security.user.password}@10.60.32.xx1:${server.port}/eureka/
```

### @EnableEurekaServer

```java
@SpringBootApplication
@EnableEurekaServer
public class EurekaServerApplication {
	
	public static void main(String[] args) {
		SpringApplication.run(EurekaServerApplication.class, args);
	}
	
    @EnableWebSecurity
    class WebSecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity httpSecurity) throws Exception {
            // Spring Security 默认开启了所有 CSRF 攻击防御，需要禁用 /eureka 的防御
            httpSecurity.csrf().ignoringAntMatchers("/eureka/**");
            super.configure(httpSecurity);
        }
    }

}
```

