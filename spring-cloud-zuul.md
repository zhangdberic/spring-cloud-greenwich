# spring cloud zuul

微服务网关：介于客户端和服务器端之间的中间层，所有的外部请求都会先经过微服务网关。微服务网关经过过滤器和路由查询，转发请求到对应的服务器。

默认请求下zuul服务器，使用ribbon来定位eureka server中的微服务；同时，还整合了hystrix实现容错，所有经过zuul的请求都会在Hystrix命令中执行。

注意：尽管zuul起到了服务网关的作用，但还是强烈建议在生产环境中**zuul一定要前置nginx**。

## 1. zuul服务器配置

### 1.1 pom.xml

```xml
		<!-- spring cloud zuul -->
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-starter-netflix-zuul</artifactId>
		</dependency>
```

### 1.2 application.yml

```yaml
# 配置zuul->ribbon->使用APACHE HTTP Client
ribbon: 
  restclient:  
    enabled: true
# 配置zuul
zuul: 
  ignored-services: '*' 
  routes: 
    sc-sampleservice: /sampleservice/** 
```

配置zuul转发请求使用Apache HttpClient。

配置zuul忽略所有eureka上获取的服务，并指定某些服务对外开放。

这样是做的好处：

1. 解决安全问题，不能所有在eureka上的服务都暴露出去。

2. 通过routes配置可以指定服务的请求路径前缀和服务ID之间的映射(类似于DNS)，这样即使服务ID修改了，对外提供的URL不变。

3. 动态刷新路由配置(routes)，通过测试可以做到，git修改配置后，/bus刷新马上生效，无须重新启动zuul。

   ```
   curl -u dy-config:12345678 -X POST http://192.168.5.54:9000/actuator/bus-refresh/sgw:** 
   ```

   

### 1.3 ZuulApplication.java

```java
@SpringBootApplication
@EnableZuulProxy
public class ZuulApplication {

	public static void main(String[] args) {
		SpringApplication.run(ZuulApplication.class, args);
	}

}
```

### 1.4 验证zuul启动是否成功

浏览器请求：http://zuul-ip:actuator-port/actuator/routes，查看返回的服务路由信息。

```
http://192.168.5.54:27070/actuator/routes
```

查看路由详细信息：http://zuul-ip:actuator-port/actuator/routes/details

```
http://192.168.5.54:27070/actuator/routes/details
```

查看应用的过滤器信息：http://zuul-ip:actuator-port/actuator/filters

```
http://192.168.5.54:27070/actuator/filters
```



## 2. zuul配置

### 2.1 配置使用路由前缀

```yaml
# 配置zuul
zuul: 
  # 忽略所有的服务
  ignored-services: '*' 
  # 指定请求前缀
  prefix: /api
  # 转发请求到服务时,是否去掉prefix前缀字符
  strip-prefix: true
  # 开放服务
  routes: 
    sc-sampleservice: /sampleservice/** 
```

关注：zuul.prefix=/api 和 zuul.strip-prefix=true 两处配置。

测试：http://192.168.5.31:8090/api/sampleservice/1，请求前缀加入了/api。

这样做还有一个好处，就是可以在zuul的前端加入nginx，nginx把所有的/api请求转发到zuul上。

**注意：zuul.routes的配置，支持/actuator/bus-refresh在线属性配置。**

### 2.2 敏感的Header设置

zuul.sensitive-headers属性设置哪些请求头不能被传递到服务，默认：Cookie,Set-Cookie,Authorization，请求头不能被传递到服务。

你可以通过设置：zuul.sensitive-headers=空，来允许这三个请求头传递到服务。例如：前后端分离开发经常要使用cookie来存放token，你需要显示的从zuul.sensitive-headers中去掉Cookie，否则后台服务无法获取到这个使用cookie为载体的token值。

```yaml
# 配置zuul
zuul: 
  # 忽略所有的服务
  ignored-services: '*' 
  # 指定请求前缀
  prefix: /api
  # 转发请求到服务时,是否去掉prefix前缀字符
  strip-prefix: true
  # 配置路由
  routes: 
  	# 配置sc-sampleservice服务路由
    sc-sampleservice: 
      path: /sampleservice/** 
      sensitive-headers: 
```

你也可以通过设置，zuul.ignoredHeaders来禁止那些请求头传递到服务，查看zuul代码，zuul.sensitive-headers的请求头会被存放到zuul.ignoredHeaders。

以上的配置支持/actuator/bus-refresh动态刷新配置。

### 2.3 Zuul上传文件

对于小于1M上传，无须任何任何处理，可以正常上传。大于1M，则需要特殊设置，配置允许最大请求字节数和单个上传的字节数。不支持/bus动态刷新配置。

```yaml
spring:   
  http:   
    multipart: 
      # 整个请求大小限制(1个请求可能包括多个上传文件)
      max-request-size: 20MB
      # 单个文件大小限制
      max-file-size: 10MB   
```

测试：postman发送post请求，http://192.168.5.31:8090/api/sampleservice/uploadFile

注意：mulitpart的设置，在zuul和upload服务都要设置。

如果是在互联网上传文件，则要考虑到网络带宽和延时等问题，因此要加大超时时间，例如：

```yaml
hystrix:
  command:
    default:
      execution:
        isolation:
          thread:
            timeoutInMilliseconds: 10000

ribbon:
  ReadTimeout: 10000
  ConnectTimeout: 2000
```

同上面mulitpart的设置，zuul和upload服务都要设置这个超时时间。

**考虑到上面的配置为了上传，加大了请求大小字节数和超时时间，这在上传操作很有用，但如果是普通的服务调用，则会有安全问题，因此强烈建议为upload单独设置一个zuul服务器，只有这台zuul服务器才需要调大这些配置。**例如：/api/dfss/upload的请求，nginx会根据url来转发到这台占用于上传处理的zuul上。

### 2.4 zuul过滤器

Zuul大部分功能都是通过过滤器来实现的。Zuul中定义了4中标准过滤器类型，这些过滤器类型对应请求的典型生命周期。

PRE（预处理）：这种过滤器在请求被路由之前调用。可利用这种过滤器实现身份认证、获取请求的微服务、记录调试等。

ROUTE（路由）：这种过滤器将请求路由到微服务，用于构建发送给微服务的请求。

ERROR（错误处理）：发生错误时执行本过滤器。

POST（后处理）：这种过滤器在路由到微服务以后执行，用于为响应添加Http Header、收集统计信息、将响应发送给客户端等。

STATIC：不常用，直接在Zuul中生成响应，不将请求转发到后端微服务。

zuul过滤器执行顺序与抛出异常处理顺序，如下：**ZuulServlet代码**

正常执行(我异常抛出)情况：preRoute->route->postRoute。

异常执行，参见“2.4.6 异常处理”。



```java
@Override
    public void service(javax.servlet.ServletRequest servletRequest, javax.servlet.ServletResponse servletResponse) throws ServletException, IOException {
        try {
            init((HttpServletRequest) servletRequest, (HttpServletResponse) servletResponse);

            // Marks this request as having passed through the "Zuul engine", as opposed to servlets
            // explicitly bound in web.xml, for which requests will not have the same data attached
            RequestContext context = RequestContext.getCurrentContext();
            context.setZuulEngineRan();

            try {
                preRoute(); 
            } catch (ZuulException e) {
                error(e); 
                postRoute();
                return;
            }
            try {
                route();
            } catch (ZuulException e) {
                error(e);
                postRoute();
                return;
            }
            try {
                postRoute();
            } catch (ZuulException e) {
                error(e);
                return;
            }

        } catch (Throwable e) {
            error(new ZuulException(e, 500, "UNHANDLED_EXCEPTION_" + e.getClass().getName()));
        } finally {
            RequestContext.getCurrentContext().unset();
        }
    }
```



#### 2.4.1 内置过滤器

Zuul内置了一些过滤器，随zuul启动。

**@EnableZuulServer所启动的过滤器**

PRE 类型过滤器：

ServletDetectionFilter：检查请求是否通过了Spring Dispatcher。

FormBodyWrapperFilter：解析表单数据，并为请求重新编码。目前效率低，如果基于json传递请求体，则可禁止该过滤器。

DebugFilter：调试过滤器，当设置zuul.debug.request=true，并且请求加上debug=true参数，就会开启调试过滤器。

ROUTE 类型过滤器：

SendForwardFilter：使用Servlet RequestDispathcer转发请求(内部转发)，转发位置存在在RequestContext的属性FilterConstant.FORWARD_TO_KEY中。用于zuul自身转发(forward)。

```yaml
zuul:
  routes:
    path: /path-a/**
    url: forward:/path-b
```

POST 类型过滤器：

SendResponseFilter：把调用微服务(service)的响应结果(响应头和响应体)，转发给最终用户（写入到最终用户响应内容）。起到代理转发作用。

ERROR 类型过滤器：

SendErrorFilter：若RequestContext.getThrowable()结果不为null，则默认转发到/error，也可以使用error.path属性来修改。

**@EnableZuulProxy所启动过滤器**

@EnableZuulProxy启动的过滤包含上面@EnableZuulServer启动的过滤器，还包括：

PRE 类型过滤器：

PreDecorationFilter：根据RouteLocator对象确定要路由到的地址(微服务位置)，以及怎样去路由。

查看sc-zuul-swagger-test项目的DocumentationConfig类，了解RouteLocator对象如果被使用。

ROUTE 类型过滤器：

RibbonRouteFilter：使用Ribbon、Hystrix、HTTP客户端发送请求。请求的servletId对应RequestContext的属性FilterConstants.SERVICE_ID_KEY。

SimpleHostRoutingFilter：如果路由配置直接指定了服务的url，而不能从eureka中获取位置，则使用这个过滤器。

**禁止某个过滤器**

zuul.<SimpleClassName>.<filterType>.disable=true

例如：zuul.FormBodyWrapperFilter.pre.disable=true

#### 2.4.2 自定义过滤器

因为声明了@Component定义为SpringBean，zuul会自动识别并应用这个过滤器。

```java
@Component
public class PreRequestLogFilter extends ZuulFilter {
	/** 日志 */
	private final Logger logger = LoggerFactory.getLogger(PreRequestLogFilter.class);

	@Override
	public boolean shouldFilter() {
		return true;
	}

	@Override
	public Object run() throws ZuulException {
		RequestContext ctx = RequestContext.getCurrentContext();
		HttpServletRequest request = ctx.getRequest();
		logger.info("send [{}] request to [{}].", request.getMethod(), request.getRequestURL().toString());
		return null;
	}

	@Override
	public String filterType() {
		return FilterConstants.PRE_TYPE;
	}

	@Override
	public int filterOrder() {
		return FilterConstants.PRE_DECORATION_FILTER_ORDER - 1;
	}

}
```

#### 2.4.3 伟大的RequestContext

```java
RequestContext requestContext = RequestContext.getCurrentContext();
```

zuul过滤器中最关键的技术就是RequestContext，其是一个上下文对象，包含zuul使用的几乎所有技术。下面说几个重点的：

1.其继承了ConcurrentHashMap对象，实现了Map所有的接口。

2.基于线程变量ThreadLocal来存储当前实例。

3.request和response都被存放到当前的map中，因此你可以在代码的任何位置来操作request和response。

4.setThrowable(Throwable th)代表zuul执行的过程中出现了异常，如果你的ZuulFilter在执行的过程中抛出了异常，zuul会自动调用这个方法添加异常对象到上下文中，你可以手工赋值（表示出现了异常）。你可以编写一个ErrorFilter来处理异常，这需要使用getThrowable()的方法来获取异常，如果异常处理完了，则一定要调用remove("throwable")来删除这个异常，表示已经没有异常了，否则异常会被传递下去。

5.任何响应的输出，不要直接使用response提供的方法来操作（RequestContext.currentContext().getResponse().xxx())，应该使用RequestContext提供的方法来设置response相关数据，例如：添加响应头RequestContext.currentContext().addZuulRequestHeader("code","ok");你调用任何RequestContext上的操作response的相关方法，SendResponseFilter过滤器(zuul原生)都会帮你输出。例如：setResponseBody(String)、setResponseDataStream(InputStream)、addZuulResponseHeader(String, String)、setOriginContentLength(Long)等。

6.setRouteHost(new URL("http:/xxx"))，设置路由(转发)到的主机，这个类似于nginx的proxyPass ip地址，请求会被zuul转发到这个地址。

7.SERVICE_ID_KEY，设置请求的服务编码，例如：RequestContext.getCurrentContext().put(FilterConstants.SERVICE_ID_KEY, "myservices");，这里的服务可以是eureka上的服务、也可以是配置文件zuul.route声明的手工服务等，你可以通过编程的方式来改变请求的服务。例如：上面的代码手工指定服务，

```yaml
zuul:
  routes:
    tgms-service:
      path: /services
      serviceId: myservices
myservices:
  ribbon:
    NIWSServerListClassName: com.netflix.loadbalancer.ConfigurationBasedServerList
    listOfServers: 121.42.175.3:80,121.42.175.4:81       
```

8.REQUEST_URI_KEY，改变转发请求的uri，例如：RequestContext.getCurrentContext().put(FilterConstants.REQUEST_URI_KEY,"/tgms-services")，例如：你浏览器的请求地址为http://localhost:5000/services，则经过本代码转发到upstream的请求url已经是/tgms-services，不再是/services了。

#### 2.4.4 FilterConstants

zuul的关键字和内置过滤器执行顺序都在这个常量类中定义。看这个常量，你能有收获。

#### 2.4.5 ZuulFilter.filterOrder()

```java
	@Override
	public String filterType() {
		return FilterConstants.PRE_TYPE;
	}
    @Override
	public int filterOrder() {
		return 1;
	}
```

zuul根据这个值来决定过滤器执行的先后顺序，同一种filterType类型的两个ZuulFilter的filterOrder()不能相同，但不同种类filterType的filterOrder()可以相同，因为zuul是逐个类型(filterType)执行的，PRE->ROUTE->POST。

技巧：因为PRE类型，可用的filterOrder()不多，一般情况下应使用2、3、4，这个可以通过查看FilterConstants常量来理解。如果你需要定义4个PRE类型的过滤器，filterOrder不够用了，这里有个技巧，你可以把两个没有先后依赖关系的ZuulFilter都定义为同一个filterOrder()值，例如都定义为3。

#### 2.4.6 异常处理

下面是整个Zuul的入口Servlet处理方法，这个方法很简单，通过这个方法就看出这个异常处理的过程，发送异常后还是否继续执行。

com.netflix.zuul.http.ZuulServlet：

```java
   @Override
    public void service(javax.servlet.ServletRequest servletRequest, javax.servlet.ServletResponse servletResponse) throws ServletException, IOException {
        try {
            init((HttpServletRequest) servletRequest, (HttpServletResponse) servletResponse);

            // Marks this request as having passed through the "Zuul engine", as opposed to servlets
            // explicitly bound in web.xml, for which requests will not have the same data attached
            RequestContext context = RequestContext.getCurrentContext();
            context.setZuulEngineRan();

            try {
                preRoute(); 
            } catch (ZuulException e) {
                error(e); 
                postRoute();
                return;
            }
            try {
                route();
            } catch (ZuulException e) {
                error(e);
                postRoute();
                return;
            }
            try {
                postRoute();
            } catch (ZuulException e) {
                error(e);
                return;
            }

        } catch (Throwable e) {
            error(new ZuulException(e, 500, "UNHANDLED_EXCEPTION_" + e.getClass().getName()));
        } finally {
            RequestContext.getCurrentContext().unset();
        }
    }
```

**ZuulException异常：**

PRE、ROUTE类型过滤器，抛出ZuulException异常时，中断程序，然后先由ERROR类型过滤器处理，然后再由POST类型过滤器处理(输出)。

POST类型过滤器，抛出ZuulException异常时，中断程序，然后只由ERROR类型的过滤器来处理。这个感觉有点乱了，最好不要在POST类型过滤器抛出ZuulException类型异常。

**Throwable异常：**

当抛出Throwable异常时(也就是非ZuulException)，中断程序，把Throwable异常包装为ZuulException，然后只由ERROR类型的过滤器来处理。

我进一步来观察com.netflix.zuul.FilterProcessor类的preRoute()、route()、postRoute()，会发现在抛出Throwable异常的时候，都进行了ZuulException包装，也就是说，正常情况下ZuulServlet的error(new ZuulException(e, 500, "UNHANDLED_EXCEPTION_" + e.getClass().getName()));是**不可能执行到**的，写这行代码的目的就是为了保护性编程。

```java
   /**
     * runs "post" filters which are called after "route" filters. ZuulExceptions from ZuulFilters are thrown.
     * Any other Throwables are caught and a ZuulException is thrown out with a 500 status code
     *
     * @throws ZuulException
     */
    public void postRoute() throws ZuulException {
        try {
            runFilters("post");
        } catch (ZuulException e) {
            throw e;
        } catch (Throwable e) {
            throw new ZuulException(e, 500, "UNCAUGHT_EXCEPTION_IN_POST_FILTER_" + e.getClass().getName());
        }
    }

    /**
     * runs all "error" filters. These are called only if an exception occurs. Exceptions from this are swallowed and logged so as not to bubble up.
     */
    public void error() {
        try {
            runFilters("error");
        } catch (Throwable e) {
            logger.error(e.getMessage(), e);
        }
    }

    /**
     * Runs all "route" filters. These filters route calls to an origin.
     *
     * @throws ZuulException if an exception occurs.
     */
    public void route() throws ZuulException {
        try {
            runFilters("route");
        } catch (ZuulException e) {
            throw e;
        } catch (Throwable e) {
            throw new ZuulException(e, 500, "UNCAUGHT_EXCEPTION_IN_ROUTE_FILTER_" + e.getClass().getName());
        }
    }

    /**
     * runs all "pre" filters. These filters are run before routing to the orgin.
     *
     * @throws ZuulException
     */
    public void preRoute() throws ZuulException {
        try {
            runFilters("pre");
        } catch (ZuulException e) {
            throw e;
        } catch (Throwable e) {
            throw new ZuulException(e, 500, "UNCAUGHT_EXCEPTION_IN_PRE_FILTER_" + e.getClass().getName());
        }
    }
```



##### PRE和ROUTE类型过滤器异常处理

PRE过滤器和ROUTE过滤器的run()方法使用如下try、catch策略保证抛出的异常一定是ZuulException异常：

```java
	@Override
	public Object run() throws ZuulException {
		try {
		...
		} catch (ServiceException sex) {
			ServiceZuulExceptionAdapter.throwZuulException(sex);
		} 
    }    
```

##### POST类型过滤器异常处理

POST类型过滤器的run()方法使用如下try、catch策略保证抛出异常写入到日志，并且不再抛出异常。如果两个POST过滤器之间有依赖关系，则要加入判断代码，看上一个POST过滤器是否执行成功。

```java
	@Override
	public Object run() throws ZuulException {
		try {
		...
		} catch (Throwable tx) {
            logger.error("cause message",tx);
		}
    } 
```

##### ERROR类型过滤器异常处理

1.使用RequestContext.getThrowable()来获取异常

2.响应输出不应该直接使用RequestContext.getResponse()来获取HttpServletResponse来输出响应信息，应该使用	RequestContext.addZuulResponseHeader(name,value)、RequestContext.setResponseDataStream(...)等方法来写响应信息到上下文，然后由zuul系统提供的SendResponseFilter来负责响应输出，不要使用原生的HttpServletResponse来输出。

3.ERROR过滤器只应关注PRE、ROUTE类型的过滤器抛出ZuulException异常如果处理，不用关心POST类型过滤器抛出异常（因为POST类型不应抛出异常，当前发生异常只写日志）。

```java
	@Override
	public Object run() throws ZuulException {
		Throwable ctxThrowable = RequestContext.getCurrentContext().getThrowable();
		// 从上下文的异常中获取ServiceException,如果获取不到则说明是系统级别异常
		ServiceException serviceException = this.getServiceExceptionFromCtxThrowable(ctxThrowable);
		if (serviceException == null) {
			serviceException = new SystemErrorException(ctxThrowable);
		}
		// 输出错误信息(json或xml)
		SgwContext.writeForSendResponseFilter(Integer.valueOf(serviceException.getStatusCode()),
				serviceException.getCode(), serviceException.toMessage(ServiceContext.getCurrentContext().getFormat()));
		// 记录日志
		if (serviceException instanceof SystemErrorException) {
			logger.error("system error.", serviceException);
		}
		// 从请求上下文件中删除Throwable属性,否则下一个ErrorFilter会被执行
		RequestContext.getCurrentContext().remove("throwable");
		// 错误信息写入到错误日志上下文
		ServiceContext.getCurrentContext().logErrorInfo(serviceException.toString());
		return null;
	}
```



#### 2.4.7 response输出

PRE和ROUTE过滤器、POST过滤器(在SendResponseFilter之前先执行POST过滤器)，不应使用RequestContext.getResponse()获取的HttpServletResponse直接输出内容，应该使用RequestContext内置的reponse操作方法，然后由SendResponseFilter来负责输出。

```java

	/**
	 * 输出服务信息适用于SendResponseFilter(按照服务输出协议)
	 * @param statusCode
	 * @param code
	 * @param responseBody
	 */
	public static void writeForSendResponseFilter(int statusCode, String code, byte[] responseBody) {
		RequestContext context = RequestContext.getCurrentContext();
		String format = ServiceContext.getCurrentContext().getFormat();
		// Content-Type
		String contentType = null;
		if (FormatType.XML.equals(format)) {
			contentType = "application/xml;charset=utf-8";
		} else {
			contentType = "application/json;charset=utf-8";
		}
		context.addZuulResponseHeader("Content-Type", contentType);
		// Content-Length
		long contentLength = 0;
		if (!ObjectUtils.isEmpty(responseBody)) {
			contentLength = responseBody.length;
		}
		context.setOriginContentLength(contentLength);
		// status
		context.setResponseStatusCode(statusCode);
		// code
		context.addZuulResponseHeader("code", code);
		// serialnum
		context.addZuulResponseHeader("serialnum", ServiceContext.getCurrentContext().getSerialnum());
		// body-type
		context.addZuulResponseHeader("body-type", contentType);
		// body-length
		context.addZuulResponseHeader("body-length", String.valueOf(contentLength));
		// body
		if (!ObjectUtils.isEmpty(responseBody)) {
			// 不压缩
			context.setResponseGZipped(false);
			context.setResponseDataStream(new ByteArrayInputStream(responseBody));
		}

	}

	public static void writeForSendResponseFilter(int statusCode, String code, String body) {
		writeForSendResponseFilter(statusCode, code, StringUtils.hasLength(body) ? body.getBytes() : null);
	}
```



### 2.4 Zuul容错和回退

#### 2.4.1 hystrix监控

http://zuul-ip:actuator-port/actuator/hystrix.stream（例如：http://192.168.5.54:27070/actuator/hystrix.stream），查看会查看到hystrix监控数据，也就是说默认情况下zuul的请求是收到zuul保护的，而且还能看出Thread Pools无相关数据，也证明了默认使用的hystrix隔离策略是SEMAPHORE。

#### 2.4.2 自定义回退类

因为声明了@Component定义为SpringBean，zuul会自动识别并应用这个回退提供者实现。

```java
@Component
public class MyFallbackProvider implements FallbackProvider {

	@Override
	public String getRoute() {
		// 表明为哪个微服务提供回退，* 表示所有微服务提供
		return "*";
	}

	@Override
	public ClientHttpResponse fallbackResponse(Throwable cause) {
		// 注意，只有hystrix异常才会好触发这个接口
		if (cause instanceof HystrixTimeoutException) {
			return response(HttpStatus.GATEWAY_TIMEOUT);
		} else {
			return this.fallbackResponse();
		}
	}

	@Override
	public ClientHttpResponse fallbackResponse() {
		return this.response(HttpStatus.INTERNAL_SERVER_ERROR);
	}

	private ClientHttpResponse response(final HttpStatus status) {
		return new ClientHttpResponse() {

			@Override
			public InputStream getBody() throws IOException {
				return new ByteArrayInputStream(("{\"code\":\""+ status.value()+"\",\"message\":\"服务不可用，请求稍后重试。\"}").getBytes());
			}

			@Override
			public HttpHeaders getHeaders() {
				HttpHeaders headers = new HttpHeaders();
				MediaType mt = new MediaType("application", "json", Charset.forName("UTF-8"));
				headers.setContentType(mt);
				return headers;
			}

			@Override
			public HttpStatus getStatusCode() throws IOException {
				return status;
			}

			@Override
			public int getRawStatusCode() throws IOException {
				return status.value();
			}

			@Override
			public String getStatusText() throws IOException {
				return status.getReasonPhrase();
			}

			@Override
			public void close() {
			}

		};
	}

}
```

测试验证：http://192.168.5.31:8090/api/sampleservice/1?sleep=2000，触发hystrix超时抛出，进而触发回退操作。



### 2.5 饥饿加载

zuul整合ribbon实现负载均衡，而ribbon默认是懒加载，可能会导致首次请求较慢。如果配置则修改为启动加载。

```yaml
zuul: 
  ribbon: 
    # 修改为启动加载(默认为懒加载)
    eager-load: 
      enabled: true
```

验证：启动时，查看log信息，会发现有DynamicServerListLoadBalancer字样。



### 2.6 QueryString 编码

如果要强制让query string与HttpServletRequest.getQueryString()保持一致，可使用如下配置：

```yaml
zuul: 
  # queryString保持一致
  forceOriginalQueryStringEncoding: true
```

注意：这个特殊的标志只适用于SimpleHostRoutingFilter，并且您失去了使用RequestContext.getCurrentContext(). setrequestqueryparams (someOverriddenParameters)轻松覆盖查询参数的能力，因为查询字符串现在直接从原始HttpServletRequest获取。



### ~~2.7 Hystrix隔离策略和线程池~~

#### 2.7.1 配置zuul使用thread隔离策略

默认情况下，Zuul的Hystrix隔离策略时**SEMAPHORE**。设置为THREAD适用于提供的服务不多但访问量很大的情况下，否则默认的SEMAPHORE更适合。

可以使用zuul.ribbon-isolation-strategy=thread修改为THREAD隔离策略，修改后HystrixThreadPoolKey默认为RibbonCommand，这意味着，所有的路由HystrixCommand都会在相同的Hystrix线程池上执行。

修改后可以通过hystrix的dashborad观察，可以看到ThreadPools栏有数据了。

新版的监控URL：http://192.168.5.54:27070/actuator/hystrix.stream

![](images/zuul-thread-pool-default.png)

也可以为每个服务(路由)，使用独立的线程池，并使用hystrix.threadpool.服务名，来定制线程池大写：

```yaml
zuul:
  ribbon-isolation-strategy: thread
  threadpool:
    useSeparateThreadPools: true  # 每个服务都有自己的线程池，而不是共享一个
    threadPoolKeyPrefix: zuulsgw # 指定线程池前缀，方便调试
    
hystrix: 
  threadpool: 
    # 设置默认情况下每个服务的线程池
    default:
      coreSize:1 # 核心线程数(默认10)，等同于ThreadPoolExecutor.corePoolSize参数
      maxinumSize: 100 # 最大值允许线程数，等同于ThreadPoolExecutor.maximumPoolSize
      maxQueueSize: -1 # 等待执行队列大小，等同于ThreadPoolExecutor.workQueue,-1为SynchronousQueue，大于零为new LinkedBlockingQueue(maxQueueSize)
      queueSizeRejectionThread: 20 # 队列允许排队的个数，超出这个阈值也被拒绝。maxQueueSize=-1没有意义
      keepAliveTimeMinutes: 1 # 线程保持(存活)的时间(分钟)，超出coreSize小于maxinumSize时，创建线程使用后存活时间，等同于等同于ThreadPoolExecutor.keepAliveTime
      allowMaximumSizeToDivergeFromCoreSize: true # 设置keepAliveTimeMinutes属性是起作用，默认为false
    # 特殊设置某个服务的线程池  
    sc-sampleservice: 
      coreSize: 2
      maxinumSize: 100
      maxQueueSize: -1
      keepAliveTimeMinutes: 2
      allowMaximumSizeToDivergeFromCoreSize: true
```

![](images/zuul-useSeparateThreadPools.png)

### 2.8 设置超时时间

在基于zuul+hystrix+ribbon组合情况下设置读取超时时间(ReadTimeout)相对复杂一些，其需要先预估一个服务调用允许的超时时间，然后根据这个预估的参考值来计算相关属性值。

~~默认配置如下（配置文件中无超时相关配置）：~~

```properties
ribbon.restclient.enabled=false
hystrix.command.<ServiceId>.execution.isolation.thread.timeoutInMilliseconds=4000
<ServiceId>.ribbon.ConnectTimeout=1000
<ServiceId>.ribbon.ReadTimeout=1000
```

设置全局的超时时间，要同时设置如下几个值：

```properties
ribbon.restclient.enabled=true
hystrix.command.default.execution.isolation.thread.timeoutInMilliseconds=xxxxx
ribbon.ConnectTimeout=xxxxx
ribbon.ReadTimeout=xxxxx
```

设置某个服务的超时时间，要同时设置如下几个值：

```properties
ribbon.restclient.enabled=true
hystrix.command.<ServiceId>.execution.isolation.thread.timeoutInMilliseconds=xxxxx
<ServiceId>.ribbon.ConnectTimeout=xxxxx
<ServiceId>.ribbon.ReadTimeout=xxxxx
```

#### 2.8.1 计算ribbonTimeout

**公式如下：**

```java
ribbonTimeout = (ribbonReadTimeout + ribbonConnectTimeout) * (maxAutoRetries + 1) * (maxAutoRetriesNextServer + 1);
```

**来源于：**org.springframework.cloud.netflix.zuul.filters.route.support.AbstractRibbonCommand.getRibbonTimeout()

例如：如下是你的配置；

```properties
ribbon.ConnectTimeout=1000
ribbon.ReadTimeout=10000
```

套用上面的公式计算（默认值：maxAutoRetries = 0，maxAutoRetriesNextServer = 1）：

(10000 + 1000) * (0 + 1) * (1 + 1) = 22000；

也就说，你配置的ReadTimeout为10000，而实际上系统计算出的ribbonTimeout为22000；因此应根据公式，反推算出一个ribbon.ReadTimeout；

计算ribbonTimeout的java代码：

```java
	protected static int getRibbonTimeout(IClientConfig config, String commandKey) {
		int ribbonTimeout;
		if (config == null) {
			ribbonTimeout = RibbonClientConfiguration.DEFAULT_READ_TIMEOUT + RibbonClientConfiguration.DEFAULT_CONNECT_TIMEOUT;
		} else {
			int ribbonReadTimeout = getTimeout(config, commandKey, "ReadTimeout",
				IClientConfigKey.Keys.ReadTimeout, RibbonClientConfiguration.DEFAULT_READ_TIMEOUT);
			int ribbonConnectTimeout = getTimeout(config, commandKey, "ConnectTimeout",
				IClientConfigKey.Keys.ConnectTimeout, RibbonClientConfiguration.DEFAULT_CONNECT_TIMEOUT);
			int maxAutoRetries = getTimeout(config, commandKey, "MaxAutoRetries",
				IClientConfigKey.Keys.MaxAutoRetries, DefaultClientConfigImpl.DEFAULT_MAX_AUTO_RETRIES);
			int maxAutoRetriesNextServer = getTimeout(config, commandKey, "MaxAutoRetriesNextServer",
				IClientConfigKey.Keys.MaxAutoRetriesNextServer, DefaultClientConfigImpl.DEFAULT_MAX_AUTO_RETRIES_NEXT_SERVER);
			ribbonTimeout = (ribbonReadTimeout + ribbonConnectTimeout) * (maxAutoRetries + 1) * (maxAutoRetriesNextServer + 1);
		}
		return ribbonTimeout;
	}
```

#### 2.8.2 计算hystrixTimeout

如果没有在配置文件中设置timeoutInMilliseconds，则使用ribbonTimeout作为hystrixTimeout，否则使用配置文件中的timeoutInMilliseconds作为hystrixTimeout。

**来源于：**

org.springframework.cloud.netflix.zuul.filters.route.support.AbstractRibbonCommand.getHystrixTimeout()

例如：如下是你的配置；

```yaml
hystrix:
  command:
    default:
      execution:
        isolation:
          thread:
            timeoutInMilliseconds: 22000
```

计算hystrixTimeout的java代码：

```java
	protected static int getHystrixTimeout(IClientConfig config, String commandKey) {
		int ribbonTimeout = getRibbonTimeout(config, commandKey);
		DynamicPropertyFactory dynamicPropertyFactory = DynamicPropertyFactory.getInstance();
		int defaultHystrixTimeout = dynamicPropertyFactory.getIntProperty("hystrix.command.default.execution.isolation.thread.timeoutInMilliseconds",
			0).get();
		int commandHystrixTimeout = dynamicPropertyFactory.getIntProperty("hystrix.command." + commandKey + ".execution.isolation.thread.timeoutInMilliseconds",
			0).get();
		int hystrixTimeout;
		if(commandHystrixTimeout > 0) {
			hystrixTimeout = commandHystrixTimeout;
		}
		else if(defaultHystrixTimeout > 0) {
			hystrixTimeout = defaultHystrixTimeout;
		} else {
			hystrixTimeout = ribbonTimeout;
		}
		if(hystrixTimeout < ribbonTimeout) {
			LOGGER.warn("The Hystrix timeout of " + hystrixTimeout + "ms for the command " + commandKey +
				" is set lower than the combination of the Ribbon read and connect timeout, " + ribbonTimeout + "ms.");
		}
		return hystrixTimeout;
	}
```

#### 2.8.3 ribbonTimeout和hystrixTimeout的关系

ribbonTImeout用于ribbon底层http client的socket的timeout，也就说用于网络的读取超时。

hystrixTimeout用于方法执行时间超时，理解为：future.get(hystrixTimeout)。

两者之间是在功能上是有区别。

例如：

ribbonTimeout超时报错：Caused by: java.net.SocketTimeoutException: Read timed out

hystrixTimeout超时报错：Caused by: com.netflix.hystrix.exception.HystrixRuntimeException: dfss-upload timed-out and no fallback available.

#### 2.8.4 ribbon和zuul.host超时(timeout)

ribbon.ConnectTimeout， ribbon.ReadTimeout这两个就是ribbon超时时间设置，当在yml写时，应该是没有提示的，给人的感觉好像是不是这么配的一样，其实不用管它，直接配上就生效了。
还有zuul.host.connect-timeout-millis， zuul.host.socket-timeout-millis这两个配置，这两个和上面的ribbon都是配超时的。区别在于，如果路由方式是serviceId的方式，那么ribbon的生效，如果是url的方式，则zuul.host开头的生效。（此处重要！使用serviceId路由和url路由是不一样的超时策略）。

zuul配置设置操作，ribbon的超时和zuul.host的超时都要设置

```yaml
zuul:
  host:
    max-per-route-connections: 200      
    max-total-connections: 500
    socket-timeout-millis: 60000
    connect-timeout-millis: 1000 

ribbon: 
  restclient:  
    enabled: true
  ReadTimeout: 60000
  ConnectTimeout: 1000
  MaxConnectionsPerHost: 200
  MaxTotalConnections: 500 
```





### 2.9 zuul使用ribbon重试

测试重试，后台开启两个sc-sampleservice的docker，使用zuul做为服务网关，接收请求，正常情况下是负载均衡分发，当停止一个sc-sampleservice的docker，再发送请求到zuul看能正常返回结果，并通过日志查看有重试操作。

默认情况：就已经开启了重试，重试的默认值：maxAutoRetries = 0，maxAutoRetriesNextServer = 1，测试通过。

maxAutoRetries 同一实例重试次数，默认为0。

maxAutoRetriesNextServer 重试其它实例的最大次数，如果有3个实例，应该设置2，默认值1。



### 2.10 设置信号量

在默认的SEMAPHORE隔离策略下，信号量可以控制服务允许的并发访问量。

```yaml
zuul: 
  # 设置默认最大信号量
  semaphore: 
    max-semaphores: 100 
  # 设置某个服务的最大信号量
  eureka: 
    sc-sampleservice: 
      semaphore:
        max-semaphores: 50 
```

### 2.11 tomcat参数设置

通过设置tomcat参数来调整zuul对外服务能力

```yaml
server:  
  tomcat: 
    max-connections: 1000
    max-threads: 200
    min-spare-threads: 10
    accept-count: 50
```

### 2.12 路由转发请求数限制

ribbon.xxxx和zuul.host.xxx两个都要设置，区别在于，如果路由方式是serviceId的方式，那么ribbon的生效，如果是url的方式，则zuul.host开头的生效，具体见下面的2.13和2.14介绍。

zuul.host.max-per-route-connections，用于在url转发方式下，每个host的同时转发连接数上限。

zuul.host.max-total-connections，用于在url转发方式下，所有host的同时转发连接数上限。

ribbon.MaxConnectionsPerHost，用于在serviceId转发方式下，每个host的同时转发连接数上限。

ribbon.MaxTotalConnections，用于在serviceId转发方式下，所有host的同时转发连接数上限。

```yaml
zuul:
  host:
    max-per-route-connections: 200      
    max-total-connections: 500

ribbon: 
  restclient:  
    enabled: true
  MaxConnectionsPerHost: 200
  MaxTotalConnections: 500 

```

### 2.13 ribbon属性配置

**如果路由方式是serviceId的方式，那么ribbon的生效**，例如：

1.基于eureka发现服务，自动转发不用人为干预。

2.RequestContext.getCurrentContext().set(FilterConstants.SERVICE_ID_KEY, serviceId);

ribbon可以配置的属性如下：

com.netflix.client.config.CommonClientConfigKey，查看这个类，类内的某个常量对应ribbon.xxxx配置，例如：

```java
public static final IClientConfigKey<Integer> MaxConnectionsPerHost = new CommonClientConfigKey<Integer>("MaxConnectionsPerHost"){};
```

对应：ribbon.MaxConnectionsPerHost的配置。

### 2.14 zuul.host属性配置

**如果使用url方式转发请求(非serviceId方式)，那么zuul.host属性配置生效**，例如：

RequestContext.getCurrentContext().setRouteHost(routeUrl);

zuul.host可配置的属性如下：

org.springframework.cloud.netflix.zuul.filters.ZuulProperties.Host，查看这个类，类内的某个属性对应zuul.host.xxx配置，例如：

```java
private int maxTotalConnections = 200;
```



### 3. Zuul高可用

Zuul可以像其它的spring cloud组件一样，把其注册到eureka上来实现zuul的高可用。但有些情况下，需要浏览器和app直接访问zuul，这种情况下可以使用nginx、HAProxy、F5等实现HA，并后接多个ZUUL来实现负载均衡和高可用。最佳实践是两种都用，两个zuul都注册到eureka上，供内网eureka客户端调用，并前置nginx(HA)供外网用户访问。



### 4.zuul整合其他非eureka上的服务

#### 4.1 配置routes路由请求到指定的URL

```yaml
zuul: 
  # 开放服务
  routes: 
    # 测试整合其它非eureka上的服务  
    dongyuit:
      path: /dongyuit/**
      url: http://www.dongyuit.cn/    
```

自定义了一个路由dongyuit，所有对/dongyuit/**前置的请求都会转发到http://www.dongyuit.cn/ ，例如：

http://192.168.5.31:8090/api/dongyuit/index.html

但要注意：上面的整合方法，请求不支持ribbon和hystrix，也就是说不支持负载均衡和hystrix容错，因为其走的不是RibbonRouteFilter，而是SimpleHostRoutingFilter。

RibbonRouteFilter：使用Ribbon、Hystrix、HTTP客户端发送请求。请求的servletId对应RequestContext的属性FilterConstants.SERVICE_ID_KEY。

SimpleHostRoutingFilter：如果路由配置直接指定了服务的url，而不能从eureka中获取位置，则使用这个过滤器。

#### 4.2 sidecar

需要被整合的服务端实现/health，这在整合一些第三方服务的情况下不可能，第三方法不可能给你实现一个/health功能。待以后解决。





## zuul的actuator

### 查看过滤器(ZuulFilter)

http://192.168.5.54:27070/actuator/filters

你可以观察到filter的执行顺序。

### 查看路由配置(Route)

http://192.168.5.54:27070/actuator/routes

其会返回：eureka配置的服务、yaml配置的服务，zuul可以路由到的所有服务。

例如：结果如下

```
{"/services":"virtual-service","/dy-eureka/**":"dy-eureka","/sgw-manager/**":"sgw-manager","/dy-admin/**":"dy-admin","/dfss-fss/**":"dfss-fss"}
```

查看路由配置详细信息(Route details)

http://10.60.33.21:27070/actuator/routes/details

```json
{"/services":{"id":"services","fullPath":"/services","location":"virtual-service","path":"/services","retryable":false,"customSensitiveHeaders":false,"prefixStripped":true},"/dy-eureka/**":{"id":"dy-eureka","fullPath":"/dy-eureka/**","location":"dy-eureka","path":"/**","prefix":"/dy-eureka","retryable":false,"customSensitiveHeaders":false,"prefixStripped":true},"/sgw-manager/**":{"id":"sgw-manager","fullPath":"/sgw-manager/**","location":"sgw-manager","path":"/**","prefix":"/sgw-manager","retryable":false,"customSensitiveHeaders":false,"prefixStripped":true},"/dy-admin/**":{"id":"dy-admin","fullPath":"/dy-admin/**","location":"dy-admin","path":"/**","prefix":"/dy-admin","retryable":false,"customSensitiveHeaders":false,"prefixStripped":true},"/dfss-fss/**":{"id":"dfss-fss","fullPath":"/dfss-fss/**","location":"dfss-fss","path":"/**","prefix":"/dfss-fss","retryable":false,"customSensitiveHeaders":false,"prefixStripped":true}}
```



### 查看hystrix信息

 http://192.168.5.54:27070/actuator/hystrix.stream



## FAQ

**Content-length different from byte array length! cl=xxx, array=0**

这个警告可以忽略。

这个警告日志，是由于你的http请求中带有Content-Length请求头，而zuul的HttpServletRequestWrapper的代码，使用req.getInputStream()获取到0个字节，两个一比较不相等，系统输出警告。警告的cl=xxx为请求头Content-Length的值，array=0为req.getInputStream()获取的字节数。你可以通过查看zuul的HttpServletRequestWrapper#parseRequest()代码，来验证上面的结论。

这个警告可以忽略，因为使用application/x-www-form-urlencoded请求的内容，可以使用request.getParameter()来解析，tomcat只会解析一次(读取req.getInputStream()返回解析到parameter对象)，解析后就缓存到request请求对象中，同时req.getInputStream()内容会读取已经结束，因此你再调用req.getInputStream()就会返回-1。而HttpServletRequestWrapper的目的也是对请求进行包装，解析请求的参数，然后存放一个HashMap<String, String[]> parameters对象，其实现原理和tomcat解析请求参数类同。因为tomcat已经解析过请求参数了，因此zuul没有必要再解析了，这段代码本身只想对性能没有什么影响，但感觉已经没有必要了，只是起到了代码保护作用。用的最多的是org.springframework.cloud.netflix.zuul.filters.pre.FormBodyWrapperFilter，如果基于json发送请求内容，可以禁用FormBodyWrapperFilter过滤器。















# DOC

https://www.jianshu.com/p/be5b26a9fa42

https://www.jianshu.com/p/f786a11a2def



