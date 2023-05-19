# security

基于SpringSecurity的多方式登录认证

##项目结构
security
｜- base， 基础包，包含http响应体
｜- config， 自动配置，包括缓存cache，sercurity全局配置
｜- controller， 包扩thymeleaf登录页，测试api
｜- security， 核心配置包
  ｜- filter， 父类过滤器+各子类过滤器，配置了登录uri和form表单参数，未认证的authentication对象
  ｜- handler， 配置登出控制
  ｜- provider， form表单验证，返回认证成功的authentication对象
  ｜- token， 父类token+各子类token的构造
  ｜- CustomLoginUser， 自定义LoginUser对象，实现了security包的UserDetails
  ｜- CustomTokenFilter， 自定义token过滤器，实现了web包的OncePerRequestFilter，校验是否传入token及token是否有效
  ｜- CustomUserDetailsService， 自定义UserDetails查询，实现了security包的UserDetailsService，查询用户信息和用户权限信息
｜- util， 工具类，包括jwt工具

##技术栈
基础开发框架：springboot 2.6.6
前端框架：thymeleaf
持久层开发框架：未使用持久层
缓存：spring.cache
序列化工具：fastjson 1.2.83
token校验方式：jwt 0.9.1
