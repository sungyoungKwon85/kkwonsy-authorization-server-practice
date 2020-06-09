# OAuth

## 클라이언트 입장
[OAuth 2.0 OAuth란?](https://velog.io/@undefcat/OAuth-2.0-%EA%B0%84%EB%8B%A8%EC%A0%95%EB%A6%AC)
유저 입장.. 다른 서비스의 회원 정보를 안전하게 다른곳에서 사용하기 위한 방법

유저가 자신의 네이버 아이디/비밀번호를 어떤 서비스에 알려주지 않아도, 네이버에 있는 유저의 정보를 그 서비스에서 안전하게 사용하기 위한 방법

`OAuth` 의 핵심은 `Access Token`

[JWT](https://jwt.io/)는 Base64 인코딩으로 되어 있어서 정보를 살펴볼 수 있긴 함

Access Token을 넘겨주면 네이버는 정보를 넘겨준다.

유저가 네이버에 로그인 
-> 네이버 서버는 아이디/비밀번호를 확인하고 해당 유저가 네이버 회원임을 확인 
-> 관련된 Access Token을 발급

서비스에서 네이버 로그인 기능을 사용하려고 한다면 사전에 네이버에 등록을 하고 승인을 받아야 한다.

redirect_uri도 사전에 미리 합의를 본다.



#



## Oauth2 Server
따라하기이므로 아래 블로그를 보는걸 추천.

[SpringBoot2로 Oauth2 서버 만들기 Archives - 아빠프로그래머의 좌충우돌 개발하기!](https://daddyprogrammer.org/post/series/spring-boot-oauth2/)

### Oauth Authorization Server
클라이언트가 서비스 제공자(페이스북이나, 구글, 카카오톡)로부터 회원 리소스를 제공받기 위해 인증 및 권한 부여를 받는 일련의 절차

해당 서비스에 로그인하고 제휴한 앱에 회원정보 접근을 승인하는 과정을 제공하는 것이 Authorization 서버

```
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

@Configuration
@EnableAuthorizationServer
public class Oauth2AuthorizationConfig extends AuthorizationServerConfigurerAdapter {

    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
            .withClient("testClientId")
            .secret("testSecret")
            .redirectUris("http://localhost:8081/oauth2/callback")
            .authorizedGrantTypes("authorization_code")
            .scopes("read", "write")
            .accessTokenValiditySeconds(30000);
    }
}

```
#

#### 인증 방식
인증 방식은 총 4가지가 있습니다. 그중 authorization_code 방식이 주로 사용됨.

Authorization Code
    * `Service Provider`가 제공하는 인증 화면에 로그인하고
      `클라이언트 앱`이 요청하는 리소스 접근 요청을 승인하면,
      지정한 `redirect_uri`로 code를 넘겨주는데. 해당 code로
      `access_token`을 얻는다.  

#
    
#### scopes
인증 후 얻은 accessToken으로 접근할 수 있는 리소스의 범위
resource서버(api서버)에서는 해당 scope정보로 클라이언트에게 제공할 리소스를 제한하거나 노출시킴.
 
 
#

```
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder noOpPasswordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("user")
            .password("pwd")
            .roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .headers().frameOptions().disable()
            .and()
            .authorizeRequests().antMatchers("/oauth/**", "/oauth2/callback", "/h2-console/*")
                .permitAll()
            .and()
            .formLogin()
            .and()
            .httpBasic();
    }
}
```
* password세팅 시에는 암호화에 대한 준비가 아직 되어있지 않으므로 NoOpPasswordEncoder를 사용하도록 세팅
*  인증할 회원 정보도 테스트를 위해 일단 더미로 세팅
* csrf는 사용 안 함 처리(크로스 사이트 요청 위조: 특정 웹사이트가 사용자의 웹 브라우저를 신용하는 상태를 노린 것)
* .headers().frameOptions().disable()은 security 적용 시 h2 console 사용이 막히므로 세팅
* security 로그인 화면은 일단 기본 폼을 사용하도록 세팅

#

```
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

public class WebMvcConfig implements WebMvcConfigurer {

    private static final long MAX_AGE_SECONDS = 3600;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
            .allowedOrigins("*")
            .allowedMethods("GET", "POST", "DELETE", "PUT")
            .allowedHeaders("*")
            .allowCredentials(true)
            .maxAge(MAX_AGE_SECONDS);
    }

    @Bean
    public RestTemplate getRestTemplate() {
        return new RestTemplate();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
```
* 프로젝트에서 사용하는 공통 빈이나 필요한 환경 정보를 세팅
* 인증서버에 크로스 도메인 접근 가능하도록 cors 설정을 추가

#

```
server:
  port: 8081
spring:
  h2:
    console:
      enabled: true
      settings:
        web-allow-others: true
  datasource:
    url: jdbc:h2:tcp://localhost/~/test
    driver-class-name: org.h2.Driver
    username: sa
  jpa:
    database-platform: org.hibernate.dialect.H2Dialect
    properties:
      hibernate:
        hbm2ddl:
          auto: update
    show-sql: true
```
* 향후 개발할 리소스 서버(api서버)와 구분을 두기 위해 8081로 세팅
* 나머지는 h2와 jpa설정


#
http://localhost:8081/oauth/authorize?client_id=testClientId&redirect_uri=http://localhost:8081/oauth2/callback&response_type=code&scope=read

접속해보면 클라이언트의 리소스 허용 확인을 묻는 화면으로 이동함.

허용하면 테스트로 세팅한 redirectUri로 리다이렉트 됨.

현재는 받아줄 controller를 세팅하지 않았으므로 404.


#
```
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OAuthToken {

    private String accessToken;
    private String tokenType;
    private String refreshToken;
    private long expiresIn;
    private String scope;
}
```
* 토큰정보를 받을 모델 생성

# 
```
implementation 'com.google.code.gson:gson'
```
* Json String을 Java 객체로 맵핑하기 위해 Gson 라이브러리를 추가


#
```
@RequiredArgsConstructor
@RestController
@RequestMapping("/oauth2")
public class Oauth2Controller {
    private final Gson gson;
    private final RestTemplate restTemplate;
    @GetMapping(value = "/callback")
    public OAuthToken callbackSocial(@RequestParam String code) {
        String credentials = "testClientId:testSecret";
        String encodedCredentials = new String(Base64.encodeBase64(credentials.getBytes()));
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization", "Basic " + encodedCredentials);
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", code);
        params.add("grant_type", "authorization_code");
        params.add("redirect_uri", "http://localhost:8081/oauth2/callback");
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<String> response = restTemplate.postForEntity("http://localhost:8081/oauth/token", request, String.class);
        if (response.getStatusCode() == HttpStatus.OK) {
            return gson.fromJson(response.getBody(), OAuthToken.class);
        }
        return null;
    }
}
```
* Oauth인증 완료 후 redirectUri를 처리해주기 위한 Controller
* 원래는 해당 프로젝트가 아닌 클라이언트에 세팅되는 화면이 되어야 함(임시로 만든 것)


#

```
$ curl -X POST \
'http://localhost:8081/oauth/token' \
-H 'Authorization:Basic dGVzdENsaWVudElkOnRlc3RTZWNyZXQ=' \
-d 'grant_type=authorization_code' \
-d 'code=u6q9Ju' \
-d 'redirect_uri=http://localhost:8081/oauth2/callback'
```

* message":"There is no PasswordEncoder mapped for the id 와 같은 에러가 나는데 Spring Security 버전이 올라가면서 발생함
* {noop}을 password에 붙여서 저장해야 함
* 일단 넘어가자


#







