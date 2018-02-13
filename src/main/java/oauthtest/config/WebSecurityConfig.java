package oauthtest.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.filter.CompositeFilter;

import javax.servlet.Filter;
import java.io.IOException;
import java.net.URI;
import java.util.*;

@Configuration
@EnableOAuth2Client
@EnableAuthorizationServer
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final Logger LOGGER = LoggerFactory.getLogger(WebSecurityConfig.class);

    @Autowired
    private OAuth2ClientContext oauth2ClientContext;

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.debug(true);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/**")
                .authorizeRequests()
                .antMatchers("/", "/login**", "/webjars/**", "/user")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and().exceptionHandling().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/"))
                .and().logout().logoutSuccessUrl("/oauth").permitAll()
                .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
    }

    private Filter ssoFilter() {
        List<Filter> filters = new ArrayList<Filter>();
        filters.add(createOauthFilter(facebook(), "/login/facebook"));
        filters.add(createOauthFilter(github(), "/login/github"));
        filters.add(createRedditOauthFilter());

        CompositeFilter compositeFilter = new CompositeFilter();
        compositeFilter.setFilters(filters);

        return compositeFilter;
    }

    private Filter createOauthFilter(ClientResources clientResources, String path) {
        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(clientResources.getClient(), oauth2ClientContext);

        UserInfoTokenServices tokenServices = new UserInfoTokenServices(clientResources.getResource().getUserInfoUri(),
                clientResources.getResource().getClientId());
        tokenServices.setRestTemplate(restTemplate);

        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
        filter.setRestTemplate(restTemplate);
        filter.setTokenServices(tokenServices);

        return filter;
    }

    private Filter createRedditOauthFilter() {
        SimpleClientHttpRequestFactory requestFactory = redditRequestFactory();

        AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider();
        provider.setRequestFactory(requestFactory);

        OAuth2RestTemplate redditTemplate = new OAuth2RestTemplate(reddit().getClient(), oauth2ClientContext);
        redditTemplate.setAccessTokenProvider(new AccessTokenProviderChain(Collections.singletonList(provider)));
        redditTemplate.setRequestFactory(requestFactory);

        UserInfoTokenServices redditTokenServices = new UserInfoTokenServices(reddit().getResource().getUserInfoUri(),
                reddit().getClient().getClientId());
        redditTokenServices.setRestTemplate(redditTemplate);

        // need this because default principal extractor (FixedPrincipalExtractor) gets the id first
        redditTokenServices.setPrincipalExtractor(new PrincipalExtractor() {
            @Override
            public Object extractPrincipal(Map<String, Object> map) {
                return map.get("name");
            }
        });

        OAuth2ClientAuthenticationProcessingFilter redditFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/reddit");
        redditFilter.setRestTemplate(redditTemplate);
        redditFilter.setTokenServices(redditTokenServices);

        return redditFilter;
    }

    private SimpleClientHttpRequestFactory redditRequestFactory() {
        return new SimpleClientHttpRequestFactory() {
            @Override
            public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
                ClientHttpRequest request = super.createRequest(uri, httpMethod);
                //<platform>:<app ID>:<version string> (by /u/<reddit username>
                request.getHeaders().add("User-Agent", "web:oauthtest:v0.0.1 (by /u/PigExterminator)");
                return request;
            }
        };
    }

    @Bean
    @ConfigurationProperties("facebook")
    public ClientResources facebook() {
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("github")
    public ClientResources github() {
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("reddit")
    public ClientResources reddit() {
        return new ClientResources();
    }

    @Bean
    public FilterRegistrationBean oauth2ClientFilterRegistration(
            OAuth2ClientContextFilter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }
}
