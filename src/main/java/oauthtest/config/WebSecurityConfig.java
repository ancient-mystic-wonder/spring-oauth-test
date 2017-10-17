package oauthtest.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
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
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.filter.CompositeFilter;

import javax.servlet.Filter;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableOAuth2Client
@PropertySource("classpath:config/oauth-secret.properties")
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    OAuth2ClientContext oauth2ClientContext;

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
                .and().logout().logoutSuccessUrl("/oauth").permitAll()
                .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
    }

    private Filter ssoFilter() {
        List<Filter> filters = new ArrayList<Filter>();
        filters.add(createFacebookOauthFilter());
        filters.add(createGithubOauthFilter());
        filters.add(createRedditOauthFilter());

        CompositeFilter compositeFilter = new CompositeFilter();
        compositeFilter.setFilters(filters);

        return compositeFilter;
    }

    private Filter createFacebookOauthFilter() {
        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(facebook(), oauth2ClientContext);

        UserInfoTokenServices tokenServices = new UserInfoTokenServices(facebookResource().getUserInfoUri(), facebook().getClientId());
        tokenServices.setRestTemplate(restTemplate);

        OAuth2ClientAuthenticationProcessingFilter facebookFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/facebook");
        facebookFilter.setRestTemplate(restTemplate);
        facebookFilter.setTokenServices(tokenServices);

        return facebookFilter;
    }

    private Filter createGithubOauthFilter() {
        OAuth2RestTemplate githubTemplate = new OAuth2RestTemplate(github(), oauth2ClientContext);

        UserInfoTokenServices tokenServices = new UserInfoTokenServices(githubResource().getUserInfoUri(), github().getClientId());
        tokenServices.setRestTemplate(githubTemplate);

        OAuth2ClientAuthenticationProcessingFilter githubFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/github");
        githubFilter.setRestTemplate(githubTemplate);
        githubFilter.setTokenServices(tokenServices);

        return githubFilter;
    }

    private Filter createRedditOauthFilter() {
        SimpleClientHttpRequestFactory requestFactory = redditRequestFactory();

        AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider();
        provider.setRequestFactory(requestFactory);

        OAuth2RestTemplate redditTemplate = new OAuth2RestTemplate(reddit(), oauth2ClientContext);
        redditTemplate.setAccessTokenProvider(new AccessTokenProviderChain(Arrays.<AccessTokenProvider> asList(provider)));
        redditTemplate.setRequestFactory(requestFactory);

        UserInfoTokenServices redditTokenServices = new UserInfoTokenServices(redditResource().getUserInfoUri(), reddit().getClientId());
        redditTokenServices.setRestTemplate(redditTemplate);

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
    @ConfigurationProperties("facebook.client")
    public AuthorizationCodeResourceDetails facebook() {
        return new AuthorizationCodeResourceDetails();
    }

    @Bean
    @ConfigurationProperties("facebook.resource")
    public ResourceServerProperties facebookResource() {
        return new ResourceServerProperties();
    }

    @Bean
    @ConfigurationProperties("github.client")
    public AuthorizationCodeResourceDetails github() {
        return new AuthorizationCodeResourceDetails();
    }

    @Bean
    @ConfigurationProperties("github.resource")
    public ResourceServerProperties githubResource() {
        return new ResourceServerProperties();
    }

    @Bean
    @ConfigurationProperties("reddit.client")
    public AuthorizationCodeResourceDetails reddit() {
        return new AuthorizationCodeResourceDetails();
    }

    @Bean
    @ConfigurationProperties("reddit.resource")
    public ResourceServerProperties redditResource() {
        return new ResourceServerProperties();
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
