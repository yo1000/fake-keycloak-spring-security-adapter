package com.yo1000.keycloak.adapters.springsecurity

import org.keycloak.adapters.AdapterDeploymentContext
import org.keycloak.adapters.KeycloakDeployment
import org.keycloak.adapters.spi.HttpFacade
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticatedActionsFilter
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter
import org.keycloak.adapters.springsecurity.filter.KeycloakPreAuthActionsFilter
import org.keycloak.adapters.springsecurity.filter.KeycloakSecurityContextRequestFilter
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.Authentication
import org.springframework.security.core.session.SessionRegistryImpl
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 *
 * @author yo1000
 */
abstract class FakeKeycloakWebSecurityConfigurerAdapter : KeycloakWebSecurityConfigurerAdapter() {
    @Autowired
    lateinit var fakeToken: KeycloakAuthenticationToken

    @Autowired
    lateinit var sessionAuthenticationStrategy: SessionAuthenticationStrategy

    @Bean
    override fun sessionAuthenticationStrategy(): SessionAuthenticationStrategy {
        return RegisterSessionAuthenticationStrategy(SessionRegistryImpl())
    }

    @Bean
    abstract fun fakeToken(): KeycloakAuthenticationToken

    override fun keycloakAuthenticatedActionsRequestFilter(): KeycloakAuthenticatedActionsFilter {
        return object : KeycloakAuthenticatedActionsFilter() {
            override fun doFilter(request: ServletRequest?, response: ServletResponse?, chain: FilterChain?) {
                chain?.doFilter(request, response)
            }
        }
    }

    override fun keycloakAuthenticationProcessingFilter(): KeycloakAuthenticationProcessingFilter {
        return object : KeycloakAuthenticationProcessingFilter(authenticationManager()) {
            init {
                setSessionAuthenticationStrategy(sessionAuthenticationStrategy)
            }

            override fun doFilter(req: ServletRequest?, res: ServletResponse?, chain: FilterChain?) {
                val httpRequest = req as HttpServletRequest
                val httpResponse = res as HttpServletResponse

                val auth = attemptAuthentication(req, res)
                sessionAuthenticationStrategy.onAuthentication(auth, httpRequest, httpResponse)
                successfulAuthentication(httpRequest, httpResponse, chain, auth)
            }

            override fun attemptAuthentication(request: HttpServletRequest?, response: HttpServletResponse?): Authentication {
                return authenticationManager.authenticate(fakeToken)
            }
        }
    }

    override fun keycloakSecurityContextRequestFilter(): KeycloakSecurityContextRequestFilter {
        return object : KeycloakSecurityContextRequestFilter() {
            override fun doFilter(request: ServletRequest?, response: ServletResponse?, filterChain: FilterChain?) {
                filterChain?.doFilter(request, response)
            }
        }
    }

    override fun keycloakPreAuthActionsFilter(): KeycloakPreAuthActionsFilter {
        return object : KeycloakPreAuthActionsFilter() {
            override fun doFilter(request: ServletRequest?, response: ServletResponse?, chain: FilterChain?) {
                chain?.doFilter(request, response)
            }
        }
    }

    override fun adapterDeploymentContext(): AdapterDeploymentContext {
        return AdapterDeploymentContext(object : KeycloakSpringBootConfigResolver() {
            override fun resolve(request: HttpFacade.Request?): KeycloakDeployment {
                return KeycloakDeployment()
            }
        })
    }

    override fun authenticationManager(): AuthenticationManager {
        return AuthenticationManager { it }
    }

    override fun configure(http: HttpSecurity) {
        http
                .csrf().requireCsrfProtectionMatcher(keycloakCsrfRequestMatcher())
                .and()
                .sessionManagement()
                .sessionAuthenticationStrategy(sessionAuthenticationStrategy())
                .and()
                .addFilterBefore(keycloakPreAuthActionsFilter(), LogoutFilter::class.java)
                .addFilterBefore(keycloakAuthenticationProcessingFilter(), BasicAuthenticationFilter::class.java)
                .addFilterAfter(keycloakSecurityContextRequestFilter(), SecurityContextHolderAwareRequestFilter::class.java)
                .addFilterAfter(keycloakAuthenticatedActionsRequestFilter(), SecurityContextHolderAwareRequestFilter::class.java)
                .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
                .and()
                .logout()
                .addLogoutHandler(keycloakLogoutHandler())
                .logoutUrl("/sso/logout").permitAll()
                .logoutSuccessUrl("/")
    }
}