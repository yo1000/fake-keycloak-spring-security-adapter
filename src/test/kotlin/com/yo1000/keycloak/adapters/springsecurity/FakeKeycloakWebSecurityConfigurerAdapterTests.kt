package com.yo1000.keycloak.adapters.springsecurity

import org.hamcrest.Matchers
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.keycloak.KeycloakPrincipal
import org.keycloak.KeycloakSecurityContext
import org.keycloak.adapters.RefreshableKeycloakSecurityContext
import org.keycloak.adapters.springsecurity.account.KeycloakRole
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultHandlers
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.context.WebApplicationContext

/**
 *
 * @author yo1000
 */
@RunWith(SpringJUnit4ClassRunner::class)
@SpringBootTest(webEnvironment= SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class FakeKeycloakWebSecurityConfigurerAdapterTests {
    companion object {
        val TEST_USERNAME = "XXXX-XXXX-XXXX-XXXX"
        val TEST_ROLES = arrayOf("ADMIN", "USER")
    }

    @Autowired
    lateinit var context: WebApplicationContext
    lateinit var mockMvc: MockMvc

    @Before
    fun beforeTestEach() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply<DefaultMockMvcBuilder>(SecurityMockMvcConfigurers.springSecurity())
                .build()
    }

    @Test
    fun when_an_endpoint_that_requires_authentication_is_requested__user_information_can_be_accessed_without_authentication_by_Fake_setting() {
        mockMvc.perform(MockMvcRequestBuilders
                .get("/fake/get"))
                .andDo(MockMvcResultHandlers
                        .print())
                .andExpect(MockMvcResultMatchers
                        .status().isOk)
                .andExpect(MockMvcResultMatchers
                        .jsonPath("name", Matchers.`is`(TEST_USERNAME)))
    }

    fun main(args: Array<String>) {
        SpringApplication.run(FakeApp::class.java, *args)
    }

    @SpringBootApplication
    class FakeApp {
        @RestController
        @RequestMapping("/fake")
        class FakeController {
            @GetMapping("/get")
            fun get(token: KeycloakAuthenticationToken): Any {
                return mapOf(
                        "name" to token.name
                )
            }
        }

        @Configuration
        class FakeKeycloakWebSecurityConfiguration : FakeKeycloakWebSecurityConfigurerAdapter() {
            override fun fakeToken(): KeycloakAuthenticationToken {
                TEST_ROLES.map {
                    "ROLE_$it"
                }.let {
                    return KeycloakAuthenticationToken(
                            SimpleKeycloakAccount(
                                    KeycloakPrincipal(TEST_USERNAME, KeycloakSecurityContext()),
                                    it.toSet(),
                                    RefreshableKeycloakSecurityContext()
                            ),
                            false,
                            it.map { KeycloakRole(it) }
                    )
                }
            }

            override fun configure(http: HttpSecurity) {
                super.configure(http)
                http.authorizeRequests()
                        .antMatchers("/**").hasAnyRole(*TEST_ROLES)
                        .anyRequest().permitAll()
            }
        }
    }
}
