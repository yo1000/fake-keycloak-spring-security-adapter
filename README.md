# Fake Keycloak Spring Security adapter
Keycloak Spring Security Fake adapter

## HOW TO USE

```xml
<!-- pom.xml -->
<dependency>
    <groupId>com.yo1000</groupId>
    <artifactId>fake-keycloak-spring-security-adapter</artifactId>
    <version>1.0.0-keycloak-3.4</version>
</dependency>
```

```kotlin
/* KeycloakConfig.kt */
@Configuration
class FakeKeycloakWebSecurityConfiguration : FakeKeycloakWebSecurityConfigurerAdapter() {
    companion object {
        val TEST_USERNAME = "XXXX-XXXX-XXXX-XXXX"
        val TEST_ROLES = arrayOf("ADMIN", "USER")
    }

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

    override fun configure(httpSecurity: HttpSecurity) {
        super.configure(httpSecurity)
        httpSecurity
                .authorizeRequests()
                .antMatchers("/**").hasAnyRole(*TEST_ROLES)
                .anyRequest().permitAll()
    }
}
```
